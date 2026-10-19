/* wl_window.c — registry bind, shm pool, surface and presentation.
 *
 * This is the layer that turns the wire protocol into pixels. Every step that
 * depends on the compositor is a separate call that can fail visibly.
 */
/* _GNU_SOURCE is required for memfd_create and MFD_CLOEXEC. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "wl.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* wl_registry */
#define REG_BIND 0
#define REG_GET_REGISTRY 1
/* wl_compositor */
#define COMPOSITOR_CREATE_SURFACE 0
/* wl_shm */
#define SHM_CREATE_POOL 0
/* wl_shm_pool */
#define POOL_CREATE_BUFFER 0
/* wl_surface */
#define SURFACE_ATTACH 1
#define SURFACE_DAMAGE 2
#define SURFACE_COMMIT 6
/* wl_display */
#define DISPLAY_SYNC 0
#define DISPLAY_GET_REGISTRY 1

int wl_fd(struct wl_conn *c);

/* ---- fd passing --------------------------------------------------- */

/* wl_shm.create_pool carries a file descriptor as SCM_RIGHTS ancillary data on
 * the same sendmsg as the message body: Wayland requires the fd to arrive
 * together with the message that references it. */
int wl_msg_send_fd(struct wl_conn *c, struct msg *m, int fd)
{
    if (!m->w) {
        errno = EINVAL;
        return -1;
    }
    m->w[1] = (uint32_t)m->n;
    size_t bytes = m->n * sizeof(uint32_t);

    struct iovec iov = {.iov_base = m->w, .iov_len = bytes};

    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } u;
    memset(&u, 0, sizeof u);

    struct msghdr msg;
    memset(&msg, 0, sizeof msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof u.buf;

    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));

    ssize_t k;
    do {
        k = sendmsg(wl_fd(c), &msg, MSG_NOSIGNAL);
    } while (k < 0 && errno == EINTR);

    free(m->w);
    m->w = NULL;
    m->n = 0;

    if (k < 0)
        return -1;
    return (size_t)k == bytes ? 0 : -1;
}

/* ---- waiting dispatch --------------------------------------------- */

int wl_dispatch_wait(struct wl_conn *c, wl_event_fn on_event, void *user,
                     int timeout_ms)
{
    int r = wl_dispatch(c, on_event, user);
    if (r != 0)
        return r;

    struct pollfd p = {.fd = wl_fd(c), .events = POLLIN, .revents = 0};
    int pr = poll(&p, 1, timeout_ms);
    if (pr < 0)
        return (errno == EINTR) ? 0 : -1;
    if (pr == 0)
        return 0; /* genuinely idle */
    return wl_dispatch(c, on_event, user);
}

/* ---- sync round-trip ---------------------------------------------- */

struct sync_state {
    int done;
    uint32_t cb_id;
};

static int sync_events(struct wl_conn *c, uint32_t id, uint32_t opcode,
                       const uint32_t *args, size_t n, void *user)
{
    (void)c;
    (void)args;
    (void)n;
    struct sync_state *s = user;
    if (id == s->cb_id && opcode == 0 /* wl_callback.done */) {
        s->done = 1;
        return 1; /* stop dispatch */
    }
    return 0;
}

/* wl_display.sync: the compositor replies once it has processed everything sent
 * before the request. This is how we know the registry is fully enumerated
 * rather than merely quiet. */
int wl_sync(struct wl_conn *c, wl_event_fn on_event, void *user, int timeout_ms)
{
    (void)on_event;
    (void)user;

    struct sync_state s;
    memset(&s, 0, sizeof s);
    s.cb_id = wl_new_id(c);

    struct msg m;
    wl_msg_begin(&m, WL_DISPLAY_ID, DISPLAY_SYNC);
    wl_msg_u32(&m, s.cb_id);
    if (wl_msg_send(c, &m) != 0)
        return -1;

    for (int spent = 0; spent <= timeout_ms; spent += 200) {
        int r = wl_dispatch_wait(c, sync_events, &s, 200);
        if (r < 0)
            return -1;
        if (s.done)
            return 0;
    }
    errno = ETIMEDOUT;
    return -1;
}

/* ---- bind --------------------------------------------------------- */

static int bind_global(struct wl_conn *c, uint32_t registry_id,
                       struct wl_global *g, uint32_t version, uint32_t *out_id)
{
    uint32_t new_id = wl_new_id(c);

    /* wl_registry.bind(name, interface:string, version, new_id).
     * Arg order matters and a mistake here is not loud: the compositor reads a
     * string length from the wrong word. */
    struct msg m;
    wl_msg_begin(&m, registry_id, REG_BIND);
    wl_msg_u32(&m, g->name);
    wl_msg_string(&m, g->iface);
    wl_msg_u32(&m, version);
    wl_msg_u32(&m, new_id);
    if (wl_msg_send(c, &m) != 0)
        return -1;

    *out_id = new_id;
    return 0;
}

/* ---- window ------------------------------------------------------- */

struct wl_window *wl_window_create(struct wl_conn *c, int width, int height,
                                   uint32_t format, wl_event_fn on_event,
                                   void *user, int timeout_ms)
{
    if (width <= 0 || height <= 0) {
        errno = EINVAL;
        return NULL;
    }

    /* 1. Enumerate globals. wl_display.get_registry returns a registry object
     *    whose events the caller's on_event collects via wl_add_global. */
    uint32_t reg_id = wl_new_id(c);
    struct msg m;
    wl_msg_begin(&m, WL_DISPLAY_ID, DISPLAY_GET_REGISTRY);
    wl_msg_u32(&m, reg_id);
    if (wl_msg_send(c, &m) != 0)
        return NULL;

    /* Drain until both interfaces we need are present, or the round-trip ends.
     * A sync after the registry guarantees we stop when the compositor is done
     * sending, instead of guessing at a number of iterations. */
    for (int i = 0; i < 200; i++) {
        if (wl_find_global(c, "wl_compositor") && wl_find_global(c, "wl_shm"))
            break;
        int r = wl_dispatch_wait(c, on_event, user, 100);
        if (r < 0)
            return NULL;
    }
    if (wl_sync(c, on_event, user, 2000) != 0) {
        /* A compositor that will not answer sync is a real problem, but keep
         * going if the interfaces are already known. */
        if (!wl_find_global(c, "wl_compositor") || !wl_find_global(c, "wl_shm"))
            return NULL;
    }

    struct wl_global *gc = wl_find_global(c, "wl_compositor");
    struct wl_global *gs = wl_find_global(c, "wl_shm");
    if (!gc || !gs) {
        errno = ENOENT;
        return NULL;
    }

    struct wl_window *w = calloc(1, sizeof *w);
    if (!w)
        return NULL;
    w->c = c;
    w->width = width;
    w->height = height;
    w->stride = width * 4;
    w->shm_version = gs->version;
    w->memfd = -1;

    /* 2. Bind, clamped to versions we actually implement. */
    uint32_t comp_v = gc->version < 4 ? gc->version : 4;
    uint32_t shm_v = gs->version < 1 ? gs->version : 1;
    if (bind_global(c, reg_id, gc, comp_v, &w->compositor_id) != 0)
        goto fail;
    if (bind_global(c, reg_id, gs, shm_v, &w->shm_id) != 0)
        goto fail;

    /* 3. Surface. */
    w->surface_id = wl_new_id(c);
    wl_msg_begin(&m, w->compositor_id, COMPOSITOR_CREATE_SURFACE);
    wl_msg_u32(&m, w->surface_id);
    if (wl_msg_send(c, &m) != 0)
        goto fail;

    /* 4. Anonymous shared memory. memfd means no filesystem name and no stale
     *    file if we die. */
    w->memfd = memfd_create("wl-buffer", MFD_CLOEXEC);
    if (w->memfd < 0) {
        char tmpl[] = "/tmp/wlshmXXXXXX";
        int fd = mkstemp(tmpl);
        if (fd >= 0) {
            unlink(tmpl);
            w->memfd = fd;
        }
    }
    if (w->memfd < 0)
        goto fail;

    w->map_size = (size_t)w->stride * (size_t)height;
    if (ftruncate(w->memfd, (off_t)w->map_size) != 0)
        goto fail;

    w->pixels = mmap(NULL, w->map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                     w->memfd, 0);
    if (w->pixels == MAP_FAILED) {
        w->pixels = NULL;
        goto fail;
    }
    memset(w->pixels, 0, w->map_size);

    /* 5. wl_shm.create_pool(fd, size) — fd travels out of band. */
    w->pool_id = wl_new_id(c);
    wl_msg_begin(&m, w->shm_id, SHM_CREATE_POOL);
    wl_msg_u32(&m, w->pool_id);
    wl_msg_i32(&m, (int32_t)w->map_size);
    if (wl_msg_send_fd(c, &m, w->memfd) != 0)
        goto fail;

    /* 6. wl_shm_pool.create_buffer(offset, w, h, stride, format). */
    w->buffer_id = wl_new_id(c);
    wl_msg_begin(&m, w->pool_id, POOL_CREATE_BUFFER);
    wl_msg_u32(&m, w->buffer_id);
    wl_msg_i32(&m, 0);
    wl_msg_i32(&m, width);
    wl_msg_i32(&m, height);
    wl_msg_i32(&m, w->stride);
    wl_msg_u32(&m, format);
    if (wl_msg_send(c, &m) != 0)
        goto fail;

    if (wl_window_present(w) != 0)
        goto fail;

    return w;

fail:
    wl_window_close(w);
    return NULL;
}

int wl_window_present(struct wl_window *w)
{
    if (!w || !w->c)
        return -1;
    struct msg m;

    wl_msg_begin(&m, w->surface_id, SURFACE_ATTACH);
    wl_msg_u32(&m, w->buffer_id);
    wl_msg_i32(&m, 0);
    wl_msg_i32(&m, 0);
    if (wl_msg_send(w->c, &m) != 0)
        return -1;

    wl_msg_begin(&m, w->surface_id, SURFACE_DAMAGE);
    wl_msg_i32(&m, 0);
    wl_msg_i32(&m, 0);
    wl_msg_i32(&m, w->width);
    wl_msg_i32(&m, w->height);
    if (wl_msg_send(w->c, &m) != 0)
        return -1;

    wl_msg_begin(&m, w->surface_id, SURFACE_COMMIT);
    return wl_msg_send(w->c, &m);
}

int wl_window_pixel(struct wl_window *w, int x, int y, uint32_t argb)
{
    if (!w || !w->pixels)
        return -1;
    if (x < 0 || y < 0 || x >= w->width || y >= w->height)
        return -1;
    uint32_t *row = (uint32_t *)((uint8_t *)w->pixels + (size_t)y * w->stride);
    row[x] = argb;
    return 0;
}

void wl_window_close(struct wl_window *w)
{
    if (!w)
        return;
    if (w->pixels && w->pixels != MAP_FAILED)
        munmap(w->pixels, w->map_size);
    if (w->memfd >= 0)
        close(w->memfd);
    free(w);
}
