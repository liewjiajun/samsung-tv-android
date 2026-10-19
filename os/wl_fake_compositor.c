/* wl_fake_compositor.c — a minimal Wayland server, for testing our client.
 *
 * This is not a display server. It is a protocol peer that answers the specific
 * requests our client makes, so we can prove the client works without a TV and
 * without Tizen's compositor being involved at all.
 *
 * It serves:
 *   wl_display  : sync, get_registry
 *   wl_registry : global events
 *   wl_compositor : create_surface
 *   wl_shm      : create_pool   (receives the fd via SCM_RIGHTS, mmaps it)
 *   wl_shm_pool : create_buffer
 *   wl_surface  : attach, damage, commit  (commit snapshots the pixels)
 *
 * The pixel snapshot is the point: it proves the client's drawing actually
 * landed in the shared memory the server can see.
 */
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define WL_DISPLAY_ID 1u

struct client {
    int fd;
    int registry_id;
    int compositor_id;
    int shm_id;
    int surface_id;
    int pool_id;
    int buffer_id;
    size_t pool_size;
    void *pool_map;
    int buffer_w, buffer_h, buffer_stride;
    int commits;
};

struct server {
    int listen_fd;
    const char *path;
    struct client cl;
    /* last seen buffer contents */
    uint32_t *snapshot;
    size_t snapshot_len;
};

/* ---- message reading ---------------------------------------------- */

/* Variant that also captures an fd, for create_pool. */
static ssize_t recv_message_fd(int fd, uint32_t *words, size_t max_words,
                               int *out_fd)

{
    *out_fd = -1;
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (poll(&p, 1, 0) <= 0)
        return 0;

    uint32_t hdr[2];
    ssize_t peeked = recv(fd, hdr, sizeof hdr, MSG_PEEK);
    if (peeked < (ssize_t)sizeof hdr)
        return 0;
    uint32_t total = hdr[1];
    if (total < 2 || total > max_words)
        return -1;

    size_t want = total * 4;
    struct iovec iov = {.iov_base = words, .iov_len = want};

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

    ssize_t k;
    do {
        k = recvmsg(fd, &msg, 0);
    } while (k < 0 && errno == EINTR);
    if (k <= 0)
        return -1;

    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
        if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
            int received;
            memcpy(&received, CMSG_DATA(cm), sizeof received);
            *out_fd = received;
        }
    }
    return (ssize_t)total;
}

/* ---- sending ------------------------------------------------------ */

static void send_words(int fd, const uint32_t *w, size_t n)
{
    size_t bytes = n * 4, sent = 0;
    while (sent < bytes) {
        ssize_t k = write(fd, (const char *)w + sent, bytes - sent);
        if (k <= 0)
            return;
        sent += (size_t)k;
    }
}

static void send_global(int fd, uint32_t registry_id, uint32_t name,
                        const char *iface, uint32_t ver)
{
    size_t len = strlen(iface) + 1;
    size_t words = (len + 3) / 4;
    uint32_t buf[64];
    size_t n = 0;
    buf[n++] = registry_id;       /* the registry the client asked on */
    buf[n++] = (uint32_t)(6 + words);
    buf[n++] = 0;                 /* global */
    buf[n++] = name;
    buf[n++] = (uint32_t)len;
    memcpy(&buf[n], iface, len);
    memset((char *)&buf[n] + len, 0, words * 4 - len);
    n += words;
    buf[n++] = ver;
    send_words(fd, buf, n);
}

static void send_callback_done(int fd, uint32_t cb_id, uint32_t serial)
{
    uint32_t buf[4] = {cb_id, 3, 0, serial};
    send_words(fd, buf, 4);
}

/* ---- request handling --------------------------------------------- */

static void handle(struct server *s, uint32_t *w, int nfd)
{
    struct client *c = &s->cl;
    uint32_t id = w[0], opcode = w[2];
    uint32_t *a = w + 3;
    size_t n = (size_t)w[1] - 3;

    /* wl_display */
    if (id == WL_DISPLAY_ID) {
        if (opcode == 1 && n >= 1) {
            /* get_registry: record id and emit the globals */
            c->registry_id = (int)a[0];
            send_global(c->fd, c->registry_id, 1, "wl_compositor", 4);
            send_global(c->fd, c->registry_id, 2, "wl_shm", 1);
            send_global(c->fd, c->registry_id, 3, "wl_seat", 5);
        }
        if (opcode == 0 && n >= 1) {
            /* sync: acknowledge */
            send_callback_done(c->fd, a[0], 1);
        }
        return;
    }

    /* wl_registry.bind */
    if ((int)id == c->registry_id && opcode == 0 && n >= 3) {
        uint32_t name = a[0];
        uint32_t slen = a[1];
        const char *iface = (const char *)&a[2];
        size_t sw = (slen + 3) / 4;
        uint32_t new_id = a[2 + sw + 1];
        (void)name;
        if (strcmp(iface, "wl_compositor") == 0)
            c->compositor_id = (int)new_id;
        else if (strcmp(iface, "wl_shm") == 0)
            c->shm_id = (int)new_id;
        return;
    }

    /* wl_compositor.create_surface */
    if ((int)id == c->compositor_id && opcode == 0 && n >= 1) {
        c->surface_id = (int)a[0];
        return;
    }

    /* wl_shm.create_pool(new_id, size) + fd */
    if ((int)id == c->shm_id && opcode == 0 && n >= 2) {
        c->pool_id = (int)a[0];
        c->pool_size = (size_t)(int32_t)a[1];
        if (nfd >= 0) {
            c->pool_map = mmap(NULL, c->pool_size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, nfd, 0);
            if (c->pool_map == MAP_FAILED)
                c->pool_map = NULL;
        }
        return;
    }

    /* wl_shm_pool.create_buffer(new_id, offset, w, h, stride, format) */
    if ((int)id == c->pool_id && opcode == 0 && n >= 6) {
        c->buffer_id = (int)a[0];
        c->buffer_w = (int32_t)a[2];
        c->buffer_h = (int32_t)a[3];
        c->buffer_stride = (int32_t)a[4];
        return;
    }

    /* wl_surface.commit — snapshot what the client drew */
    if ((int)id == c->surface_id && opcode == 6) {
        c->commits++;
        if (c->pool_map && c->buffer_w > 0 && c->buffer_h > 0) {
            size_t len = (size_t)c->buffer_stride * (size_t)c->buffer_h;
            s->snapshot = realloc(s->snapshot, len);
            if (s->snapshot) {
                memcpy(s->snapshot, c->pool_map, len);
                s->snapshot_len = len;
            }
        }
        return;
    }
}

/* ---- server lifecycle --------------------------------------------- */

static int server_start(struct server *s, const char *path)
{
    memset(s, 0, sizeof *s);
    s->path = path;
    s->cl.fd = -1;
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sa.sun_path) {
        close(fd);
        return -1;
    }
    strcpy(sa.sun_path, path);

    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 4) != 0) {
        close(fd);
        return -1;
    }
    s->listen_fd = fd;
    return 0;
}

static int server_accept(struct server *s)
{
    int fd = accept(s->listen_fd, NULL, NULL);
    if (fd < 0)
        return -1;
    s->cl.fd = fd;
    return 0;
}

/* Serve requests until the client goes quiet, then return the snapshot. */
static int server_pump(struct server *s, int rounds, int quiet_ms)
{
    for (int i = 0; i < rounds; i++) {
        struct pollfd p = {.fd = s->cl.fd, .events = POLLIN};
        int pr = poll(&p, 1, quiet_ms);
        if (pr <= 0)
            return 0; /* idle */

        uint32_t words[1024];
        int nfd = -1;
        ssize_t total = recv_message_fd(s->cl.fd, words, 1024, &nfd);
        if (total <= 0)
            return -1;
        handle(s, words, nfd);
        if (nfd >= 0)
            close(nfd);
    }
    return 0;
}

static void server_stop(struct server *s)
{
    if (s->cl.pool_map)
        munmap(s->cl.pool_map, s->cl.pool_size);
    if (s->cl.fd >= 0)
        close(s->cl.fd);
    if (s->listen_fd >= 0)
        close(s->listen_fd);
    free(s->snapshot);
    if (s->path)
        unlink(s->path);
}

/* ---- accessors used by the test ----------------------------------- */

int fake_server_start(struct server **out, const char *path)
{
    struct server *s = calloc(1, sizeof *s);
    if (!s || server_start(s, path) != 0) {
        free(s);
        return -1;
    }
    *out = s;
    return 0;
}

int fake_server_accept(struct server *s) { return server_accept(s); }
int fake_server_pump(struct server *s, int rounds, int quiet_ms)
{
    return server_pump(s, rounds, quiet_ms);
}
void fake_server_stop(struct server *s)
{
    if (s) {
        server_stop(s);
        free(s);
    }
}
int fake_server_commits(struct server *s) { return s->cl.commits; }
int fake_server_buffer_w(struct server *s) { return s->cl.buffer_w; }
int fake_server_buffer_h(struct server *s) { return s->cl.buffer_h; }
uint32_t fake_server_pixel(struct server *s, int x, int y)
{
    struct client *c = &s->cl;
    if (!s->snapshot || x < 0 || y < 0 || x >= c->buffer_w || y >= c->buffer_h)
        return 0;
    const uint8_t *row = (const uint8_t *)s->snapshot + (size_t)y * c->buffer_stride;
    return ((const uint32_t *)row)[x];
}
