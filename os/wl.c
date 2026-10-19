/* wl.c — a from-scratch Wayland wire-protocol client.
 *
 * Why not link libwayland: the TV ships libwayland-client, but depending on it
 * means our OS inherits Tizen's version, ABI and bugs. The wire protocol is a
 * small stable format, so we implement it directly and stay independent of both
 * Samsung's compositor version and any compositor we write later.
 *
 * Message framing (native-endian 32-bit words):
 *   u32 object_id
 *   u32 word_count          (includes these 8 header bytes)
 *   u32 opcode
 *   ...args...
 */
#include "wl.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* Cap on words per outbound message; keeps capacity reasoning trivial. */
#define MSG_MAX_WORDS 512

/* Refuse to buffer an inbound message larger than this (1 MiB). A compositor
 * never legitimately sends more; a hostile or corrupt peer might. */
#define MAX_MESSAGE_BYTES (1024u * 1024u)

struct wl_conn {
    int fd;
    uint32_t next_id;

    uint8_t *in;
    size_t in_len;
    size_t in_cap;

    struct wl_global *globals;
    size_t n_globals;
    size_t globals_cap;
};

/* ---- growable buffers --------------------------------------------- */

static int grow_bytes(uint8_t **buf, size_t *cap, size_t need)
{
    if (need <= *cap)
        return 0;
    size_t n = *cap ? *cap : 4096;
    while (n < need)
        n *= 2;
    uint8_t *p = realloc(*buf, n);
    if (!p)
        return -1;
    *buf = p;
    *cap = n;
    return 0;
}

/* ---- connection --------------------------------------------------- */

struct wl_conn *wl_connect(const char *path)
{
    if (!path)
        path = getenv("WAYLAND_DISPLAY");
    if (!path)
        path = "wayland-0";
    if (path[0] != '/')
        return NULL; /* caller resolves XDG_RUNTIME_DIR to an absolute path */

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return NULL;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof sa.sun_path) {
        close(fd);
        return NULL;
    }
    strcpy(sa.sun_path, path);

    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return NULL;
    }

    /* Non-blocking from the start. A tool that inspects a compositor must be able
     * to say "nothing more to read" and return, instead of parking forever when
     * the peer is idle. Callers that want to wait use poll(). */
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    struct wl_conn *c = calloc(1, sizeof *c);
    if (!c) {
        close(fd);
        return NULL;
    }
    c->fd = fd;
    c->next_id = 1; /* id 1 is wl_display, implicitly allocated */
    return c;
}

void wl_close(struct wl_conn *c)
{
    if (!c)
        return;
    if (c->fd >= 0)
        close(c->fd);
    for (size_t i = 0; i < c->n_globals; i++)
        free(c->globals[i].iface);
    free(c->globals);
    free(c->in);
    free(c);
}

uint32_t wl_new_id(struct wl_conn *c) { return c->next_id++; }

/* ---- outbound ----------------------------------------------------- */

void wl_msg_begin(struct msg *m, uint32_t id, uint32_t opcode)
{
    /* One fixed-size allocation per message. Capacity is implicit and constant,
     * so `ensure` below can reason about it without tracking it separately. */
    memset(m, 0, sizeof *m);
    m->w = calloc(MSG_MAX_WORDS, sizeof(uint32_t));
    if (!m->w)
        return;
    m->w[0] = id;
    m->w[1] = 2; /* word count, patched by wl_msg_send */
    m->w[2] = opcode;
    m->n = 3;
}

static int ensure(struct msg *m, size_t extra)
{
    if (!m->w)
        return -1;
    return (m->n + extra <= MSG_MAX_WORDS) ? 0 : -1;
}

void wl_msg_u32(struct msg *m, uint32_t v)
{
    if (ensure(m, 1) != 0)
        return;
    m->w[m->n++] = v;
}

void wl_msg_i32(struct msg *m, int32_t v) { wl_msg_u32(m, (uint32_t)v); }

/* Wayland strings: u32 length INCLUDING the trailing NUL, then bytes padded to
 * a 4-byte boundary. NULL is length 0. */
void wl_msg_string(struct msg *m, const char *s)
{
    if (!s) {
        wl_msg_u32(m, 0);
        return;
    }
    size_t len = strlen(s) + 1;
    size_t words = (len + 3) / 4;
    if (ensure(m, 1 + words) != 0)
        return;
    m->w[m->n++] = (uint32_t)len;
    uint8_t *dst = (uint8_t *)&m->w[m->n];
    memcpy(dst, s, len);
    size_t pad = words * 4 - len;
    if (pad)
        memset(dst + len, 0, pad);
    m->n += words;
}

void wl_msg_fd(struct msg *m, int fd)
{
    /* fds travel out-of-band; recorded as a 0 word placeholder here */
    (void)fd;
    wl_msg_u32(m, 0);
}

int wl_msg_send(struct wl_conn *c, struct msg *m)
{
    if (!m->w) {
        return -1;
    }
    m->w[1] = (uint32_t)m->n;
    size_t bytes = m->n * sizeof(uint32_t);
    const uint8_t *p = (const uint8_t *)m->w;
    while (bytes) {
        ssize_t k = write(c->fd, p, bytes);
        if (k <= 0) {
            if (k < 0 && errno == EINTR)
                continue;
            free(m->w);
            m->w = NULL;
            m->n = 0;
            return -1;
        }
        p += k;
        bytes -= (size_t)k;
    }
    free(m->w);
    m->w = NULL;
    m->n = 0;
    return 0;
}

/* ---- inbound ------------------------------------------------------ */

/* Returns 1 if bytes were added, 0 if the socket would block (caller should
 * return an idle result), -1 on real error or peer close. */
static int read_more(struct wl_conn *c)
{
    if (grow_bytes(&c->in, &c->in_cap, c->in_len + 4096) != 0)
        return -1;
    ssize_t k = read(c->fd, c->in + c->in_len, c->in_cap - c->in_len);
    if (k < 0) {
        if (errno == EINTR)
            return 1;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }
    if (k == 0)
        return -1; /* peer closed */
    c->in_len += (size_t)k;
    return 1;
}

/* Returns 1 with a complete message, 0 if more bytes are needed, -1 on error. */
static int next_msg(struct wl_conn *c, uint32_t *id, uint32_t *opcode,
                    uint32_t **args, size_t *n_args)
{
    for (;;) {
        if (c->in_len >= 8) {
            uint32_t *w = (uint32_t *)c->in;
            uint32_t words = w[1];
            if (words < 2)
                return -1; /* malformed */
            if ((size_t)words * 4 > MAX_MESSAGE_BYTES)
                return -1; /* larger than we will ever buffer */
            if (c->in_len >= (size_t)words * 4) {
                *id = w[0];
                *opcode = w[2];
                *args = w + 3;
                *n_args = words - 3;
                size_t consumed = (size_t)words * 4;
                memmove(c->in, c->in + consumed, c->in_len - consumed);
                c->in_len -= consumed;
                return 1;
            }
        }
        int r = read_more(c);
        if (r < 0)
            return -1;
        if (r == 0)
            return 0; /* would block: hand control back to the caller */
    }
}

/* ---- globals ------------------------------------------------------ */

void wl_add_global(struct wl_conn *c, uint32_t name, const char *iface,
                   uint32_t version)
{
    if (c->n_globals == c->globals_cap) {
        size_t cap = c->globals_cap ? c->globals_cap * 2 : 32;
        struct wl_global *g = realloc(c->globals, cap * sizeof *g);
        if (!g)
            return;
        c->globals = g;
        c->globals_cap = cap;
    }
    struct wl_global *g = &c->globals[c->n_globals++];
    g->name = name;
    g->iface = strdup(iface ? iface : "");
    g->version = version;
}

struct wl_global *wl_find_global(struct wl_conn *c, const char *iface)
{
    for (size_t i = 0; i < c->n_globals; i++)
        if (strcmp(c->globals[i].iface, iface) == 0)
            return &c->globals[i];
    return NULL;
}

size_t wl_global_count(struct wl_conn *c) { return c->n_globals; }

struct wl_global *wl_global_at(struct wl_conn *c, size_t i)
{
    return i < c->n_globals ? &c->globals[i] : NULL;
}

/* ---- dispatch ----------------------------------------------------- */

int wl_dispatch(struct wl_conn *c, wl_event_fn on_event, void *user)
{
    for (;;) {
        uint32_t id = 0, opcode = 0;
        uint32_t *args = NULL;
        size_t n = 0;

        int r = next_msg(c, &id, &opcode, &args, &n);
        if (r < 0)
            return -1;
        if (r == 0)
            return 0;

        if (id == WL_DISPLAY_ID) {
            if (opcode == 0)
                return -2; /* wl_display.error */
            continue;
        }

        if (on_event && on_event(c, id, opcode, args, n, user) != 0)
            return 1;
    }
}

int wl_roundtrip(struct wl_conn *c)
{
    (void)c;
    return 0; /* implemented at a higher layer with wl_display.sync */
}
