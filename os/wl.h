/* wl.h — minimal Wayland wire protocol + window layer, no libwayland. */
#ifndef WL_H
#define WL_H

#include <stddef.h>
#include <stdint.h>

#define WL_DISPLAY_ID 1u

/* wl_shm formats */
#define WL_SHM_FORMAT_ARGB8888 0u
#define WL_SHM_FORMAT_XRGB8888 1u

struct wl_conn;

struct wl_global {
    uint32_t name;
    char *iface;
    uint32_t version;
};

struct msg {
    uint32_t *w;
    size_t n;
};

/* connection */
struct wl_conn *wl_connect(const char *abs_socket_path);
void wl_close(struct wl_conn *c);
uint32_t wl_new_id(struct wl_conn *c);
int wl_fd(struct wl_conn *c);

/* outbound message building */
void wl_msg_begin(struct msg *m, uint32_t id, uint32_t opcode);
void wl_msg_u32(struct msg *m, uint32_t v);
void wl_msg_i32(struct msg *m, int32_t v);
void wl_msg_string(struct msg *m, const char *s);
int wl_msg_send(struct wl_conn *c, struct msg *m);
/* Send a message carrying one file descriptor out-of-band (SCM_RIGHTS).
 * Required for wl_shm.create_pool. Consumes *m. */
int wl_msg_send_fd(struct wl_conn *c, struct msg *m, int fd);

/* registry accumulation */
void wl_add_global(struct wl_conn *c, uint32_t name, const char *iface,
                   uint32_t version);
struct wl_global *wl_find_global(struct wl_conn *c, const char *iface);
size_t wl_global_count(struct wl_conn *c);
struct wl_global *wl_global_at(struct wl_conn *c, size_t i);
void wl_globals_reset(struct wl_conn *c);

/* Event callback: return 0 to continue, non-zero to stop dispatch. */
typedef int (*wl_event_fn)(struct wl_conn *c, uint32_t id, uint32_t opcode,
                           const uint32_t *args, size_t n, void *user);

/* Returns 0 when no further complete message is available, -1 on IO error,
 * -2 on protocol error, 1 when a callback asked to stop. */
int wl_dispatch(struct wl_conn *c, wl_event_fn on_event, void *user);

/* Dispatch, waiting up to timeout_ms when the socket is momentarily idle. */
int wl_dispatch_wait(struct wl_conn *c, wl_event_fn on_event, void *user,
                     int timeout_ms);

/* wl_display.sync round-trip: returns 0 once the compositor confirms it has
 * processed everything sent so far. Requires on_event to be dispatching. */
int wl_sync(struct wl_conn *c, wl_event_fn on_event, void *user, int timeout_ms);

/* ---- window layer ------------------------------------------------- */

struct wl_window {
    struct wl_conn *c;
    uint32_t compositor_id;
    uint32_t shm_id;
    uint32_t surface_id;
    uint32_t pool_id;
    uint32_t buffer_id;
    int memfd;
    void *pixels;
    size_t map_size;
    int width;
    int height;
    int stride;
    uint32_t shm_version;
};

/* Bind wl_compositor and wl_shm, create a surface, allocate a shm buffer and
 * attach it. Returns NULL with errno set on failure. */
struct wl_window *wl_window_create(struct wl_conn *c, int width, int height,
                                   uint32_t format,
                                   wl_event_fn on_event, void *user,
                                   int timeout_ms);

/* Mark the whole surface damaged and commit, i.e. present the buffer. */
int wl_window_present(struct wl_window *w);

void wl_window_close(struct wl_window *w);

/* Write one pixel, bounds-checked. */
int wl_window_pixel(struct wl_window *w, int x, int y, uint32_t argb);

#endif /* WL_H */
