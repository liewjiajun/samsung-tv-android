/* wl.h — minimal Wayland wire protocol, no libwayland dependency. */
#ifndef WL_H
#define WL_H

#include <stddef.h>
#include <stdint.h>

#define WL_DISPLAY_ID 1u

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

/* outbound message building */
void wl_msg_begin(struct msg *m, uint32_t id, uint32_t opcode);
void wl_msg_u32(struct msg *m, uint32_t v);
void wl_msg_i32(struct msg *m, int32_t v);
void wl_msg_string(struct msg *m, const char *s);
void wl_msg_fd(struct msg *m, int fd);
int wl_msg_send(struct wl_conn *c, struct msg *m);

/* registry accumulation */
void wl_add_global(struct wl_conn *c, uint32_t name, const char *iface,
                   uint32_t version);
struct wl_global *wl_find_global(struct wl_conn *c, const char *iface);
size_t wl_global_count(struct wl_conn *c);
struct wl_global *wl_global_at(struct wl_conn *c, size_t i);

/* Event callback: return 0 to continue, non-zero to stop dispatch.
 * args points at the argument words, n is how many there are. */
typedef int (*wl_event_fn)(struct wl_conn *c, uint32_t id, uint32_t opcode,
                           const uint32_t *args, size_t n, void *user);

/* Returns 0 when the socket has no more complete messages, -1 on IO error,
 * -2 on protocol error, 1 when a callback asked to stop. */
int wl_dispatch(struct wl_conn *c, wl_event_fn on_event, void *user);

int wl_roundtrip(struct wl_conn *c);

#endif /* WL_H */
