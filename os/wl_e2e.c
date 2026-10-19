/* wl_e2e.c — end-to-end: our client talks to a protocol peer and puts pixels
 * where the peer can see them.
 *
 * Proves:
 *   - registry enumeration finds the interfaces we need
 *   - bind() arg order is correct (wrong order makes the peer misparse)
 *   - the shm fd really arrives over SCM_RIGHTS and maps in the peer
 *   - our drawing lands in that shared memory
 *   - commit() is reached
 *
 * Structure: the fake compositor runs on its own thread. The client blocks
 * waiting for replies, which is what a real client does, so the peer must be
 * able to answer concurrently. A single-threaded interleave cannot work here
 * because wl_window_create waits inside the call.
 */
#include "wl.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct server;
int fake_server_start(struct server **out, const char *path);
int fake_server_accept(struct server *s);
int fake_server_pump(struct server *s, int rounds, int quiet_ms);
void fake_server_stop(struct server *s);
int fake_server_commits(struct server *s);
int fake_server_buffer_w(struct server *s);
int fake_server_buffer_h(struct server *s);
uint32_t fake_server_pixel(struct server *s, int x, int y);

static int failures;
#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, msg);               \
            failures++;                                                        \
        }                                                                      \
    } while (0)

#define WIDTH 64
#define HEIGHT 32

/* ---- client event handler ------------------------------------------ */

static int on_event(struct wl_conn *c, uint32_t id, uint32_t opcode,
                    const uint32_t *args, size_t n, void *user)
{
    (void)user;
    if (opcode == 0 && n >= 3) {
        uint32_t name = args[0], len = args[1];
        if (len == 0 || len > (n - 2) * 4)
            return 0;
        const char *iface = (const char *)&args[2];
        size_t words = (len + 3) / 4;
        if (2 + words >= n)
            return 0;
        wl_add_global(c, name, iface, args[2 + words]);
    }
    return 0;
}

/* ---- server thread -------------------------------------------------- */

struct srv_thread {
    struct server *srv;
    volatile int accepted;
    volatile int stop;
};

static void *server_thread(void *arg)
{
    struct srv_thread *t = arg;
    /* Wait for the client to connect. */
    for (int i = 0; i < 500 && !t->stop; i++) {
        if (fake_server_accept(t->srv) == 0) {
            t->accepted = 1;
            break;
        }
        usleep(5000);
    }
    if (!t->accepted)
        return NULL;

    /* Serve continuously until told to stop. */
    while (!t->stop)
        fake_server_pump(t->srv, 64, 5);
    /* final drain so the last commit is captured */
    fake_server_pump(t->srv, 256, 5);
    return NULL;
}

int main(void)
{
    /* A write to a dead peer must not kill the test; we want to see the error. */
    signal(SIGPIPE, SIG_IGN);

    const char *path = "/tmp/wl_e2e.sock";
    printf("wl_e2e: client to compositor, end to end\n");

    struct server *srv = NULL;
    CHECK(fake_server_start(&srv, path) == 0, "start fake compositor");
    if (!srv) {
        printf("RESULT=FAIL could not start peer\n");
        return 1;
    }

    struct srv_thread t = {.srv = srv, .accepted = 0, .stop = 0};
    pthread_t th;
    if (pthread_create(&th, NULL, server_thread, &t) != 0) {
        printf("RESULT=FAIL cannot start peer thread\n");
        fake_server_stop(srv);
        return 1;
    }

    struct wl_conn *c = NULL;
    for (int i = 0; i < 60 && !c; i++) {
        c = wl_connect(path);
        if (!c)
            usleep(10000);
    }
    CHECK(c != NULL, "connect to compositor");
    if (!c) {
        t.stop = 1;
        pthread_join(th, NULL);
        fake_server_stop(srv);
        printf("RESULT=FAIL could not connect\n");
        return 1;
    }

    /* Registry enumeration. */
    uint32_t reg = wl_new_id(c);
    struct msg m;
    wl_msg_begin(&m, WL_DISPLAY_ID, 1 /* get_registry */);
    wl_msg_u32(&m, reg);
    CHECK(wl_msg_send(c, &m) == 0, "send get_registry");

    /* Wait for the FULL expected set, not just the two we plan to bind. Stopping
     * early and then asserting on a third global is a race: under slower
     * emulation the later globals have not arrived yet, and the test fails on a
     * correct implementation. A real client wants the whole registry anyway. */
    for (int i = 0; i < 400; i++) {
        wl_dispatch(c, on_event, NULL);
        if (wl_find_global(c, "wl_compositor") && wl_find_global(c, "wl_shm") &&
            wl_find_global(c, "wl_seat"))
            break;
        usleep(10000);
    }

    CHECK(wl_find_global(c, "wl_compositor") != NULL, "found wl_compositor");
    CHECK(wl_find_global(c, "wl_shm") != NULL, "found wl_shm");
    CHECK(wl_find_global(c, "wl_seat") != NULL, "found wl_seat");
    CHECK(wl_global_count(c) == 3, "all three globals");

    /* Bind, allocate shared memory, attach, commit. */
    struct wl_window *w = wl_window_create(c, WIDTH, HEIGHT,
                                           WL_SHM_FORMAT_XRGB8888,
                                           on_event, NULL, 3000);
    CHECK(w != NULL, "window created");

    if (w) {
        CHECK(w->compositor_id > 0, "bound compositor");
        CHECK(w->shm_id > 0, "bound shm");
        CHECK(w->surface_id > 0, "created surface");
        CHECK(w->memfd >= 0, "backing memory allocated");
        CHECK(w->pixels != NULL, "memory mapped locally");
        CHECK(w->width == WIDTH && w->height == HEIGHT, "geometry");

        CHECK(wl_window_pixel(w, 5, 5, 0x00FF0000) == 0, "draw red");
        CHECK(wl_window_pixel(w, 10, 7, 0x0000FF00) == 0, "draw green");
        CHECK(wl_window_pixel(w, 0, 0, 0x000000FF) == 0, "draw blue");
        CHECK(wl_window_pixel(w, WIDTH, 0, 0xFFFFFFFF) == -1, "reject x too big");
        CHECK(wl_window_pixel(w, 0, -1, 0xFFFFFFFF) == -1, "reject negative y");
        CHECK(w->pixels != NULL, "still mapped after rejected writes");
        CHECK(wl_window_present(w) == 0, "present");
        /* edge pixel is the last valid coordinate */
        CHECK(wl_window_pixel(w, WIDTH - 1, HEIGHT - 1, 0x00123456) == 0,
              "draw at last pixel");
    }

    /* One full round trip so the peer has certainly processed the commit. */
    wl_sync(c, on_event, NULL, 2000);
    usleep(200000);

    CHECK(fake_server_commits(srv) >= 2, "peer saw commits");
    CHECK(fake_server_buffer_w(srv) == WIDTH, "peer buffer width");
    CHECK(fake_server_buffer_h(srv) == HEIGHT, "peer buffer height");

    if (fake_server_commits(srv) > 0) {
        CHECK(fake_server_pixel(srv, 5, 5) == 0x00FF0000, "red pixel reached peer");
        CHECK(fake_server_pixel(srv, 10, 7) == 0x0000FF00, "green pixel reached peer");
        CHECK(fake_server_pixel(srv, 0, 0) == 0x000000FF, "blue pixel reached peer");
        CHECK(fake_server_pixel(srv, WIDTH - 1, HEIGHT - 1) == 0x00123456,
              "corner pixel reached peer");
        CHECK(fake_server_pixel(srv, 1, 1) == 0x00000000, "background untouched");
    }

    if (w)
        wl_window_close(w);
    wl_close(c);

    t.stop = 1;
    pthread_join(th, NULL);
    fake_server_stop(srv);

    if (failures) {
        printf("RESULT=FAIL failures=%d\n", failures);
        return 1;
    }
    printf("RESULT=PASS client drew pixels a peer could read\n");
    return 0;
}
