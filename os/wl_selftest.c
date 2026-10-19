/* wl_selftest.c — prove the wire protocol without a real compositor.
 *
 * We stand up a pair of connected unix sockets, put a fake registry on one end,
 * and check that:
 *   - our outbound messages have correct framing (id, word count, opcode)
 *   - strings are NUL-terminated, length-inclusive, and 4-byte padded
 *   - the inbound parser reassembles messages across split reads
 *   - globals land in the table with names preserved
 *
 * If this passes on the host and under qemu-arm, the protocol layer is sound
 * and any remaining failure is the compositor's, not ours.
 */
#include "wl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, msg);               \
            failures++;                                                        \
        }                                                                      \
    } while (0)

/* ---- framing test: build a message and inspect its bytes ---------------- */

static void test_message_framing(void)
{
    /* We cannot call wl_msg_send without a socket, so build into a msg and
     * check the words directly. */
    struct msg m;
    wl_msg_begin(&m, 7, 3);          /* object 7, opcode 3 */
    wl_msg_u32(&m, 0xdeadbeef);
    wl_msg_string(&m, "wl_compositor");

    /* header(2) + opcode(1) + u32(1) + [len(1) + 4 words] */
    CHECK(m.n == 3 + 1 + 1 + 4, "word count");
    CHECK(m.w[0] == 7, "object id");
    CHECK(m.w[2] == 3, "opcode");
    CHECK(m.w[3] == 0xdeadbeef, "u32 arg");

    /* string: length includes NUL */
    uint32_t slen = m.w[4];
    CHECK(slen == strlen("wl_compositor") + 1, "string length includes NUL");

    const char *s = (const char *)&m.w[5];
    CHECK(strcmp(s, "wl_compositor") == 0, "string payload");

    /* padding must be zeroed */
    size_t padded = ((slen + 3) / 4) * 4;
    const unsigned char *raw = (const unsigned char *)&m.w[5];
    for (size_t i = slen; i < padded; i++)
        CHECK(raw[i] == 0, "string padding zeroed");

    free(m.w);
}

static void test_null_string(void)
{
    struct msg m;
    wl_msg_begin(&m, 1, 0);
    wl_msg_string(&m, NULL);
    CHECK(m.n == 4, "null string is one word");
    CHECK(m.w[3] == 0, "null string len 0");
    free(m.w);
}

/* ---- inbound reassembly test ------------------------------------------- */

struct counter {
    int globals;
    int done;
    char first_iface[64];
    uint32_t first_version;
};

static int on_event(struct wl_conn *c, uint32_t id, uint32_t opcode,
                    const uint32_t *args, size_t n, void *user)
{
    struct counter *ct = user;
    (void)id;

    if (opcode == 0 && n >= 3) {
        /* registry global: name, interface string, version.
         * Bounds-check the string before trusting its length: a compositor is a
         * peer, and a peer's length field is not automatically trustworthy. */
        uint32_t name = args[0];
        uint32_t len = args[1];
        if (len == 0 || len > (n - 2) * 4)
            return 0;
        const char *iface = (const char *)&args[2];
        size_t words = (len + 3) / 4;
        if (2 + words >= n)
            return 0;
        uint32_t ver = args[2 + words];
        wl_add_global(c, name, iface, ver);
        if (ct->globals == 0) {
            snprintf(ct->first_iface, sizeof ct->first_iface, "%s", iface);
            ct->first_version = ver;
        }
        ct->globals++;
    }
    return 0;
}

/* Build a fake registry event the way a compositor would emit it.
 * Words: header(3: id, count, opcode) + name(1) + strlen(1) + string(words)
 *        + version(1)  =>  total 6 + words
 * The count field must include the version word, or the trailing word is left
 * in the stream and parsed as the next message's header. */
static size_t make_global(uint8_t *out, uint32_t name, const char *iface,
                          uint32_t version)
{
    uint32_t *w = (uint32_t *)out;
    size_t len = strlen(iface) + 1;
    size_t words = (len + 3) / 4;
    size_t n = 0;

    w[n++] = 2;                         /* registry object id */
    w[n++] = (uint32_t)(6 + words);      /* total words, incl. header + version */
    w[n++] = 0;                          /* opcode: global */
    w[n++] = name;
    w[n++] = (uint32_t)len;
    memcpy(&w[n], iface, len);
    size_t pad = words * 4 - len;
    if (pad)
        memset((uint8_t *)&w[n] + len, 0, pad);
    n += words;
    w[n++] = version;
    return n; /* in words */
}

/* Drive dispatch until it reports idle. In non-blocking mode a partial message
 * legitimately yields "nothing yet", so we loop with a bounded number of tries
 * and a short poll instead of assuming one call sees everything. */
static int drain(struct wl_conn *c, struct counter *ct, int max_rounds)
{
    for (int i = 0; i < max_rounds; i++) {
        int r = wl_dispatch(c, on_event, ct);
        if (r == -1)
            return -1;
        if (r == 0)
            return 0; /* idle */
        if (r == -2)
            return -2;
    }
    return 1;
}

static void test_inbound_split(void)
{
    const char *path = "/tmp/wl_selftest.sock";
    unlink(path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(fd >= 0, "listen socket");
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path);
    CHECK(bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0, "bind");
    CHECK(listen(fd, 1) == 0, "listen");

    struct wl_conn *c = wl_connect(path);
    CHECK(c != NULL, "wl_connect to test socket");

    int peer = accept(fd, NULL, NULL);
    CHECK(peer >= 0, "accept");

    if (!c || peer < 0) {
        close(fd);
        unlink(path);
        return;
    }

    uint8_t buf[256];
    struct counter ct;
    memset(&ct, 0, sizeof ct);

    /* idle first: nothing written yet, so dispatch must return 0, not block */
    CHECK(wl_dispatch(c, on_event, &ct) == 0, "idle returns 0");
    CHECK(ct.globals == 0, "idle parsed nothing");

    size_t n1 = make_global(buf, 10, "wl_compositor", 4);

    /* Split mid-message: parser must hold the partial and report idle. */
    size_t half = (n1 * 4) / 2;
    CHECK(write(peer, buf, half) == (ssize_t)half, "write first half");
    usleep(50000);
    CHECK(wl_dispatch(c, on_event, &ct) == 0, "partial yields idle");
    CHECK(ct.globals == 0, "no global from partial");

    /* Second half completes the message. */
    size_t rest = n1 * 4 - half;
    CHECK(write(peer, buf + half, rest) == (ssize_t)rest, "write second half");
    usleep(50000);
    CHECK(drain(c, &ct, 8) == 0, "drain ok");
    CHECK(ct.globals == 1, "one global parsed");
    CHECK(strcmp(ct.first_iface, "wl_compositor") == 0, "iface name");
    CHECK(ct.first_version == 4, "iface version");

    /* second global */
    size_t n2 = make_global(buf, 11, "wl_shm", 1);
    CHECK(write(peer, buf, n2 * 4) == (ssize_t)(n2 * 4), "write second global");
    usleep(50000);
    CHECK(drain(c, &ct, 8) == 0, "drain 2 ok");
    CHECK(ct.globals == 2, "two globals");

    struct wl_global *g = wl_find_global(c, "wl_shm");
    CHECK(g != NULL, "find wl_shm");
    CHECK(g && g->name == 11, "wl_shm name");
    CHECK(wl_find_global(c, "wl_nope") == NULL, "missing global is NULL");

    wl_close(c);
    close(peer);
    close(fd);
    unlink(path);
}

static void test_registry_bind_shape(void)
{
    /* wl_registry.bind(new_id, name, interface, version) — 4 words of args */
    struct msg m;
    wl_msg_begin(&m, 2, 0);        /* registry id 2, opcode 0 = bind */
    wl_msg_u32(&m, 99);            /* new id */
    wl_msg_u32(&m, 10);            /* global name */
    wl_msg_string(&m, "wl_shm");   /* interface */
    wl_msg_u32(&m, 1);             /* version */

    CHECK(m.w[0] == 2, "bind target");
    CHECK(m.w[2] == 0, "bind opcode");
    CHECK(m.w[3] == 99, "new id");
    CHECK(m.w[4] == 10, "global name");
    uint32_t len = m.w[5];
    CHECK(len == strlen("wl_shm") + 1, "iface len");
    CHECK(strcmp((const char *)&m.w[6], "wl_shm") == 0, "iface");
    free(m.w);
}

int main(void)
{
    printf("wl_selftest: Wayland wire protocol\n");
    test_message_framing();
    test_null_string();
    test_registry_bind_shape();
    test_inbound_split();

    if (failures) {
        printf("RESULT=FAIL failures=%d\n", failures);
        return 1;
    }
    printf("RESULT=PASS all checks\n");
    return 0;
}
