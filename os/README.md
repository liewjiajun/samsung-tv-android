# os/ — our userspace, built from scratch

Target: Samsung Tizen TVs cannot have their kernel or rootfs replaced (fused boot
chain, per-section RSA). So "our own OS" means **our userspace running on Samsung's
kernel**. This directory is that userspace, written from zero.

## Design rule

Do not link Samsung's libraries. The TV ships `libwayland-client`, `libwayland-server`,
`libmali.so`, `libEGL`. Using them means inheriting Tizen's ABIs, versions and bugs,
and the code cannot run anywhere else. We implement the protocols we need ourselves,
so the device is an output target rather than a dependency.

## Files

`wl.h` / `wl.c` — Wayland wire protocol, no libwayland.
- connection over `AF_UNIX`
- framing (object id, word count, opcode)
- argument marshalling: `u32`, `i32`, strings (length includes NUL, 4-byte padded)
- inbound reassembly across split reads
- registry accumulation, interface lookup by name
- `wl_display.sync` round-trip, so registry enumeration is provably complete
  rather than merely quiet

`wl_window.c` — registry bind, shm pool, surface, presentation.
- binds `wl_compositor` and `wl_shm`, clamped to versions implemented
- creates a surface
- allocates an anonymous `memfd` as the pixel buffer and passes it to
  `wl_shm.create_pool` via `SCM_RIGHTS` (fd travels with the message that uses it)
- `wl_shm_pool.create_buffer`, then attach / damage / commit to present

`wl_fake_compositor.c` — a protocol peer that is not a display server. It answers
exactly the requests our client makes, receives the shm fd, mmaps it, and snapshots
the pixels on commit. This is how the client is tested without a TV.

`wl_selftest.c` — protocol-level checks. No compositor needed.
`wl_e2e.c` — client to peer, end to end, asserting pixels arrive.

## Verified state

Passes on **armv7 EABI5 / cortex-a7, statically linked**, under `qemu-arm` — the TV's
CPU class — and natively on x86-64. Toolchain is zig 0.13.0, no root required.

```
zig cc -target arm-linux-musleabihf -mcpu=cortex_a7 -static -Os -pthread \
    -o wl_e2e wl.c wl_window.c wl_fake_compositor.c wl_e2e.c
qemu-arm-static ./wl_e2e    # RESULT=PASS client drew pixels a peer could read
```

E2E asserts: three globals enumerated, bind succeeds, surface created, memfd
allocated and mapped, four known pixel values readable by the peer, an untouched
pixel still background, and out-of-bounds writes refused.

## Bugs found while building this (all real, all silent if shipped)

1. **Use-after-move in the message parser.** `next_msg` returned args pointing into
   the receive buffer, then compacted that buffer with `memmove` to reclaim the
   consumed bytes — overwriting the message being dispatched. The callback read
   shifted fields. Looked exactly like the peer sending bad data. Now copies the
   message out first.
2. **Object id 1 collision.** The id allocator started at 1, which is `wl_display`'s
   reserved id. Every object we created aliased the display object, so requests went
   to the wrong target.
3. **Blocking reads.** First version blocked in the parse loop, making an idle
   compositor indistinguishable from a dead one. Sockets are now non-blocking and
   `wl_dispatch` returns 0 for "nothing more to read".
4. **Growable message buffer.** Wrote past the end of a 16-word allocation while
   `ensure()` assumed 512. Replaced with a fixed per-message capacity.
5. Test-only: a word count that omitted the version word, and an enumeration check
   that asserted on a global it had stopped waiting for. Both fixed; the second was
   a race that only showed under emulation.

## Next

1. `wl_surface.frame` callbacks, so presentation is paced by the compositor.
2. Input: `wl_seat` / `wl_pointer` / `wl_keyboard`, so the remote can drive our UI.
3. A minimal compositor of our own, so we are not reliant on Tizen presenting
   our windows.
