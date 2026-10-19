# os/ — our userspace, built from scratch

Target: Tizen TVs cannot have their kernel or rootfs replaced (fused, per-section
RSA). So "our own OS" means **our userspace running on Samsung's kernel**. This
directory is that userspace, written from zero.

## Design rule

Do not link Samsung's libraries. The TV ships `libwayland-client`, `libwayland-server`,
`libmali.so`, `libEGL`. Using them means inheriting Tizen's versions, ABIs and bugs,
and it means our OS cannot run anywhere else. We implement the protocols we need
ourselves, so the code is portable and the device is an output target rather than a
dependency.

## What is here

`wl.h` / `wl.c` — a Wayland wire-protocol client with no libwayland dependency.

Implements:
- connection over `AF_UNIX`
- message framing (id, word count, opcode)
- argument marshalling: `u32`, `i32`, strings (length includes NUL, 4-byte padded)
- inbound reassembly across split reads
- registry accumulation and interface lookup by name
- **non-blocking** operation, so a tool can report "compositor idle" instead of parking

Deliberate choices:
- **Non-blocking.** A blocking read makes an idle compositor indistinguishable from a
  dead one. `wl_dispatch` returns 0 for "nothing more to read".
- **Bounded buffers.** `MAX_MESSAGE_BYTES` (1 MiB) refuses an oversized inbound frame.
  A compositor is a peer; its length fields are not automatically trustworthy.
- **Fixed per-message capacity.** `MSG_MAX_WORDS` is constant so capacity reasoning is
  trivial. A growable builder here was the source of a real overflow during development.

`wl_selftest.c` — proves the protocol layer with no compositor present. Stands up a
unix socket pair, feeds it registry events, checks framing, padding, split-read
reassembly, bounds checks, and the idle path. Fails loudly on any of them.

## Verified state

Builds and passes for **armv7 (EABI5, cortex-a7), statically linked** — the TV's CPU
class — under `qemu-arm`. Also passes natively.

```
zig cc -target arm-linux-musleabihf -mcpu=cortex_a7 -static -Os -o wl_test wl.c wl_selftest.c
qemu-arm-static ./wl_test        # RESULT=PASS all checks
```

Toolchain: zig 0.13.0 (no root, no system cross-gcc needed).

## Next

1. `wl_display.sync` round-trip, so registry enumeration is known-complete.
2. `wl_compositor` / `wl_surface` / `wl_shm` — enough to put our own pixels on the panel.
3. A minimal compositor, so we are not reliant on Tizen presenting our windows.
