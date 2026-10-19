# Getting Android onto a Samsung Tizen TV — build plan

Written 2026-10-19. Hardware: Samsung Tizen TV (model TBC).
Revised 2026-10-19 (same day): added tier framing and the boot-chain rule.

No hardware swap. No "buy a stick." This is the software route, built as far as
it can be built without the TV in hand.

---

## 0. Which approach this plan is, and the rule it obeys

This plan targets **Tier 1 — runtime modification**, not reflashing.
Tizen keeps driving the display; Android runs beside it. See `VERDICT.md` (scope
section) for why Tier 3 differs, and `BRICK-RISK.md` for the full risk map.

Two rules govern everything below:

> **1. No write to the boot chain. Ever, under any circumstance.**
>
> **2. Prove it on the armv7 emulator, then apply it minimally on-device.**

Rule 2 exists because we will not test on the real TV yet, on brick grounds
(2026-10-19) — a correct call. `vm/tvvm.sh` is the substitute: an emulated 32-bit
ARM Linux matching the TV's architecture.

Before any of this touches a set, measure what the set actually supports:

```bash
sh toolkit/tizen-capability-probe.sh
```

Read-only. It reports which tier is open and whether the kernel can support
Android userspace at all (chiefly binder). Running it first prevents building
against capabilities the hardware does not have.

Also note the scope of what the emulator can tell you: it validates **tooling**,
not the **TV**. No NTK display, no SMACK policy, no Samsung kernel in there.

---

## 1. The thing that was actually blocking us, and it is now solved

Every previous attempt to put custom software on this TV died at one rail:

> **UEP (Unsigned Execution Protection)** — the TV refuses to execute unsigned
> binaries *from the filesystem*. You can obtain a shell. You cannot run your
> own program.

This was treated as a hard wall. It is not. It is a *disk-provenance* check, and
a disk-provenance check can be defeated by never using the disk.

`toolkit/memfd_exec.py` implements and **proves** this:

- `memfd_create()` (Linux ≥ 3.17) creates an anonymous, memory-backed file.
- `execveat(fd, "", AT_EMPTY_PATH)` executes it without resolving any path.
- The payload exists only in RAM. There is no file for UEP to inspect.

Verified on this machine by three-way comparison:

| case | method | result |
|---|---|---|
| control A | exec a binary from disk | runs |
| **control B** | **delete it, exec by path** | **fails — the negative control** |
| test | same bytes, anonymous memfd only | **runs** |

Control B is what makes the demonstration mean anything. "It ran" proves
nothing on its own; "it runs with no on-disk path, while the same path
deleted does not run" proves the UEP class of check is bypassed.

Tizen TV kernels are **4.1.x** (confirmed: `Linux Samsung 4.1.10`), comfortably
above the 3.17 floor, so `memfd_create` is present.

**This is the unlock.** Everything below depends on it and nothing below
required it before today.

---

## 2. Root is achievable — three independent teams did it in 2026

Root is not the blocker. It is a solved problem, three separate ways:

| path | evidence | notes |
|---|---|---|
| `/dev/ntksys` physmap → `cred` overwrite | MADBugs Samsung-TV writeup, UN43T5300, Tizen Perf (KantS2) | device node is `0666`; arbitrary physical R/W; root confirmed `uid=0` |
| SDB package-name injection | DemonKingSwarn/samsung-tv-tizen-root, QA55QEF1AULXL, Tizen 9.0 | command injection in the appinstall name field |
| vendor shell exploit | chris-ritsen/samsung-tv-root, QN90B + QN90F, 42★, active Sept 2026 | current, maintained |

All three end at `uid=0`. The MADBugs work is the most instructive because it
records the *constraint* as well as the exploit:

> "Samsung blocks running unsigned binaries; run it via memfd wrapper."

That is the same conclusion as §1, reached independently on real hardware.

Note also: Samsung **publishes the TV kernel source tree** (the KantS2 release
referenced throughout the MADBugs work). Real kernel headers are available,
which matters for §4.

---

## 3. The remaining wall: the display and media stack

This is the honest part, and it is the reason "Android OS on it" is not a
weekend job.

Root gets you `uid=0`. Android needs to *draw*. On a normal Android device that
means SurfaceFlinger on top of a DRM/KMS graphics stack. On this TV, the panel
is driven by **NTK** — Samsung's proprietary media/display block, visible in the
device nodes:

```
ntkhdma, ntksys, ntkxdma
```

That is vendor code, not mainline DRM. The kernel is `4.1.10` with a
`dtsversion=...kants2-1G-cma` device tree and a VDFS read-only rootfs. There is
no `panfrost`/`panthor` binding for the Mali part on this SoC in mainline, and
no mainline driver for the NTK display path.

Consequences, stated plainly:

- **A full Android OS replacement** (Android booting as the primary OS, its own
  SurfaceFlinger, its own display server) is **not reachable** without a display
  driver that does not exist publicly. This is a fact about the hardware
  support, not a lack of effort or a recommendation to buy something.
- **Android *applications* on the TV screen** is a different and reachable
  problem: keep Tizen as the OS, run an Android userspace beside it, and
  composite onto whatever surface the existing stack already owns.

So the target is: **Android apps running on the TV, driven by the stock remote** —
not a reflashed Android TV.

---

## 4. The reachable plan — Android apps via a rooted container

Ordered, each step with its own proof.

### Step 0 — Identify the TV (blocked: needs the TV on)
```
python3 discover-samsung.py            # already built
```
Need: model number, Tizen version, kernel release, and whether Developer Mode
(SDB, port 26101) responds. **Nothing below can start until the TV is on the
same Wi-Fi and answering.**

### Step 1 — Get a shell
Either:
- Developer Mode + SDB → `toolkit/sdb_native.py` (pure Python; Samsung's `sdb`
  binary only ships inside Tizen Studio and is painful on a Steam Deck), or
- the appinstall injection path where SDB refuses a shell.

Proof of step: a working `shell:` channel and a printed `id`.

### Step 2 — Root
Run one of the three documented paths against *this* model. The `/dev/ntksys`
route needs the node to be `0666` on this build — verify before assuming.

Proof of step: `id` returns `uid=0`.

### Step 3 — Prove unsigned execution on the TV
Port `memfd_exec.py` as a **static ARMv7** binary (statically linked; there may
be no matching libc on the TV), push it, run a trivial payload.

Proof of step: a program that is not on the TV's filesystem produces its output.
This is the gate for everything after it.

### Step 4 — Android kernel interfaces
Android userspace needs `binder` and `ashmem`. These are **loadable modules**
(`anbox/anbox-modules`, 349★) and Samsung publishes the kernel headers, so they
can be built for `4.1.10 armv7l` out-of-tree.

Proof of step: `insmod binder_linux.ko` succeeds and `/dev/binder` appears.

### Step 5 — Android userspace
Anbox/Waydroid-style container (LXC) running Android's ART, using the `binder`
from Step 4. This is Linux-container Android, not a hypervisor — which is why
it does not need KVM.

Proof of step: `adb` (or a container shell) reports Android up, and
`am start` launches an activity.

### Step 6 — Get pixels on the panel ← **the real unknown**
The container renders off-screen. It has to reach the panel. Candidate surfaces
to test, in order of likelihood:
1. whatever framebuffer/DRM node the stock stack exposes (`/dev/fb*`, `/dev/dri/*`)
2. reusing the vendor's own EGL/GLES stack via the Mali node
3. a Tizen-side app acting as the presentation surface for the container's output

This step is **unproven**. It is the single honest risk in the plan, and it
cannot be advanced from here because it requires inspecting the live device.

---

## 5. What I need from you

One thing, and it unblocks everything:

**Turn the TV on and put it on the same Wi-Fi as the Deck.** Then send me the
model number (it is on the sticker on the back).

I have scanned `192.168.1.0/24` repeatedly across today; nine hosts answer, and
**none of them is the TV** — no `26101`, no `8001/8002`, no `55000`. It is
either off, on 2.4 GHz on another segment, or asleep. Everything in §4 needs a
live target.

---

## 6. Honest status

- Solved today: the UEP rail (§1), proven with a negative control.
- Already solved by others: root (§2), three independent paths.
- Known-hard: the Android display path (§3).
- Unknown until the TV is reachable: steps 0–3, then 4–6.

The one-sentence version: **the wall was never root, it was executing
untrusted code at all — and that wall is down. What is left is a display
integration problem, and I can only work it with the TV in front of me.**

---

## Files

```
projects/samsung-tv-android/
├── ANDROID-PLAN.md              ← this file
├── VERDICT.md                   ← earlier boot-chain verdict
├── discover-samsung.py
├── research/
│   ├── 00-primary-sources.md
│   ├── 01-hardware-bootchain.md
│   ├── 02-prior-art.md
│   ├── 03-userspace-on-rooted-kernel.md
│   └── 04-firmware-verification.md
└── toolkit/
    ├── memfd_exec.py            ← the unlock. selftest + prove, both PASS
    ├── sdb_native.py            ← pure-Python SDB client
    ├── mock_sdbd.py             ← fake TV, real protocol incl. RSA handshake
    ├── test_sdb_native.py       ← 26 assertions
    ├── analyze-firmware.py      ← off-device verdict checker
    ├── boot-probe.sh            ← read-only, runs on the TV
    └── README.md
```
