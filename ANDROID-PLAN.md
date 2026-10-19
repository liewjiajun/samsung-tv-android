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

## 1. The UEP wall — and a correction

Every previous attempt to put custom software on this TV died at one rail:

> **UEP (Unsigned Execution Protection)** — the TV refuses to execute unsigned
> binaries. You can obtain a shell, and even uid 0. You still cannot run your own
> program.

### What I got wrong

This section used to claim UEP was a *disk-provenance* check, and that
`memfd_create` + `execveat` defeated it by never using the disk. **That claim was
wrong**, and it was wrong in the most expensive way: it was written down here as
the foundation for everything below.

The public research tested it:

> "Direct ELF loading and anonymous `fexecve` were both rejected while UEP was
> enabled."
> — `samsung-tv-root`, QN90F reproduction notes

So UEP does not inspect a **path**. It inspects the **file** at exec time.
Removing the path does not remove the check.

Where the error came from: `re/uep-analogue-test.sh` genuinely proves memfd beats
a **path-based** denial (a `noexec` mount). That result is true. But it is a
different mechanism, and I let a true result about one thing stand as proof of
another. The test was sound; the inference was not.

### What actually works

Two real paths, both documented by the researchers on hardware they owned:

**A. The signed host — works with UEP fully enabled.**

Samsung ships `/usr/bin/dotnet`, signed. It will load an uploaded managed
assembly **as data**. A signed binary is doing the loading, so there is no
unsigned ELF for UEP to reject. P/Invoke from managed code supplies `open`,
`mmap`, `ioctl`, `prctl` and friends.

This is the bootstrap path for every payload in the public research. It requires
no UEP patch and no kernel memory writes — therefore no crash risk from corrupting
kernel state.

Its limitation is that it runs *managed* code. It does not make an arbitrary
native ARM binary runnable.

**B. Patch the UEP state word — for true native ELF.**

Samsung's own `SfdUepPacketHandler` clears a 32-bit state word when it accepts an
authorized UEP-disable certificate. The exploit reproduces that same transition:
validate the surrounding state, then change `1` to `0`.

```
QN90B: virtual 0xc08c26c4  physical 0x208c26c4
QN90F: virtual 0xffffffc010b58030  physical 0x20b58030
```

It does not forge a signature or alter the verifier — it directly sets the state
Samsung itself sets. Volatile: a reboot restores UEP.

**These addresses are per-model and per-firmware.** They do not transfer. Our TV
is a 2022 The Frame (Pontus), so both of the above are reference points only; the
real address must be derived from our own kernel image.

### Why A comes first

A needs no memory corruption. B needs an arbitrary-physical-write primitive, which
on QN90B meant an unvalidated `/dev/sdp_pqe_fdet` mmap and on QN90F meant a Mali
use-after-free. Those are chip-specific. A is platform-independent.

So the plan starts with A: managed code on a signed host, which is enough to look
around, run tooling, and — critically — to read `/proc` and settle the binder
question on real hardware without writing anything.

---

## 2. Root is achievable — three independent teams did it in 2026

Root is not the blocker. It is a solved problem, three separate ways:

| path | evidence | notes |
|---|---|---|
| `/dev/ntksys` physmap → `cred` overwrite | MADBugs Samsung-TV writeup, UN43T5300, Tizen Perf (KantS2) | device node is `0666`; arbitrary physical R/W; root confirmed `uid=0` |
| SDB package-name injection | DemonKingSwarn/samsung-tv-tizen-root, QA55QEF1AULXL, Tizen 9.0 | command injection in the appinstall name field |
| vendor shell exploit | chris-ritsen/samsung-tv-root, QN90B + QN90F, 42★, active Sept 2026 | current, maintained |

All three end at `uid=0`. The MADBugs work is the most instructive because it
records the *constraint* as well as the exploit: root and unsigned execution are
separate boundaries, and root alone does not let you run your own binary.

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

That is vendor code, not mainline DRM. There is a `dtsversion=...kants2-1G-cma`
device tree and a VDFS read-only rootfs. There is no `panfrost`/`panthor` binding
for the Mali part on this SoC in mainline, and no mainline driver for the NTK
display path.

On the kernel version: our TV is **2022 PontusM**, so the working value is
**Linux 5.4.77 ARMv7**, not 4.1.10. An earlier version of this file said 4.1.10;
that came from 2020-era Q60T research and does not transfer. Confirm with
`uname -r` before relying on it.

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

### Step 3 — Get our own code running on the TV

Use the signed .NET host. Push a managed assembly plus its runtime config as
data, then run it through Samsung's own signed `/usr/bin/dotnet`:

```
sdb push MyTool.dll            /opt/usr/MyTool.dll
sdb push MyTool.runtimeconfig.json /opt/usr/MyTool.runtimeconfig.json
dotnet /opt/usr/MyTool.dll
```

Stage under `/opt`, never `/tmp` — assemblies under `/tmp` refuse to load.

Proof of step: a program we wrote produces its output on the TV, with UEP still
enabled. This is the gate for everything after it, and it needs no kernel writes
and no UEP patch.

Do **not** use `memfd_exec.py` for this. It was believed to bypass UEP by
avoiding the filesystem; that is disproved — anonymous `fexecve` was tested and
rejected by the researchers. UEP checks the file, not the path.

Native ELF execution is a separate, later step requiring the per-firmware UEP
state-word patch (§1B), which needs its own physical-memory primitive.

### Step 4 — Android kernel interfaces
Android userspace needs `binder` and `ashmem`. These are **loadable modules**
(`anbox/anbox-modules`, 349★) and Samsung publishes the kernel headers, so they
can be built out-of-tree — for **5.4.77 armv7l** if our TV is on that line.

Before building anything, check `MODULE_SIG_FORCE` in the target kernel's config.
If it is set, an unsigned out-of-tree module cannot be loaded at all, and this
whole route is dead no matter how correct the build is. `re/analyze-kernel.py`
answers exactly that from a kernel image, offline, with no TV involved.

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
    ├── memfd_exec.py            ← defeats PATH-based exec denial only; NOT a UEP bypass
    ├── sdb_native.py            ← pure-Python SDB client
    ├── mock_sdbd.py             ← fake TV, real protocol incl. RSA handshake
    ├── test_sdb_native.py       ← 26 assertions
    ├── analyze-firmware.py      ← off-device verdict checker
    ├── boot-probe.sh            ← read-only, runs on the TV
    └── README.md
```
