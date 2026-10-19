# Tizen TV → Android: a scoped investigation

Can a Samsung Tizen TV be made to run Android applications?

**Short answer: not by replacing the OS. Possibly by modifying the running one.**
This repo contains the tooling, the research, and — importantly — the limits of
what has actually been tested.

Everything here is designed to be verifiable by you, on your own hardware.

---

## The three tiers

Much of the confusion in this problem comes from treating "get Android on a
Samsung TV" as one question. It is three, and they have very different answers.

| Tier | Approach | Status |
|---|---|---|
| **3** | **Replace** the OS — flash a modified Tizen or Android | **Closed.** Per-section RSA signatures in the boot chain; a modified image will not boot. Also loses the panel driver, which only Samsung's NTK stack provides. |
| **1** | **Modify** the *running* system — Tizen keeps the display, Android runs beside it | **Untested.** Not refuted. The live question. |
| **2** | Signed `.tpk` app in Developer Mode | Works today. Sandboxed, no root. |

Tier 3 being closed does **not** close Tiers 1 and 2. Tier 3 dies partly on
*display*: replacing the OS means supplying a display driver, and the panel is
reachable only through Samsung's proprietary stack. Tier 1 never faces that,
because **Tizen still owns the display** — Android draws into a buffer and Tizen
presents it.

Precedents for exactly this shape:

- **webOS homebrew** — signed read-only squashfs rootfs, modified at runtime via
  `mount --bind` + overlayfs layered from a writable partition.
- **ChromeOS ARC** — runs Play Store apps on non-Android Linux. A container, not a
  hypervisor.

Note on Play Store: even with a working runtime, Google does not certify Tizen
devices, so there is no GMS. The deliverable is **Android apps on the TV**, not
the Play Store.

---

## The decisive question

The one thing that decides whether Tier 1 is possible is whether *this specific*
TV's kernel can support Android userspace at all — chiefly **binder** (Android's
IPC) and **ashmem** (shared memory).

`toolkit/tizen-capability-probe.sh` measures this. It is **read-only**.

```bash
sh toolkit/tizen-capability-probe.sh          # human-readable
sh toolkit/tizen-capability-probe.sh --json   # machine-readable
```

Run it before any other work on a set. It reports which tier is open and what the
next step would be.

**Why it reads the live system instead of a config file:** on a hardened device
`/proc/config.gz` and `/boot/config-*` do not exist. An earlier version of this
probe reported `UNKNOWN` for every symbol in exactly that situation — output that
looks identical to a probe that found nothing. It now falls back to observing the
live system (`/dev/binder`, `/proc/self/ns/*`, `/sys/fs/cgroup`), because
`UNKNOWN` is useless for a go/no-go decision.

---

## What's here

| Path | What it does | Needs a TV? |
|---|---|---|
| `toolkit/tizen-capability-probe.sh` | Read-only probe: which tier is open on this set | no (runs in the VM) |
| `toolkit/tizen-debloat.py` | Disables (never uninstalls) unwanted packages | yes, Developer Mode |
| `toolkit/sdb_native.py` | Native SDB client — pure Python, no Tizen Studio | yes, to be useful |
| `toolkit/memfd_exec.py` | Runs a payload from memory (defeats path-based denial, not UEP) | yes |
| `toolkit/analyze-firmware.py` | Read-only firmware container analyser | **no** |
| `toolkit/boot-probe.sh` | Read-only boot-chain probe | yes, any shell |
| `toolkit/mock_sdbd.py` | Fake TV speaking the real wire protocol | no |
| `toolkit/test_*.py` | Test suites (26 + 53 assertions) | no |
| `vm/tvvm.sh` | Offline emulated armv7 lane | no |

---

## Testing without hardware

`vm/tvvm.sh` builds an emulated **32-bit ARM** Linux matching the TV's
architecture, so tooling is exercised off-device:

```bash
cd vm && ./tvvm.sh fetch build run
```

The probe is baked into the initramfs and runs automatically at boot.

**What this validates:** shell portability, `/proc` parsing, probe logic, and
behaviour when kernel config files are absent.

**What it cannot validate:** NTK display, SMACK policy, or any Samsung-specific
behaviour. A green run here is **not** a verdict about any real TV.

---

## Two-minute check (no TV, no emulator)

Download the official firmware for your exact model from Samsung's support site:

```bash
python3 toolkit/analyze-firmware.py /path/to/upgrade.msd
```

If it reports **per-item signature descriptors**, Tier 3 is confirmed closed for
your model. This is the real test, and it runs entirely offline.

---

## The boot-chain rule

> **No write to the boot chain. Ever.**

A brick requires writing boot-critical storage — the bootloader, kernel partition,
or eMMC boot area. None of the tooling here does that. See `BRICK-RISK.md` for the
full risk map and the recovery reality.

Worth stating plainly, because reassurance is cheap: "writes nothing to storage"
is **not** the same as "cannot destabilise the TV." The documented root path in
public research works by writing to *kernel memory*. A bug there can **crash** the
set — a power cycle, not a brick, but not nothing. Root-level work carries crash
risk and demands care.

---

## Status and blockers

**Untested on real hardware.** Every claim about a specific TV is inference until
the probe runs on it. The tools are proven against a mock and against emulated
armv7; that is not the same thing.

**Known unknowns:**

- Whether consumer Tizen TVs expose binder, and whether it can be added if absent.
- The exact model in scope (the probe needs it).
- Whether the display path holds once Android is actually rendering.

**Known facts from firmware analysis:** Tizen TV kernels are Linux 4.1.10 (ARM)
with a Tizen 5.4 line on newer parts. The firmware container's AES key has not
been rotated since 2021 — a publicly known passphrase still decrypts current
images. That looks like an open door and is not: the encryption was never the
obstacle, the signatures are.

---

## Licence

MIT — see `LICENSE`.
