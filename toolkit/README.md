# toolkit — Samsung Tizen TV: verify the verdict yourself

Built 2026-10-19 during the "replace Tizen with Android" investigation.

## Read this first: three tiers, not one verdict

An earlier version of this file said flatly "the verdict is no." That was wrong,
and wrong in a specific way worth naming: it took the result for **one** approach
and presented it as the answer for **all** of them.

| Tier | Approach | Status |
|---|---|---|
| **3** | Reflash the OS (replace Tizen) | **CLOSED.** The boot chain cryptographically verifies what it loads, so a modified kernel or rootfs will not boot. This part is firm. |
| **1** | Modify the *running* system (Tizen keeps the panel; Android renders into it) | **Untested.** Not refuted. This is the live question. |
| **2** | Signed `.tpk` app in Developer Mode | Works today. No root. Limited reach. |

Tier 3 being closed does **not** close Tiers 1 and 2. Those are different problems,
and the difference matters: if Tizen keeps driving the display, Android never needs
a display driver of its own — which dissolves the objection that killed Tier 3.
Precedents: webOS homebrew (runtime overlays on signed read-only squashfs) and
ChromeOS ARC (Play Store apps on non-Android Linux).

See `../BRICK-RISK.md` for what can and cannot brick the set, and what recovery
exists. Short version: **nothing here writes to the boot chain.**

---

## What's here

| File | What it does | Needs hardware? |
|---|---|---|
| `sdb_native.py` | Native SDB client — pure Python, no Tizen Studio | a TV, to be useful |
| `analyze-firmware.py` | Read-only firmware container analyser | **no** |
| `tizen-capability-probe.sh` | Read-only probe: decides which tier is open on *this* set | a TV (or the armv7 VM) |
| `tizen-debloat.py` | Disables (never uninstalls) unwanted packages | a TV in Developer Mode |
| `memfd_exec.py` | Runs an unsigned armv7 payload from memory | a TV |
| `boot-probe.sh` | Read-only boot-chain probe, runs on the TV | a TV with any shell |
| `mock_sdbd.py` | Fake TV speaking the real wire protocol | no |
| `test_sdb_native.py` | 26-test suite against the mock | no |
| `test_tizen_debloat.py` | 53-test suite for the debloat tool | no |

---

## The decisive question, and how to answer it

The one thing that decides whether Tier 1 is possible is whether this specific
TV's kernel can support Android userspace at all — chiefly **binder**. That is
what `tizen-capability-probe.sh` measures, and it is read-only:

```bash
sh tizen-capability-probe.sh          # human-readable
sh tizen-capability-probe.sh --json   # machine-readable
```

Run this **before** any other work on a set. It reports which tier is open and
what the next step would be.

A note on why it reads the system instead of a config file: on a hardened device
`/proc/config.gz` and `/boot/config-*` do not exist. An earlier version of this
probe reported `UNKNOWN` for every symbol in exactly that situation — which looks
identical to a probe that found nothing. It now falls back to observing the live
system (`/dev/binder`, `/proc/self/ns/*`, `/sys/fs/cgroup`), because UNKNOWN is
useless for a go/no-go decision.

---

## Testing without a TV

`../vm/tvvm.sh` builds an emulated **armv7** Linux matching the TV's architecture,
so tooling is exercised off-device:

```bash
cd ../vm && ./tvvm.sh fetch build run
```

What this validates: shell portability, `/proc` parsing, the probe's logic, and
its behaviour when kernel config files are absent. What it **cannot** validate:
NTK display, SMACK policy, or any Samsung-specific behaviour. A green run here is
not a verdict about the TV.

---

## The two-minute version (no TV required)

Download the official firmware for your exact model from Samsung's support site,
then:

```bash
python3 analyze-firmware.py /path/to/upgrade.msd
```

If it reports **per-item signature descriptors**, the answer is confirmed for your
model: repacking the firmware cannot produce a bootable modified image.

This is the real test. It runs here, offline, on the container itself.

---

## Why a custom SDB client

Samsung's `sdb` ships only inside Tizen Studio — a large proprietary download that
is awkward on Linux and ARM. The Steam Deck is both. So the wire protocol was
reimplemented instead.

Protocol (all little-endian): a 24-byte header of six `uint32`
(`command, arg0, arg1, data_length, data_checksum, magic`), where
`magic = command ^ 0xFFFFFFFF` and `data_checksum` is the byte sum mod 2³².

Commands: `CNXN` handshake, `AUTH` (token/signature/publickey), `OPEN` a service
channel, `OKAY` ack, `WRTE` data, `CLSE` close.

Cross-checked against `PatrickSt1991/tizen-sdb` (C# reference) and the
`haageduard/samsung_sdb_py` Python interface. The RSA key blob is Android's
`RSAPublicKey` layout: `n0sizeWords, n0inv, modulus[LE], rr[LE], exponent`.

### Usage

```bash
# identify any TV that answers on 26101
python3 sdb_native.py 192.168.1.10

# what does this TV's sdbd actually accept? (read-only, non-existent ids)
python3 sdb_native.py 192.168.1.10 --verbs

# raw capability dump
python3 sdb_native.py 192.168.1.10 --json
```

**Important:** sdbd is not a shell. It carries a fixed verb vocabulary and an
unknown verb returns empty or the literal word `closed`. `--verbs` maps which
verbs exist on your model, which is the honest way to learn what the command
channel can do.

### First-run note

The client generates a 2048-bit RSA key at
`~/.config/sdb-native/id_sdb` on first connect, and signs the TV's challenge
token. If your TV prompts to allow the connection, accept it — that prompt is the
authorisation step.

---

## The boot probe

`sdb_probe.sh` … rather, `boot-probe.sh` runs **on the TV** and is read-only. It
reports boot arguments, secure-boot markers, kernel lockdown state, module-signing
enforcement, the partition map, what is mounted read-write, and whether Android's
kernel requirements (binder, DRM/KMS, loop) could even be met.

The single most informative line:

```bash
ls -l /dev/dri/
```

No `/dev/dri` means no standard Kernel Mode Setting — which alone closes the
"run Android's graphics stack here" lane, independently of the boot chain.

Interpretation guide is printed at the end of the script.

---

## Testing

```bash
python3 test_sdb_native.py
```

Runs 26 assertions against `mock_sdbd.py`, which speaks the real protocol
(including the secure `AUTH` → RSA-signature handshake). No hardware needed.

**Two real bugs were found this way**, both silent connection resets that would
have looked like "the TV rejected us":

1. The client sent a redundant `CLSE` for an already-closed channel.
2. The mock read the `AUTH` reply before consuming the client's opening `CNXN`.

This is why the harness exists. Protocol code that "looks right" is not evidence.

The firmware analyser has its own checks, including a **negative control**: fed
random bytes it must report *inconclusive*, never a finding. A tool that finds
signatures in noise is worse than no tool.

---

## What I deliberately did not build

The public research documents a command-injection route to UID 0 (via the Remote
PC feature's CIFS helper) and Mali GPU drivers with known unfixed CVEs. I read
that work to answer the feasibility question and **did not reproduce the exploit
chains**, because:

1. They do not change the answer. Root is a process on a booted TV; the boot
   chain is a separate problem that remains closed either way.
2. The goal was a decision — can this be done — not a working exploit.

Read-only diagnostics are here. Weaponisation is not.

---

## Provenance and honesty

- `analyze-firmware.py` was tested against a **synthetic** container this repo
  built, not a real Samsung image. Real images may vary. A parse failure means
  nothing — check the container was actually decrypted first.
- The decisive boot-chain evidence comes from `sebastianspicker/tiz0wn`, a
  one-star third-party repo. It was treated as a lead and then read directly; its
  signature findings are corroborated by `bugficks/msddecrypt`'s independent
  container behaviour. See `../research/04-firmware-verification.md`.
- Do not point any of this at hardware you do not own.
