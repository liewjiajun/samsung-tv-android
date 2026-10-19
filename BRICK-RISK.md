# BRICK RISK MAP — Samsung Tizen TV

Owner's concern (2026-10-19 18:19): *"I am worried about bricking my samsung tv so i
dont want to test on a real tv just yet."*

This document answers the concern with evidence, not reassurance. It states
what can brick the TV, what cannot, and what is recoverable.

---

## 1. The honest headline

**Nothing I have proposed so far can brick your TV.**

Every tool built to date is either read-only or app-level:

| Tool | What it does to the TV | Risk |
|---|---|---|
| `tizen-capability-probe.sh` | reads kernel config, mounts, devices | **zero** — read-only |
| `tizen-debloat.py` | `pkgcmd -D` (disable) | **very low** — reversible, no uninstall |
| `memfd_exec.py` / `memfd_run` | runs a payload in RAM | **zero** on the TV's storage — writes nothing |
| `sdb_native.py` | speaks the SDB protocol | **zero** — no writes |

None of these write to the bootloader, the kernel partition, or the eMMC.
A brick requires writing boot-critical storage. Nothing here does.

### One caveat I will not hide

"Writes nothing to storage" is not the same as "cannot destabilise the TV."

The root path documented in public research works by writing to **kernel memory**
(the `ntksys` physical-mapping primitive, used to overwrite the calling task's
credentials). Two consequences:

- A bug in that write can **crash** the TV. A crash means a power cycle, not a
  brick — recovered by pulling the plug.
- Running an arbitrary payload as root means that payload's bugs run at full
  privilege. A badly written tool at root could in principle corrupt storage.

So the accurate statement is: **none of my tools write to boot-critical storage,
but root-level work carries crash risk and demands care.** That is exactly why
the offline lane exists and why no root-level step runs on your TV before it is
proven on emulated armv7.

---

## 2. What actually bricks a Tizen TV

There is exactly one class of action that bricks these sets: **writing the boot
chain** — bootloader, kernel partition, or the eMMC regions the SoC reads before
any recovery code can run.

Concretely:
- flashing a modified firmware image
- writing U-Boot / bootloader partitions
- corrupting the eMMC boot area
- service-menu settings that prevent boot (a softer, usually recoverable case)

**Everything Android-related that I proposed avoids all four.** Tier 1
(runtime modification) operates in RAM and on a writable data partition — it
does not touch the boot chain.

---

## 3. Recovery reality — the uncomfortable finding

From the SamyGO wiki (the authoritative Samsung hacking reference), on
`UnBricking_TV_by_EEPROM_Reset`:

> "This wiki entry will not help resolve a TV bricked by **firmware flashing**."
> "This hacks just removes service menu settings and let you give another chance
> to fix settings."

This matters and I am not going to soften it:

- **EEPROM reset** recovers from *service-menu* mistakes. It does **not** recover
  from a bad firmware flash.
- So if a firmware flash goes wrong badly enough, the EEPROM trick will not save
  it.

Recovery options that do exist, in order of likelihood:

1. **Blind factory reset** (worth trying first, costs nothing):
   hold `EXIT` for 12–15 seconds, then press `Left`, then `Enter`.
   Works blind — you do not need the screen.
2. **Official USB firmware reinstall** — Samsung publishes firmware per model.
   Placed correctly on a FAT32 USB, many non-booting states recover. *This is
   the main real recovery path.*
3. **Service menu / factory reset** via the remote combination.
4. **Samsung service center / JTAG** — if the bootloader itself is corrupt.
   This is the bad case, and it is not a DIY fix.

Note what this implies: **recovery from a boot-chain brick is uncertain.** That
is precisely why Tier 3 (reflash) stays closed, and why the safe play is to
prove everything off-device first.

---

## 4. Risk by tier

| Tier | What it is | Brick risk | Reversible? | Status |
|---|---|---|---|---|
| **0** | Inventory + capability probe (read-only) | none | n/a | ready |
| **2** | Signed `.tpk` app in Developer Mode | very low | yes — uninstall | ready |
| **1** | Runtime modification, Tizen keeps panel | low | yes — reverts on reboot / disable overlay | **untested** |
| **3** | Reflash the OS | **high** | no | **closed** |

Tier 1 is the interesting one, and its risk profile is favourable for a specific
reason: the Android userspace runs *inside a container beside Tizen*, and
persistence is achieved through **runtime overlays** (bind mounts / overlayfs
layered from a writable partition). A runtime overlay is gone the moment you
reboot without it. That is a very different risk class from writing flash.

**Developer Mode itself is reversible.** It is a setting, not a firmware change.
Turning it off returns the TV to normal.

---

## 5. The rule this produces

> **No write to the TV's boot chain. Ever. Under any circumstance.**

And the working method:

> **Prove it off-device, then apply it minimally on-device.**

Which is exactly what the offline lane (`vm/`) exists for. Emulate armv7 Linux,
run the payloads there, and only touch the TV with a step that is already proven
and already known to be reversible.

---

## 6. Offline lane (built to remove the need for early TV testing)

- `vm/vmlinuz`, `vm/initrd.gz` — a real **armv7** Debian kernel + initramfs,
  matching the TV's 32-bit ARM architecture
- `qemu-system-arm -M virt -cpu cortex-a15` — boots that kernel locally
- Purpose: run and debug the Android-container work on an emulated armv7 Linux,
  so the TV is only involved once a step is proven

This is the substitute for "test on a real TV." Same architecture, no risk.

---

## 7. What I will not do without an explicit decision from you

- Write anything to a boot partition, bootloader, or eMMC boot area
- Flash any firmware image, modified or otherwise
- Run any tool on the TV that I have not first run on the emulated armv7 lane
- Proceed past a step whose failure mode I cannot describe precisely

If a step proves genuinely risky and unavoidable, I will say so plainly with the
recovery options, and let you decide — not bury it in a paragraph.
