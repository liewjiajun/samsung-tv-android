# 01 — Hardware and boot chain

Labels: VERIFIED (read the source myself this session) · INFERRED · UNKNOWN.
Primary evidence is the two public root projects' own documentation, which is the
strongest material available — one author runs it daily on his own TVs.

## 1. SoC and architecture by generation

VERIFIED, from `chris-ritsen/samsung-tv-root` (README "Tested TVs" table):

| Model | Year | Tizen | Kernel | CPU arch | GPU |
|---|---|---|---|---|---|
| QN55QN90BAFXZA | 2022 | 6.5 | Linux 5.4.77 | **ARMv7 (32-bit)** | UNKNOWN |
| QN75QN90FAFXZA | 2026 | 9.0 | Linux 5.4.261 | **AArch64 (64-bit)** | Mali-G510 r48p0 |
| QA55QN90FAUXEG | 2026 | 9.0 | Linux 5.4.261 | **AArch64 (64-bit)** | Mali-G510 r48p0 |

VERIFIED, from `DemonKingSwarn/samsung-tv-tizen-root`:
| QA55QEF1AULXL | 2026 | 9.0.0 | UNKNOWN | SDB reports `cpu_arch:armv7, core_abi:arm_32` | UNKNOWN |
Platform codename **`rosel`**.

### Resolving the armv7-vs-AArch64 contradiction — the single most useful finding

These two facts look contradictory and are not. VERIFIED, from the QN90F
reproduction notes in the primary source:

> "The QN90F kernel is AArch64, but the verified Tizen userspace and installed
> native toolchain are 32-bit ARM EABI5."

So on a 2026 Samsung TV:
- The **kernel is 64-bit AArch64**.
- The **userspace is 32-bit** (ARM EABI5), which is what makes the SDB
  capability string report `armv32`. It describes the userspace build, not the
  silicon.
- Native binaries must be built 32-bit ARM EABI5, linked against the TV's
  `/lib/ld-linux.so.3`.

**Why this matters:** the silicon is 64-bit. That removes the "32-bit only, stuck
on ancient Android" objection. It does not by itself make Android possible —
see the boot chain below.

SoC part numbers are UNKNOWN for both generations. The primary source gives
platform/codename and GPU only. Samsung does not publish TV SoC datasheets. Other
screen sizes and variants are explicitly `compatible-untested` or `incompatible`.

## 2. Boot chain — where this project actually dies

VERIFIED facts from the primary source:

**a) Samsung UEP blocks unsigned native execution — even as root.**
> "Root and unsigned execution are separate boundaries. Both TVs still apply
> Samsung's kernel UEP/SFD check to unsigned ELF files even from UID 0."

UEP (unsigned executable prevention) is a kernel-side `execve` check. Getting
`uid=0` does **not** let you run your own binary. The project disables it by
finding the kernel state word Samsung's own handler clears:

| Model | Virtual | Physical |
|---|---|---|
| QN90B | 0xc08c26c4 | 0x208c26c4 |
| QN90F | 0xffffffc010b58030 | 0x20b58030 |

**b) Every meaningful change is volatile.**
> "A reboot destroys the root processes, credential changes, reclaimed
> page-table state, and UEP change."

The "persistent-looking" behaviour is a **host-side controller** re-running the
exploit after each boot. No boot service is installed. Nothing in the boot chain
is modified.

**c) The root filesystem is read-only.**
VERIFIED from the DemonKingSwarn reproduction: `/` and `/prd` are read-only, and
no writable systemd unit directory exists — its authors state on-device boot
persistence is "provably impossible" on that target.

**d) But there IS a writable persistent path for files.** — IMPORTANT
VERIFIED, from the QN90F reproduction notes:
> "The files under `/opt/<package>` survive a normal reboot. Authorization does
> not: UEP returns to its stock state."

So the filesystem does have writable, persistent locations. What does not persist
is *authorisation to execute*. That distinction defines the shape of any attempt:
you can leave files on the TV, but you cannot leave a boot-time hook.

**e) Firmware keys are recoverable.** The project includes SWU firmware-key
extraction for both models. Consequence: firmware images can be decrypted and
examined — but signing is a separate matter, and no signing bypass is claimed.

**f) The boot chain itself is untouched.** No bootloader unlock, no secure-boot
bypass, no vendor-signing break is claimed anywhere in either project. Both work
strictly *after* the OS has booted, from userspace (via `dotnet` managed code),
escalating through a GPU/memory bug.

### Why "replace the OS" is a different problem entirely
Replacing an OS means the bootloader must load a different kernel/rootfs.
Everything above happens *after* boot and is destroyed *by* boot. Neither project
contributes anything toward the boot path. UNKNOWN: whether the bootloader on any
Tizen TV has ever been unlocked. No evidence found that it has — for any Tizen TV,
any year. That absence over ~11 years of an active modding scene is itself the
finding.

## 3. GPU

VERIFIED: Mali-G510 r48p0, API 1.14 on 2026 QN90F-class hardware.
Driver is Samsung's proprietary blob integrated with Tizen's display stack.
UNKNOWN: whether a mainline Panfrost/PanVK driver could ever bind to this
vendor-kernel Mali. Not demonstrated for any Tizen TV.

## 4. Android TV hardware requirements (for comparison)
Android TV / Google TV reference requirements are documented by Google for
licensing. VERIFIED research note from lane 03: Google's 2026-era guidance pushes
Android TV to 64-bit, and apps targeting TV must ship 64-bit native libraries.
INFERRED: TVs have roughly 1.5–3 GB RAM and small eMMC. RAM is likely adequate;
usable writable storage for an Android image is not, absent USB.

## 5. Summary of the block

| Layer | State | Evidence |
|---|---|---|
| Silicon 64-bit capable (2026) | ✅ VERIFIED | QN90F AArch64 kernel |
| Userspace 32-bit | ✅ VERIFIED | EABI5 toolchain requirement |
| Root achievable (2022–2026) | ✅ VERIFIED | two public projects, one live-daily |
| Unsigned native exec | ❌ blocked by UEP | VERIFIED |
| Persistent file placement | ✅ `/opt` survives reboot | VERIFIED |
| Persistent boot hook | ❌ none | VERIFIED / provably impossible on one target |
| Bootloader unlock | ❌ no evidence, ever | UNKNOWN-but-unprecedented |
| Custom kernel/OS booted | ❌ no evidence, ever | UNKNOWN-but-unprecedented |
| GPU usable from non-Tizen | ❌ proprietary blob | INFERRED, high confidence |
