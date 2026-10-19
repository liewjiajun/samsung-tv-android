# 00 — Primary source notes: chris-ritsen/samsung-tv-root

Read directly from the repo (default branch `master`) on 2026-10-19. This is the
most credible public source: the author built it for his own two TVs, uses it
daily, and it is Unlicense.

## Tested hardware — THE key table

| Profile | Exact model | Firmware | Internal build | Platform |
|---|---|---|---|---|
| `qn90b` | QN55QN90BAFXZA | T-PTMAKUC-1602.3 | T-PTMAKUC-REL-202310071804 | Tizen 6.5, **Linux 5.4.77, ARMv7** |
| `qn90f` | QN75QN90FAFXZA | 1203.0 | T-RSMFAKUC-0090-REL-202512092052 | Tizen 9.0, **Linux 5.4.261, AArch64, Mali-G510 r48p0** |
| `qn90f` | QA55QN90FAUXEG | 1301.0 | T-RSMFUABC-0090-REL-202607141954 | Tizen 9.0, **Linux 5.4.261, AArch64, Mali-G510 r48p0** |

**Significance:** 2022 silicon (QN90B) is 32-bit armv7. 2026 silicon (QN90F) is
**64-bit AArch64** with a Mali-G510. So the architecture story changed between
generations — this is good news for any Android ambition, because Android TV
today is arm64. The DemonKingSwarn 2026 set reported `cpu_arch:armv7,
core_abi:arm_32` in its SDB capability string, but that appears to describe the
**Tizen userspace build/ABI**, not necessarily the silicon — worth resolving.

## Exploits included (three routes)

- `SVE-2025-50109` — SDB package-name injection → initial `uid=901(sdk)` foothold.
  Public advisory. Needs Developer Mode on.
- QN90B: `/dev/sdp_pqe_fdet` physical-memory exploit.
- QN90F: Mali-G510 r48p0 exploit based on **CVE-2025-0072**.
- Plus a **model-independent "SDK archive-launcher" root route**, live-tested on
  both TVs. This is the interesting one for porting to other models.

## What the author actually achieves

- Interactive root shells + authenticated root command execution (HMAC channel,
  controller accepts only `uid==euid==gid==egid==0`, full capability mask).
- **UEP status and "volatile disable" controls for unsigned native execution.**
  ← BIG. UEP = unsigned executable prevention. With it disabled, unsigned native
  binaries can run this boot. This is the closest thing to "a foothold to run
  arbitrary code" the project exposes.
- Remote input observation/suppression/remapping; HDMI source selection;
  local dimming; PC/Game mode; Picture Off; speaker volume; foreground-app
  events; 960x540 HDMI capture; transparent compositor overlays; screenshots.
- SWU firmware-key extraction for both models.

## Constraints stated by the author

- **Root and UEP changes are VOLATILE.** Reboot reverts them. "It does not
  install a TV-side boot service." A host-side controller reacquires root after
  each TV boot (~10s per the other writeup).
  → Therefore persistent boot-time modification is NOT demonstrated. This is
  the central obstacle to any "replace the OS" plan.
- Tested only on the listed models. Other sizes/variants are `compatible-untested`
  or `incompatible`, decided by a preflight fingerprint check.
- Needs Samsung Tizen Studio's proprietary `sdb` (not redistributed) and, for
  payloads, the .NET 6 SDK.
- Enabling Developer Mode needs a Samsung `BN59-01199F` full-button IR remote
  (type `12345` on App Settings).
- Never tested by any third party as far as I can find.

## Contrast with DemonKingSwarn/samsung-tv-tizen-root (2026-10-18, 1 day old)

- Its own contribution: same public `SVE-2025-50109` foothold, escalated via the
  **archive-root** method it credits to this repo. So the two projects agree.
- Target: QA55QEF1AULXL, Tizen 9.0.0, platform `rosel`. Removed 84 packages,
  511 → 427.
- Reports **persistence impossible on-device**: `/` and `/prd` read-only, no
  writable systemd unit directory. Agrees with the volatile finding above.

## Open questions this raises

1. Is the QN90F's AArch64 + Mali-G510 representative of 2026 Samsung TVs
   broadly, or specific to the QN90F tier? (lane 01)
2. Does the Mali-G510 have usable open-source driver support (Panfrost/PanVK)?
   If so the usual "proprietary GPU blocks Android" argument weakens. (lane 01/03)
3. Is `binder` present or buildable in Samsung's 5.4.261 kernel, and is module
   signing enforced? Settle with one command on a rooted unit:
   `zcat /proc/config.gz | grep -E 'BINDER|ASHMEM|MODULE_SIG|NAMESPACES|CGROUPS|BLK_DEV_LOOP|IPV6'`
4. Is there ANY writable, non-signature-checked partition that survives boot?
   The persistent-modification question rests on this.
5. Has anyone attacked the boot chain itself (U-Boot / vendor bootloader) rather
   than the OS? (lane 01/02)
