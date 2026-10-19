# 04 — The decisive experiment, already run by someone else

Status: **this is the answer to the question the project was built to answer.**

## What I set out to determine

The entire feasibility question reduced to one unknown: **does the boot chain
verify what it loads?** Root is not the obstacle. Running *my* code at boot is.

I proposed a read-only probe (`toolkit/boot-probe.sh`) to test it on a TV we owned.

## What I found instead

Someone has already done better than my probe: they took an official firmware
image for a real 2026 Samsung TV, decrypted it, and published a static analysis.

**Source:** `sebastianspicker/tiz0wn` — "evidence-first Samsung Tizen TV security
research," assessed against a **personally-owned Samsung GQ55Q60TGUXZG running
`T-NKLDEUC-2743.0`**, pushed 2026-10-04. One star, so it is not famous — but it is
first-hand, firmware-specific, and self-documented.

**Document:** `docs/firmware-analysis.md` (40 KiB), plus
`docs/Samsung_Q60T_Debloating_Research_2026-09-25.md` (79 KiB).

### The finding that closes the project

> "Every section carries a per-item `OURSAValidationDesc` with a public-key id
> (`0x19fc36c9`), so authenticity is checked independently of the (broken)
> encryption — reading the firmware does not let you forge a bootable modified
> image."

And, separating the three questions cleanly (§11.3):

> "**Can the contents be read? Can a modified package be authenticated? Will the
> device boot and operate correctly after accepting it?** These are different
> problems. Decrypting or re-encrypting a firmware payload does not supply
> Samsung's signing authority or establish a supported route to flash it."

This is precisely the check my `boot-probe.sh` was written to detect, answered
from the image itself rather than from the device. **The boot chain verifies.
The OS-replacement route is closed.**

### The one genuinely surprising detail

> "The firmware container's AES key has **not been rotated since 2021**: a
> five-year-old, publicly known passphrase still decrypts the current 2026 image."

So *reading* current Samsung firmware is trivial — the container encryption is
broken by age and the key is public. This is a confidentiality failure, not a
trust failure. **It does not help us**, because the encryption was never what
stopped us. The per-item signatures are.

This distinction is the single most important thing in the project: an
apparently "broken" firmware container looks like an open door, and is not.

## Root: achievable, and still useless for this goal

The same work demonstrates UID 0 on the assessed set — via a command injection in
the Remote PC feature's CIFS helper, through the SMB password field. They are
careful about what it does and does not establish, and so am I:

> "This is a root-command proof, not persistence, a root shell, a firmware
> modification, or a claim about firmware versions other than the exact assessed
> build."

**This is worth knowing and it does not change the verdict.** Root gives you a
process running as UID 0 on a booted TV. It does not give you a bootloader that
loads your kernel. Those remain separate problems — exactly as the QN90B/QN90F
project says for the RAM-patch route.

The same team also confirmed the historical physical-memory root primitive
(`sdp_mem`, later `sdp_hwmem`) is **hardened** on the current build — a
whitelist-containment check plus an explicit kernel-region-intersection reject,
confirmed at disassembly level, not just by strings. The old trick of mapping
kernel physical memory to patch credentials is closed.

## Their explicit statement on OS replacement (§11.6)

> "**Native applications and firmware replacement are different projects.**
> An alternative application can use the existing system's display and playback
> infrastructure. Replacing the operating system would additionally require a
> usable boot path and working support for the panel, graphics, video decoding,
> sound, input, power management and any other retained functions.
> No tested custom-OS image or full replacement procedure for this exact
> configuration was established."

Independent arrival at the same conclusion this project reached from prior art,
now on a specific 2026 firmware: alternative *application* — yes. Replacement
*OS* — no.

## What this changes about my earlier verdict

| Claim | Before | Now |
|---|---|---|
| Boot chain verifies the kernel/rootfs | inference from absence | **confirmed in a real 2026 image** |
| Root on Tizen | only via model-specific RAM patch | **also a documented UID-0 route on Q60T** |
| Firmware container encryption | assumed meaningful protection | **broken; key public since 2021; irrelevant** |
| sdp_mem phys-memory root | historical, status unknown | **confirmed hardened at driver level** |
| Verdict | high confidence, one experiment open | **experiment done; route closed** |

## Hardware differences worth noting (do not conflate)

The two documented TVs differ materially, so results are per-model:

| | Q60T (tiz0wn) | QN90B / QN90F (root project) |
|---|---|---|
| Kernel | Linux 4.1.10 (ARM) | 5.4.77 ARMv7 / 5.4.261 AArch64 |
| GPU | Mali-G51 Bifrost r11p0 | Mali-G510 (QN90F) |
| `/dev/mali0` | mode 0666, SMACK `*` | — |
| Root route | Remote PC/CIFS injection | kernel RAM state patch |
| Root persistence | none | none (volatile, lost on reboot) |

## Caveats on this source

- One star, self-described AI-co-authored in places. Treated as a **lead**, then
  read directly. The claims here are the ones stated as first-hand and reproduced,
  and the firmware findings are self-consistent with the published decryptor's
  behaviour (`bugficks/msddecrypt`, which shows the same `MSDU11` magic,
  per-partition salts, CRC32s, and `OURSAValidationDesc` records).
- **Independent corroboration:** `msddecrypt`'s public output independently shows
  `SecureDowngradeDesc` / `OURSAValidationDesc` handling in the same container
  format, from a different author, years earlier. Two unrelated sources describe
  the same signing structure. That is why I treat the signature finding as solid.

## Bottom line

Nobody needs to run my probe on JJ's TV. The boot chain verifies, and the
mechanism is not version-specific — it is how the container is built. The
remaining value of the toolkit is that it lets us **verify this on JJ's exact
model** rather than trust anyone, mine or theirs.
