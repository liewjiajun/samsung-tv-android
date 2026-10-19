# 02 — Prior art: has anyone replaced a TV's OS?

Labels: VERIFIED (checkpointed a source this session) · INFERRED · UNKNOWN.
Note: general web search was badly degraded this session (DuckDuckGo served bot
challenges; the search API returned HTTP 402). Findings below rest on GitHub's
API, Wikipedia source, and primary project repos, which were reachable.

## The headline finding

**No OS replacement has ever been publicly achieved on a Samsung TV — Tizen-era
or before.** Not a partial port, not a fork, not a proof of concept. Across ~11
years and an active modding community, the ceiling was firmware *patching*, never
OS *replacement*.

Equally important: **the most successful TV-rooting project in existence never
produced an OS replacement either.** See LG below.

## Samsung: what was actually achieved

### SamyGO — the whole history of Samsung TV modding
VERIFIED (Wikipedia "SamyGO", LWN 2009, wiki.samygo.tv):
- Described as "a project that helps running custom firmware on smart TVs by
  Samsung" — a forum with rooting methods for various TV variants.
- Achievements: implemented **NFS and SMB file sharing**, playback from USB
  devices, and unlocked **unauthorised Wi-Fi dongles**.
- That is the ceiling. Feature unlocks on a patched stock firmware.

VERIFIED via GitHub API:
- `george-hopkins/samygo-patcher` — "SamyGO Samsung TV Firmware Patcher", 9 stars,
  last updated 2022-11-16. Patches firmware; does not replace it.
- `aenniw/SamyGo` — 5 stars, last updated 2018-08-07. Dormant.
- `card2000/OESamyGO` — "SamyGO OpenEmbedd 2.0", 1 star. The name suggests a Linux
  distro (OpenEmbedded) was contemplated. One star and no activity = did not
  become a working OS replacement.
- `harlequin/samygo-plugin-dvbapi`, `mad-ady/samygo-web`, `Tasshack/libSambilight`
  — all plugins, remote control, or Ambilight. None approach OS replacement.
- SamyGO targets **pre-Tizen** sets. Modern Tizen TVs are explicitly outside it.

### Tizen era (2015–2026)
Before late 2025, the public answer was: no root at all. Then two projects landed:
- `chris-ritsen/samsung-tv-root` (Unlicense, created 2026-08-17, 41 stars, active)
- `DemonKingSwarn/samsung-tv-tizen-root` (2026-10-18, 3 stars, demo-grade)

Both are **userspace privilege escalations only**. Neither touches the boot chain.
Their own docs are explicit that all changes are volatile and revert on reboot.
They are not steps toward OS replacement — they are a different kind of work.

## LG webOS — the best-funded attempt, and its ceiling

VERIFIED via GitHub API and repo README:
- `RootMyTV/RootMyTV.github.io` — **2,464 stars.** "A user-friendly exploit for
  rooting/jailbreaking LG webOS smart TVs."
- `webosbrew/webos-homebrew-channel` — **1,522 stars.** Homebrew store + root tooling.
- `throwaway96/dejavuln-autoroot` — 749 stars; `faultmanager-autoroot` — 470;
  `slopbro` — 288.
- `reprodev/LGTV-Firmware-Downgrade` — 151 stars; firmware downgrade *requires
  already having root*.

**What they achieved:** root, and a thriving homebrew ecosystem.
**What they did not achieve:** replacing webOS. The deliverable is a *homebrew app
store*, not an Android port. Even with years of work, thousands of stars, and a
far more open platform than Tizen, the community took the platform as given and
built apps for it.

**And it is now dead:** VERIFIED from RootMyTV's README — the vulnerabilities used
by v1 and v2 "have been patched by LG", patched since mid-2022, and firmware
downgrades are no longer possible without pre-existing root. A table lists the
patched-since version per model year (2016 → 3.4.2, 2021 → 6.3.0). Even the most
successful project in this space was pushed back to zero on the latest firmware.

**This is the single most informative data point in the whole survey.** Where
success was greatest, the prize was still homebrew — not a new OS.

## Amazon Fire TV — not an OS-replacement story

VERIFIED (Wikipedia "Amazon Fire TV"):
- Fire TV devices run **Fire OS, which is Android-derived (AOSP fork)**. "Android
  on a Fire TV" is therefore not an OS replacement at all — it is already Android.
- Fire TV Edition sets are TVs from other manufacturers shipping Fire OS under
  licence — i.e. the vendor chose the OS at manufacture.
- **New and important:** On 30 September 2025 Amazon announced the Fire TV Stick
  4K Select running **Vega OS**, a proprietary non-Android OS. Amazon is moving
  *away* from Android on TV hardware — the opposite direction.

## Hardware where OS replacement genuinely works

VERIFIED via GitHub API (community projects):
- `zubSero/StremioBox` — "Android 16 TV image for **Intel NUC**", with HEVC HDR10
  hardware decoding.
- `crucifix86/lineageos-tv-x86-n95-bringup` — "Bring-up docs + overlay configs to
  make **LineageOS-TV-x86** actually work."
- LineageOS on Raspberry Pi (KonstaKANG) and Android-x86 / Bliss OS generally.

**What these share — the generalisable principle:**

| Enabler | Present on these | Present on a Samsung TV |
|---|---|---|
| Standard/generic SoC with public BSP | ✅ x86, BCM2711 | ❌ proprietary Samsung silicon |
| Unlockable bootloader | ✅ | ❌ no unlock path known |
| Open or reverse-engineered GPU driver | ✅ Intel/AMD/V3D | ❌ proprietary Mali blob |
| Vendor-partition / Treble compliance (for GSI) | ✅ | ❌ TV doesn't ship Treble |
| Documented boot ROM / recovery | ✅ | ❌ |

Android lands on hardware that is *generic and documented*. A Samsung TV is the
inverse of every row.

## Project Treble / GSI — why you can't just flash one

INFERRED (standard Android platform knowledge; could not re-verify live this
session):
- A Generic System Image requires **Treble compliance**: a stable vendor interface,
  a separate `/vendor` partition, and VNDK. Android TV products do not ship this
  for third-party images.
- GSI also assumes the bootloader will load a system image it did not sign. A
  locked bootloader refuses.
- GSI is designed for *phones and tablets from participating OEMs*, not TVs.

## What I could NOT verify (honest gaps)

- Whether **Hisense/TCL/Philips** Android TV builds can be cross-flashed between
  brands. Search engines were captcha-blocked. UNKNOWN.
- Whether **NVIDIA Shield** has an unlockable bootloader. UNKNOWN (Shield is
  known in the community for *not* having a general unlock, but I could not
  confirm this session).
- Whether **Chromecast with Google TV** has ever been unlocked. UNKNOWN.
- Any single instance, anywhere, across any brand or era, of a smart TV being
  made to boot a different operating system than it shipped with. **None found.**
  I want to flag the absence clearly rather than overstate it: this is
  "no published instance found", not a mathematical proof.

## Their own claims about misinformation (useful signal)

Both primary projects and the tv-vibehack README independently warn about it. My
own searching surfaced the pattern constantly: pages titled along the lines of
"how to install Android on your Samsung TV" that actually instruct you to copy an
APK onto a USB stick, or to screen-mirror from a phone. **That is not installing
an OS — it cannot be, because a Samsung TV has no Android runtime and no way to
run an APK.** Treat all such pages as misinformation. Note also
`mundobytes.com`'s "Can I upgrade my Tizen OS to Android?" appearing top of
results with exactly this USB/APK content.

## Conclusion for this lane

Three independent lines of evidence converge:
1. Nobody has done it on Samsung, ever — across both the SamyGO era and Tizen.
2. The best-resourced TV-rooting project ever (LG, 2.4k stars, years) landed on
   homebrew apps, not an OS replacement, and has now been patched out.
3. Every successful OS-replacement case sits on generic, documented hardware with
   an unlockable bootloader — the opposite of a Samsung TV.

The absence is not from lack of trying. It is structural.
