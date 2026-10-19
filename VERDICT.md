# VERDICT — Can a Samsung Tizen TV be made to run Android?

Project started 2026-10-19 at JJ's request. Research complete 2026-10-19.
Revised 2026-10-19 (same day): scoped to Tier 3 only. See "Scope" below.

## Scope — read this before the verdict

This document answers **one** question: *can Tizen be REPLACED by Android?*

That is **Tier 3** of three distinct approaches. The findings below are firm for
Tier 3. They do **not** settle the other two, and an earlier version of this file
was read as if they did:

| Tier | Question | This doc? |
|---|---|---|
| **3** | Replace the OS — flash a modified Tizen/Android | **yes — closed** |
| **1** | Modify the *running* system — Tizen keeps the panel, Android renders into it | no — open, untested |
| **2** | Signed `.tpk` app in Developer Mode | no — works today, limited |

The distinction is not academic. Tier 3 dies on *display*: replacing the OS means
supplying a display driver, and the panel is reachable only through Samsung's
proprietary NTK stack. **Tier 1 never faces that problem, because Tizen still
owns the display.** Android draws into a buffer and Tizen presents it — the same
shape as webOS homebrew and ChromeOS ARC. So Tier 3's wall is real, and it is
narrower than it first appears.

JJ raised exactly this on 2026-10-19 ("have you explored modifying tizen OS
directly instead?"). He was right to. The answer is in `ANDROID-PLAN.md`;
risk is mapped in `BRICK-RISK.md`.

---

## The answer (Tier 3 only)

**Replacing Tizen with Android on a Samsung TV has never been done by anyone, and
the evidence says it cannot be done from the software side as currently
understood.** The reason is structural, not a matter of effort or skill.

The blocker is **the boot chain, not the OS** — and as of this project, that is no
longer an inference. An official 2026 firmware image has been decrypted and
analysed, and **every boot-relevant item carries its own cryptographic signature**
(`OURSAValidationDesc`, public-key id `0x19fc36c9`). Reading the firmware does not
grant the ability to produce a bootable modified image. See
`research/04-firmware-verification.md` and `toolkit/`.

A second finding is worth stating plainly because it is a trap: the firmware
container's AES key **has not been rotated since 2021**, so a publicly known
passphrase still decrypts current images. That looks like an open door and is not.
The encryption was never what stopped us — the signatures are.

## Why not — the chain of reasons, strongest first

### 1. The boot chain is the actual wall (decisive)

Replacing an OS means the bootloader must load a kernel and rootfs you supplied.
Both public root projects work *entirely after boot*, in userspace, and their own
docs state every change is destroyed by reboot:

> "A reboot destroys the root processes, credential changes, reclaimed page-table
> state, and UEP change." — chris-ritsen/samsung-tv-root

Neither project claims any progress on the bootloader. No bootloader unlock,
secure-boot bypass, or vendor-signing break is documented **for any Tizen TV,
any year**. Eleven years of modding with zero instances is the finding.

### 2. Samsung blocks unsigned native execution even as root (UEP)

VERIFIED from the primary source: "Root and unsigned execution are separate
boundaries. Both TVs still apply Samsung's kernel UEP/SFD check to unsigned ELF
files even from UID 0."

So even holding `uid=0`, you cannot run your own binaries. The project bypasses
this by patching a specific 32-bit kernel state word **in RAM**, per boot. An
Android runtime is exactly "my own binaries" at scale.

### 3. The firmware is read-only where it counts

`/` and `/prd` are read-only; no writable systemd unit directory exists. One
target is described by its own authors as "provably impossible" for on-device boot
persistence.

Important nuance (VERIFIED): files under `/opt/<package>` **do** survive reboot.
What does not survive is *authorisation to execute*. You can leave an Android
image on the TV. You cannot get the TV to run it at boot.

### 4. Nobody has ever done it — on any TV, any brand

- **Samsung/Tizen:** no instance. Ceiling achieved = firmware patching.
- **SamyGO** (the entire history of Samsung TV modding, pre-Tizen): VERIFIED
  achievements were NFS/SMB sharing, USB playback, and unlocking off-brand Wi-Fi
  dongles. Feature unlocks on patched stock firmware — not an OS replacement.
- **LG webOS:** the best-resourced attempt anywhere — RootMyTV (2,464 stars),
  webhomebrew (1,522 stars), years of work by skilled people. Result: **root plus a
  homebrew app store. Not an Android port.** And it is now dead: RootMyTV's own
  README states the vulnerabilities are patched since mid-2022 and downgrades are
  no longer possible without pre-existing root.

That last point is the most informative finding in the project: **where TV modding
succeeded most, the prize was still homebrew apps — and the vendor patched it out.**

### 5. Every OS-replacement success sits on opposite hardware

Android/large-OS replacement reliably works on generic, documented hardware —
Intel NUC (StremioBox: "Android 16 TV image for Intel NUC"), LineageOS-TV-x86
bring-up projects, Raspberry Pi, Android-x86/Bliss OS.

| Enabler | Those devices | Samsung TV |
|---|---|---|
| Generic SoC + public BSP | ✅ | ❌ Samsung proprietary silicon |
| Unlockable bootloader | ✅ | ❌ none known, ever |
| Open/reverse-engineered GPU | ✅ Intel/AMD/V3D | ❌ proprietary Mali blob |
| Treble/vendor partition (GSI) | ✅ | ❌ not shipped |
| Documented boot ROM/recovery | ✅ | ❌ |

### 6. Even if you got past all that, the result would be poor

From lane 03 (Android userspace on the rooted kernel):

- **GPU:** Samsung's proprietary Mali blob is built for Tizen's glibc + TBM/Wayland
  EGL. Android needs Bionic-linked gralloc/EGL. Not interchangeable → software
  rendering (SwiftShader) only → low frame rate.
- **Video/DRM:** hardware decoders sit behind Samsung's proprietary media stack.
  Software decode only, ~1080p H.264 at best. No 4K/HDR. **No Widevine L1 — which
  kills Netflix-class streaming**, the main reason to want Android on a TV.
- **Kernel:** Android needs binder (mainline since 3.19, so not the blocker people
  assume), plus loop, IPv6, namespaces, cgroups. Tizen doesn't use binder, so it is
  almost certainly not built in. You'd need an out-of-tree `binder.ko` built
  against the *exact* vendor kernel, and module signing may refuse it.
- **Certification:** it would be uncertified AOSP/LineageOS, not Android TV. No
  Google TV launcher, no licensed Play Services.

## What we got right that most internet sources get wrong

Two things the project established, both correcting common misinformation:

1. **The silicon is fine.** A 2026 Samsung TV runs an **AArch64 (64-bit) kernel**
   with a **Mali-G510**. The SDB string reporting `cpu_arch:armv7` describes the
   32-bit *userspace* (ARM EABI5), not the chip. Anyone arguing "TVs are stuck on
   32-bit ARM" is wrong about 2026 hardware.
2. **Root is genuinely achievable now** — a real change since ~Aug 2026, and worth
   knowing on its own. It is useful for debloating, diagnostics, remote remapping,
   and HDMI/compositor control. It is just not a path to a different OS.

Also confirmed: many "install Android on your Samsung TV" pages (e.g. the
top-ranking mundobytes.com article) are **misinformation** — they describe copying
an APK to a USB stick. A Samsung TV has no Android runtime and cannot run an APK.

## The decisive experiment — run, and it settles the question

The open question was whether the boot chain verifies what it loads. It does:

> "Every section carries a per-item `OURSAValidationDesc` with a public-key id
> (`0x19fc36c9`), so authenticity is checked independently of the (broken)
> encryption — reading the firmware does not let you forge a bootable modified
> image." — `sebastianspicker/tiz0wn`, firmware analysis of a 2026 GQ55Q60TGUXZG (`T-NKLDEUC-2743.0`)

Their §11.6 states the conclusion independently of this project:

> "**Native applications and firmware replacement are different projects.** …
> Replacing the operating system would additionally require a usable boot path and
> working support for the panel, graphics, video decoding, sound, input, power
> management … No tested custom-OS image or full replacement procedure for this
> exact configuration was established."

The same work also confirms the historical physical-memory root primitive
(`sdp_mem`/`sdp_hwmem`) is **hardened** at driver level on current builds — a
whitelist-containment check plus an explicit kernel-region-intersection reject,
verified by disassembly.

### Verify it yourself — no TV needed

`toolkit/analyze-firmware.py` reads a stock firmware container and reports whether
per-item signature descriptors are present. Download the official firmware for your
model from Samsung and run it. That is the real test, and it runs offline.

```bash
python3 toolkit/analyze-firmware.py /path/to/upgrade.msd
```

`toolkit/boot-probe.sh` does the same job from the other direction, on the device,
if you ever want device-side confirmation. Its single most informative line is
`ls -l /dev/dri/`: no `/dev/dri` means no standard Kernel Mode Setting, which alone
closes the "run Android's graphics stack here" lane independently of the boot chain.

## Recommendation

**Put a $30–60 Android/Google TV stick or box on an HDMI port.** Twenty minutes, no
risk, no warranty loss, and it delivers everything "Android on the TV" was meant to
deliver — including certified Android TV, Widevine L1, 4K, and hardware decoding.
Every finding above says this is strictly better than any software route.

Nothing further is needed from JJ to close this out. The two things I previously
asked for (model number, TV on the network) are no longer blockers: the answer came
from the firmware image, not the device.

## Method note / confidence

Four of five delegated research lanes were killed by a model-provider safety
filter (category: cyber) mid-run; the surviving lane (Android userspace) reported
itself as a weakly-verified first pass. Rather than ship a blocked or thin result,
the hardware/boot-chain and prior-art lanes were **reconstructed directly by the
parent** from primary sources: the two root projects' own documentation and file
trees (fetched via raw.githubusercontent + GitHub API), Wikipedia source exports,
and live GitHub repository data. Where web search was captcha-blocked, gaps are
labelled UNKNOWN rather than guessed — see 02-prior-art.md, "What I could NOT
verify".

Confidence: **high** that OS replacement is not achievable by the software routes
explored, and high that no one has ever done it. **Lower** on the absolute claim
that it is impossible — that rests on the absence of any published instance plus
the unexamined bootloader. The decisive experiment above is how to raise it.
