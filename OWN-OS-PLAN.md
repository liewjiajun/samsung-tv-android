# OWN-OS-PLAN.md — what it actually takes to replace Tizen on this panel

Scope note: this is the plan for "reverse engineer it until it is our OS."
It is written against the LS03B (The Frame 65, QA65LS03BAKXXS, PontusM,
Tizen 6.5, Linux 5.4.77 armv7) firmware, from the image only. Nothing here has
been run on the TV.

## The honest shape of the problem

There are three independent walls and they are not equally hard:

| # | Wall | Status | Verdict |
|---|------|--------|---------|
| 1 | Signed boot chain (kernel/rootfs) | HW-fused, per-section RSA | **closed** — cannot reflash a modified image |
| 2 | UEP / SFD exec gate | built into the kernel image | **bypassable in principle, not by patching it** |
| 3 | Android runtime + Play Store | absent, and GMS licensing | **closed** — architecturally excluded |

So "flash our own OS image" is not available. What *is* available is replacing
everything above the kernel: if we get code execution as root, Tizen's own
userspace becomes optional. That is the realistic meaning of "our OS" here —
our runtime on Samsung's kernel.

## What is already established (offline, verified)

- Kernel 5.4.77, armv7, no embedded IKCONFIG. Vermagic known.
- **No binder** anywhere in the kernel image (positive controls valid).
- `CONFIG_MODULES` present (`kernel/module.c`, `do_init_module`).
- **CORRECTION:** an earlier note in this project said "no module signature
  enforcement." That was wrong. The image contains the full PKCS#7 verifier
  (`pkcs7_parse_message`, `pkcs7_verify`, `pkcs7_validate_trust`) plus
  `is_module_sig_enforced` and `PKCS7: Invalid module sig` strings. Module
  signing support is definitely compiled in. Whether it is *enforced* is not
  determinable offline: the usual enforcement messages ("module verification
  failed", "Loading of unsigned module") are absent, but so are other strings
  that certainly should exist, so absence here is not evidence. **This must be
  tested on device before any module-based plan is trusted.**
- rootfs is VDFS4 layout 2007, read-only, 61,344 files; fully readable now
  (including the 16,937 compressed ones) via `re/vdfs4.py` + `re/xfile.py`.
- 87 capability-bearing binaries; **only 16 grant capabilities on exec.**
  `/usr/bin/dotnet` is NOT one of them (permitted set empty) — the published
  research named the wrong entry point.
- Real levers (permitted set non-empty, incl. `cap_sys_admin`):
  `/usr/bin/launchpad-starter`, `/usr/bin/dotnet-launcher`,
  `/usr/bin/launchpad-process-pool`, `/usr/bin/wrt`, `/usr/bin/devzone-launcher`.
  `launchpad-starter` imports `prctl`, `capset`, `execv`, `setreuid`,
  `smack_lsetlabel` and logs "Failed to set capability" / "exec launchpad".
- **UEP is the `sfd` security filter driver, compiled into the kernel**, not a
  module. 271 modules exist; none is uep/sfd. Kernel strings include
  `SfdUepVerifyExecutableBinary`, `SfdUepVerifyDynamicLibrary`,
  `SfdCheckFileIsInRW`, `UEP has been disabled`, `Blocked! cur pid:%u`.
- `libkUEPUser.so` (userspace) does have a designed disable route:
  `FindUEPDiableFile()` walks **USB mass storage** for `VDUEPOFF.cer`, and
  `verifyFileWihtoutKey()` runs a signature-free path when found, gated on
  `isRootUID()` / `isIsolatedContainer()`.

## Consequences that shape the plan

1. **You cannot patch UEP out** — it is in the kernel image, and the image is
   signature-verified. Any plan that starts with "modify the kernel" is dead.
2. **You cannot flash a custom kernel or rootfs.** Wall 1 is fused.
3. **Loadable modules are plausible but unproven.** `CONFIG_MODULES` is on inside
   the kernel, and 271 `.ko` files ship in `/usr/lib/modules/5.4.77`. But the
   PKCS#7 module verifier is compiled in and `is_module_sig_enforced` exists.
   Whether an unsigned module loads is an open question that decides the plan.
4. **Therefore the route is: get root in the running system → become the
   authority → build our userspace alongside Tizen.** Not "replace the OS image."

## Ordered plan, each step with a proof gate

### Step 1 — prove code execution on device (BLOCKED: needs Dev Mode)
Enable Developer Mode, set developer IP to 192.168.50.53, reboot, connect SDB
on 26101. Then verify, in order:
- `getcap /usr/bin/dotnet /usr/sbin/sdbd-tarlauncher` — settle the permitted-set
  question on the actual device.
- `/proc/self/status` CapEff/CapPrm/CapInh from an `sdk`-owned process.
- `id` — confirm uid 901 `sdk`.
- `cat /proc/modules` and `ls /lib/modules/5.4.77`.
- `cat /sys/module/module/parameters/sig_enforce` (if present) — this is the
  single most valuable read on the device. Read-only, trivial.
- `insmod` of test module. **If this fails, the module route is dead and the
  plan collapses back to userspace-only.**

Gate: a loaded `.ko` of our own, or a clear errno showing why not.

### Step 2 — build a capability-bearing entry point
Do not depend on `/usr/bin/dotnet`. Target the launchers whose file permitted
set is non-empty. Concretely: understand what `launchpad-starter` will `execv`
and whether the path is influenceable, or whether a config it reads is writable.
Gate: our code running with `cap_sys_admin` effective, confirmed from
`/proc/self/status`.

### Step 3 — neutralise UEP for our payloads only
Two possible routes, in preference order:
(a) if `insmod` works: load a module that hooks the sfd notifier for our
    process only (least invasive, reversible).
(b) if the `VDUEPOFF.cer` USB route is real: determine whether the `.cer` needs
    a Samsung signature. If it does, this route is closed and (a) is the only one.
Gate: an unsigned armv7 binary of ours executes and stays executing.

### Step 4 — our runtime alongside Tizen
With root + no UEP, the panel is reachable via the Wayland stack that is already
present (libwayland-server/-client, 26 client libs, libmali.so, libEGL/libGLES).
Build a minimal compositor, take the display, keep Tizen services for hardware
(HDMI, tuner, audio) where convenient.
Gate: our own window on the panel, driven by our code.

### Step 5 — our services instead of theirs
`launchpad` (app management), SMACK policy, and the boot targets are the things
that make it feel like Samsung's TV. Replace incrementally; each replacement is
reversible by keeping the original binary and its unit file.

## What will NOT happen

- Play Store. No ART, no GMS, no binder, and Google's certification is a
  business relationship, not a technical setting. If you want Play, that is an
  Android device, not this panel.
- A custom kernel or a reflashed rootfs.
- Anything that survives a factory reset while wall 1 is fused, unless the change
  lives in a writable partition and is re-applied at boot.

## Immediate next actions (offline, no TV needed)

1. Determine how the sfd notifier decides to block — read `SfdCheckFileIsInRW`
   call paths in the kernel image; find whether the decision is per-inode and
   whether `/opt` (writable, survives reboot) is treated as RW-trusted.
2. Resolve whether `VDUEPOFF.cer` is signature-required (strings/flow in
   `libkUEPUser.so` around `handleStorageCallback`).
3. Confirm armv7 kernel module build feasibility: check `.config` reconstruction
   from the image for `CONFIG_MODVERSIONS`.
4. Map the Wayland surface path Tizen uses, so step 4 has a known entry.
