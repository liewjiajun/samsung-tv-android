# 03 — Android userspace on a rooted Tizen kernel (container path)

Labels: VERIFIED (checked a source this session), KNOWN (well-established public fact, not re-fetched this session), INFERRED, UNKNOWN.
Tool note: web_search returned 402 and exec was unavailable this session; only ArchWiki Waydroid was fetched live. Treat KNOWN items as needing a re-check before anything gets built.

## 1. What Android userspace needs from the kernel
- **Binder** (binder/hwbinder/vndbinder) is required. servicemanager, every system service, and HALs talk over it. It has been in mainline since 3.19 under CONFIG_ANDROID_BINDER_IPC, binderfs since 5.0, and there is a Rust binder (rust_binder) in recent kernels. VERIFIED (ArchWiki: needs binder_linux or rust_binder, `devices=binder,hwbinder,vndbinder`, or binderfs on kernels 5.7+). Mainline binder is enough. This is what Waydroid uses on stock distro kernels. VERIFIED.
- **ashmem**: deprecated. Android 10+ falls back to memfd (mainline). KNOWN. Older Android images (≤9), which matter for armv7, may still want ashmem. Waydroid historically shipped ashmem_linux DKMS. KNOWN.
- **ION / dma-buf heaps**: dma-buf is mainline. ION was removed in 5.11 and replaced by dma-buf heaps. Only vendor HALs need these. Software gralloc does not. KNOWN.
- Also needed: loop devices, IPv6 (otherwise no IPv4 in the container), netfilter conntrack netlink, PSI, cgroups, and namespaces for LXC. VERIFIED (ArchWiki minimal-kernel list).
- **Tizen kernel reality**: Samsung TV kernels are vendor 3.x/4.x/5.x trees. Tizen does not use binder (it uses D-Bus and kdbus-era IPC). INFERRED/UNKNOWN per model: binder is almost certainly not built in. Rooting gives you the ability to load modules, not to change the kernel. You would need an out-of-tree binder.ko built against that **exact** vendor kernel (headers/config/vermagic), and Samsung may enforce module signing. **This is the first hard gate. Check `/proc/config.gz`, `CONFIG_MODULES`, `CONFIG_MODULE_SIG_FORCE`, and namespace/cgroup support on a rooted unit.** UNKNOWN until tested.

## 2. Prior art
- **Anbox**: LXC container with binder and ashmem modules, rendering through an OpenGL ES pipe to the host. The project was declared deprecated/unmaintained in early 2023, with Waydroid as the successor (KNOWN; anbox GitHub README states this). Anbox Cloud is a separate commercial Canonical product. Dead for this purpose.
- **Waydroid**: LineageOS 18.1 / 20 (Android 11 / 13) images in LXC. Needs binder, a Wayland compositor, and a GPU with mesa (Intel/AMD best, NVIDIA unsupported, software rendering fallback). VERIFIED (ArchWiki). It ships images for x86_64, arm64, x86, and **armv7 (arm)**. KNOWN, but armv7 images are old/rarely tested. It runs well on arm64 Linux phones (PinePhone, postmarketOS, Ubuntu Touch, Droidian). KNOWN. It runs native arch only, with no ARM translation on x86. VERIFIED.
- **Android-x86 / Bliss OS / LineageOS on RPi**: these are full OS replacements with their own Android-patched kernel. Not container-on-foreign-kernel, so not this lane. They show that mesa-based gralloc and drm_hwcomposer work when an open DRM/KMS + mesa GPU driver exists. KNOWN.
- **Smart TVs**: no known public project runs Anbox/Waydroid on a Tizen (or webOS) TV. UNKNOWN or none found. The closest analogue is Waydroid on embedded arm64 boards with mainline kernels.

## 3. Graphics (main blocker)
- Waydroid's display path: Android's SurfaceFlinger uses a custom HWC (hwcomposer.waydroid) that hands buffers to the **host Wayland compositor** as Wayland surfaces. Buffers come from gbm/minigbm gralloc on the host DRM render node, and GL comes from mesa inside the container. KNOWN.
- Tizen does use a Wayland compositor (Enlightenment/"DS" display server), but it is not a general desktop compositor. INFERRED: it likely lacks the protocols Waydroid relies on (xdg-shell, linux-dmabuf, possibly wl_drm) and enforces Tizen app/window policy. Its Wayland socket may also be restricted by Smack.
- The TV GPU is ARM Mali with Samsung's **proprietary** Mali blob (libMali, fbdev/tbm-based). There is no mesa driver for that kernel's Mali driver. Panfrost/Lima need the mainline kernel driver and don't apply to a vendor kbase driver. INFERRED, high confidence. So the hardware-accelerated Waydroid path (mesa + gbm) is unavailable.
- **Fallback: software rendering.** Waydroid supports SwiftShader/llvmpipe (`ro.hardware.gralloc=default`, `ro.hardware.egl=swiftshader`). VERIFIED (ArchWiki has a software-rendering section). On a 4-core Cortex-A53/A55/A72 TV SoC at 1080p, expect a sluggish UI, very low frame rates in launchers and animations, and unusable games. INFERRED.
- **Alternative: no host compositor.** Stop or suspend Tizen's compositor and give Android DRM/KMS through drm_hwcomposer and software gralloc, i.e. a full-screen takeover. This requires Samsung's display driver to expose usable KMS. TV display pipelines are often proprietary (TBM/TDM), not standard KMS. UNKNOWN. It would also kill Tizen's UI and fight Tizen watchdogs.
- **Practical appearance**: at best, a Wayland window or full-screen surface layered by Tizen's compositor, or fb/KMS takeover. A realistic minimum is a VNC/scrcpy-style headless Android rendered in software and shown by a Tizen web/native app. INFERRED.

## 4. Hardware acceleration
- Mali GPU: Samsung's libMali is built against Tizen's glibc and TBM/Wayland EGL platform. Android needs Bionic-linked gralloc/EGL. These are not interchangeable, so the GPU cannot be used from Android. INFERRED, high confidence. Possible exceptions are libhybris-style shims, which go the other way (Android blobs on glibc), or a GL-forwarding pipe like Anbox's (host renders GLES via the Tizen EGL, guest serializes calls). The pipe approach is theoretically possible but is a large engineering project with high latency.
- Video decode: TV decoders sit behind Samsung's proprietary media framework (MM/TrustZone/DRM secure path, often not V4L2). Android's codec2/OMX would need a custom HAL bridging to Tizen services. Without it you get software decode only, which handles roughly 720p/1080p H.264 at best on A53-class cores. No HEVC/VP9/AV1 4K, and no Widevine L1 (so Netflix etc. would be SD at best or refuse). INFERRED.
- Audio, the tuner, the remote/IR input, and HDMI-CEC would all need bridges as well. Input could come via uinput/evdev passthrough. INFERRED.

## 5. armv7 32-bit constraint
- Android supports 32-bit-only devices through Android 13/14 for low-RAM "Go"-style configs. Since Android 12/13, Google Play and the CDD effectively push 64-bit for new devices. Play has required 64-bit native libs in apps since Aug 2019, but 32-bit libs are still shipped for 32-bit devices. KNOWN.
- Android TV: Google required 64-bit support for Android TV/Google TV in 2026-era guidance. Starting Aug 2026, apps targeting TV must ship 64-bit, and Android TV 14 devices are expected to be 64-bit. KNOWN-ish, needs re-verification. Many Android TV devices still run a 32-bit userspace on 64-bit CPUs.
- Waydroid's **armv7** builds are LineageOS 17.1/18.1 (Android 10/11) at most, and maintenance is spotty. INFERRED/KNOWN. Realistic newest on armv7 is **Android 11–13** (LineageOS builds 32-bit arm through 20/21 for some devices). Note that even when the CPU is 64-bit, Tizen userspace is armv7, so the kernel may be 32-bit. A 32-bit kernel cannot run arm64 Android userspace.
- This would be LineageOS/AOSP, **not certified Android TV**. No Google TV launcher, and no licensed Play Services (GApps can be sideloaded, but device certification and Widevine L1 are absent).

## 6. Storage/performance
- Waydroid images are about 1–2 GB (system.img + vendor.img) plus userdata. KNOWN. TV eMMC is small and Tizen-partitioned.
- Option: put system/vendor/userdata on a USB drive (ext4) and point Waydroid's `images_path` and `/var/lib/waydroid` there, loop-mounted. Mount needs the loop module (VERIFIED requirement). Most TV USB ports are USB 2.0 (~30–35 MB/s, poor random IO), and some are USB 3.0. Expect slow boot (minutes) and app-install/launch stutter, but it is functional. INFERRED. Also needed: a chroot/host userland (LXC, python for waydroid tooling) built for armv7 and statically or alongside Tizen libs, also placed on USB.
- RAM: TVs have 1.5–3 GB, mostly used by Tizen. Android 11 + software rendering wants ≥2 GB. You would likely have to stop Tizen's UI services. INFERRED.

## 7. Verdict
**Not viable as "Android on the TV". At most viable-but-badly-degraded as a hobby proof-of-concept.**

Where it dies, in order:
1. **Kernel gate**: you need binder (plus ashmem for older images), namespaces/cgroups, loop, and IPv6 on a closed vendor kernel. If module loading is signed/disabled or the kernel sources/config for the exact firmware aren't available, it stops here. Samsung publishes kernel GPL source at opensource.samsung.com, which helps, but the vermagic and config must match the exact build. UNKNOWN, test first.
2. **Graphics**: no mesa driver for the vendor Mali, so you're limited to software rendering. Tizen's compositor probably won't host Waydroid surfaces, so a KMS takeover or a custom bridge is required.
3. **Media/DRM**: no hardware decode and no Widevine L1, which kills the main reason to want Android on a TV (streaming apps).
4. **Arch/OS level**: armv7 limits you to roughly Android 11–13 AOSP/Lineage, with no Android TV certification and no Google TV.

End-user experience if it boots: a laggy, software-rendered LineageOS (tablet or Lineage ATV UI) at low fps, with SD-at-best streaming, no HDR/4K, flaky remote input, booting off USB, possibly with Tizen's UI killed. It's a tech demo, not a usable Android TV. For anyone actually wanting Android on the TV, a $30–50 Android TV/Google TV stick is strictly better.

Recommended next test on a rooted unit (cheap, decisive): `zcat /proc/config.gz | grep -E 'BINDER|ASHMEM|MODULE_SIG|NAMESPACES|CGROUPS|BLK_DEV_LOOP|IPV6|DRM'`, `uname -a`, `cat /proc/cpuinfo`, `ls /dev/dri`, `lsmod`. If there is no `/dev/dri/card*` with KMS and module signing is forced, close this lane.

## Sources
- https://wiki.archlinux.org/title/Waydroid (VERIFIED, fetched 2026-10-19)
- https://docs.waydro.id , https://github.com/waydroid/waydroid (not re-fetched)
- https://github.com/anbox/anbox (deprecation notice, not re-fetched)
- https://lwn.net/Articles/953116/ (Rust binder, cited via ArchWiki)
- https://source.android.com/docs/core/architecture/ipc/binder-overview
- https://opensource.samsung.com (Samsung TV kernel GPL sources)
