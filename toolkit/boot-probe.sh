#!/bin/sh
# ---------------------------------------------------------------------------
# boot-probe.sh — THE DECISIVE EXPERIMENT
#
# Runs ON the TV (via the root path / injected shell) and answers the one
# question all desk research cannot: does this TV's boot chain verify what it
# loads?
#
# Read-only. It inspects, it does not modify. Nothing is written to the device
# except its own stdout, which you redirect to the host yourself.
#
# Usage (from the host, with the TV reachable):
#   sdb -s <TV_IP>:26101 shell "0 appinstall tpk <injection>"   # or the toolkit
# and feed this script to /bin/sh, e.g.:
#   cat boot-probe.sh | <transport> /bin/sh
#
# Or, once you have any root shell:
#   sh boot-probe.sh > boot-probe-$(date +%Y%m%d-%H%M).txt
# ---------------------------------------------------------------------------

hr() { echo ""; echo "=================================================="; echo "== $1"; echo "=================================================="; }

hr "IDENTITY"
echo "date      : $(date 2>/dev/null)"
uname -a 2>/dev/null || echo "uname: unavailable"
echo "id        : $(id 2>/dev/null)"
echo "kernel    : $(cat /proc/version 2>/dev/null)"

hr "1. BOOT ARGUMENTS (what the bootloader handed the kernel)"
cat /proc/cmdline 2>/dev/null || echo "unavailable"
echo "--- device tree model ---"
cat /proc/device-tree/model 2>/dev/null && echo "" || echo "unavailable"
echo "--- dt compatible ---"
cat /proc/device-tree/compatible 2>/dev/null | tr '\0' '\n' || echo "unavailable"

hr "2. BOOT CHAIN / VERIFICATION STATE"
echo "--- secure boot / verification hints in cmdline ---"
grep -oiE '(dm-verity|verity|avb|androidboot[a-z_.]*=[^ ]*|secure[^ ]*|verified[^ ]*)' /proc/cmdline 2>/dev/null || echo "none found"
echo "--- kernel lockdown ---"
cat /sys/kernel/security/lockdown 2>/dev/null || echo "no lockdown interface"
echo "--- module signing enforcement (does it refuse our .ko?) ---"
if [ -r /proc/config.gz ]; then
  zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_MODULE_SIG|CONFIG_MODULES=|CONFIG_LOCK_DOWN|CONFIG_SECURITY_LOCKDOWN' || echo "no module-sig keys"
else
  echo "/proc/config.gz absent"
fi
echo "--- kernel taint (was anything unsigned already loaded?) ---"
cat /proc/sys/kernel/tainted 2>/dev/null || echo "unavailable"

hr "3. UEP / EXECUTION POLICY"
echo "--- Samsung UEP / SFD artefacts ---"
ls -la /sys/module/ 2>/dev/null | grep -iE 'uep|sfd|sdp' || echo "no uep/sfd module entries"
echo "--- can we see the state word? (informational only) ---"
grep -iE 'uep|sfd' /proc/kallsyms 2>/dev/null | head -5 || echo "kallsyms restricted"
echo "--- SELinux / SMACK (exec policy) ---"
cat /sys/fs/selinux/enforce 2>/dev/null && echo " (selinux)" || echo "no selinux enforce node"
ls /sys/fs/smack/ 2>/dev/null | head -5 || echo "no smack"

hr "4. PARTITIONS — the real question: what is writable and verified?"
echo "--- /proc/mtd (raw flash) ---"
cat /proc/mtd 2>/dev/null || echo "no MTD (eMMC/UFS device, likely)"
echo "--- block devices ---"
ls -l /dev/mmcblk* /dev/sd* /dev/block/* 2>/dev/null | head -30 || echo "none visible"
echo "--- by-name partition map ---"
ls -l /dev/block/by-name/ 2>/dev/null || echo "no by-name map"
echo "--- mounts (note ro/rw) ---"
cat /proc/mounts 2>/dev/null
echo "--- which mounts are writable? ---"
grep -E ' rw,| rw ' /proc/mounts 2>/dev/null | awk '{print $2, $3, $4}' || echo "none"

hr "5. BOOTLOADER ARTEFACTS VISIBLE FROM USERSPACE"
for p in /dev/block/by-name/boot /dev/block/by-name/rootfs /dev/block/by-name/uboot /dev/mmcblk0p1; do
  if [ -e "$p" ]; then
    echo "--- $p exists: strings sample ---"
    strings "$p" 2>/dev/null | grep -iE 'u-boot|uboot|samsung|secure|verify|signature|magic' | head -8 || echo "   (no matching strings / unreadable)"
  fi
done
echo "--- firmware / version files ---"
for f in /etc/version.info /etc/os-release /etc/build.prop /proc/samsung_boot; do
  [ -e "$f" ] && { echo "--- $f"; cat "$f" 2>/dev/null | head -12; }
done

hr "6. CAN ANDROID'S KERNEL REQUIREMENTS BE MET? (lane-03 gate)"
if [ -r /proc/config.gz ]; then
  echo "--- critical configs ---"
  zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_ANDROID_BINDER|CONFIG_ASHMEM|CONFIG_NAMESPACES|CONFIG_CGROUPS|CONFIG_BLK_DEV_LOOP|CONFIG_IPV6|CONFIG_DRM=|CONFIG_DRM_KMS_HELPER' || echo "none present"
else
  echo "/proc/config.gz absent — cannot read config"
fi
echo "--- binder device present? ---"
ls -l /dev/binder* /dev/hwbinder /dev/vndbinder 2>/dev/null || echo "no binder devices (expected: Tizen does not use binder)"
echo "--- display: DRM/KMS available? ---"
ls -l /dev/dri/ 2>/dev/null || echo "NO /dev/dri — no standard KMS. This closes the graphics lane."
echo "--- GPU kernel driver loaded ---"
lsmod 2>/dev/null | grep -iE 'mali|kbase|panfrost|drm' || echo "no mali/drm modules listed"
echo "--- loadable modules supported? ---"
ls /lib/modules/ 2>/dev/null | head -3 || echo "no /lib/modules"

hr "7. STORAGE AND MEMORY HEADROOM"
echo "--- RAM ---"
grep -E 'MemTotal|MemAvailable|MemFree' /proc/meminfo 2>/dev/null
echo "--- filesystem usage ---"
df -h 2>/dev/null | head -20
echo "--- persistent writable locations ---"
for d in /opt /mnt /home/owner /tmp /var; do
  [ -d "$d" ] && echo "$d: $(ls -ld "$d" 2>/dev/null | awk '{print $1,$3,$4}')"
done

hr "PROBE COMPLETE"
echo "Interpretation guide:"
echo "  * No /dev/dri            -> graphics lane closed (no standard KMS for Android)"
echo "  * No binder in config    -> would need out-of-tree binder.ko against this exact kernel"
echo "  * MODULE_SIG_FORCE=y     -> cannot load a self-built module"
echo "  * VM/AVB/dm-verity set   -> boot chain verifies; OS replacement closed"
echo "  * A writable, unverified boot partition -> GENUINELY NEW. Stop and report."
