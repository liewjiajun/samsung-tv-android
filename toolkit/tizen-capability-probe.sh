#!/bin/sh
# tizen-capability-probe.sh — decide, on the device, how Android can run here.
#
# READ-ONLY. This script changes nothing. It only reads and reports.
#
# WHY IT EXISTS
# -------------
# There are three ways to get Android onto a Tizen TV, and they are not equally
# possible. Which one is open depends on facts that can only be read from the
# live device:
#
#   TIER 1  Runtime modification — overlay the running system. Tizen keeps
#           driving the panel, so Android renders off-screen and Tizen presents
#           the frames. No mainline display driver needed. This is how webOS
#           homebrew works on signed read-only squashfs images, and how ARC
#           works on ChromeOS.
#
#   TIER 2  Package-level — install a .tpk/.wgt signed with your OWN author
#           certificate in Developer Mode. No root. Very limited reach.
#
#   TIER 3  Firmware reflash — replace the OS. This is the one that is closed:
#           every boot-relevant section carries its own RSA signature
#           (OURSAValidationDesc), so a repacked image does not boot.
#
# TIER 1 hinges on a handful of kernel and filesystem facts. This probe reads
# exactly those, and prints a verdict per tier.
#
# USAGE
#   sh tizen-capability-probe.sh              # human-readable
#   sh tizen-capability-probe.sh --json       # machine-readable
#   sh tizen-capability-probe.sh --save FILE  # write report to FILE
#
# Run it via memfd if UEP blocks executing it from the filesystem.

JSON=0
SAVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --save) SAVE="$2"; shift ;;
    *) ;;
  esac
  shift
done

# Buffer the report so it can be saved and re-emitted at the end. /tmp may be
# read-only or absent on some builds, so degrade to printing straight through.
#
# Keep a copy of the original stdout on fd 3. Without this, redirecting stdout
# into $REPORT makes the final `cat $REPORT` write into its own file and the
# report never reaches the terminal.
REPORT=$(mktemp 2>/dev/null) || REPORT=""
if [ -z "$REPORT" ]; then
  REPORT=/tmp/.probe.$$
  ( : > "$REPORT" ) 2>/dev/null || REPORT=""
fi
if [ -n "$REPORT" ]; then
  exec 3>&1
  exec > "$REPORT" 2>&1
else
  exec 3>&1
fi

say() { printf '%s\n' "$*"; }
hdr() { printf '\n=== %s ===\n' "$*"; }

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# read a kernel config symbol from /proc/config.gz or /boot/config-*
kconfig() {
  sym="$1"
  if [ -r /proc/config.gz ] && have zcat; then
    zcat /proc/config.gz 2>/dev/null | grep -E "^${sym}=" | head -1
    return
  fi
  for f in /boot/config-* /lib/modules/*/build/.config; do
    [ -r "$f" ] || continue
    grep -E "^${sym}=" "$f" 2>/dev/null | head -1
    return
  done
  printf '%s=UNKNOWN\n' "$sym"
}

# is CONFIG_X set to y or m? prints y / m / n / UNKNOWN
koption() {
  line=$(kconfig "$1")
  val=${line#*=}
  case "$val" in
    y|m|n) printf '%s' "$val" ;;
    *) printf 'UNKNOWN' ;;
  esac
}

# ---------------------------------------------------------------------------
# EMPIRICAL FALLBACKS
# ---------------------------------------------------------------------------
# On a hardened device /proc/config.gz is usually absent and /boot is empty, so
# every CONFIG_* read comes back UNKNOWN. UNKNOWN is useless for a go/no-go
# decision, and it is exactly the situation we expect on the real TV. So when a
# symbol cannot be read, test for the capability by OBSERVING the live system
# instead of trusting a config file that may not be there.
# ---------------------------------------------------------------------------

# does a kernel module appear loaded, or a device node exist?
have_module() {
  [ -d "/sys/module/$1" ] && return 0
  [ -e "/dev/$1" ] && return 0
  grep -qw "$1" /proc/modules 2>/dev/null && return 0
  return 1
}

# binder: the hard gate for Android userspace
probe_binder() {
  if [ -e /dev/binder ] || [ -d /sys/module/binder ]; then
    printf 'PRESENT(device)'
  elif grep -qiE 'binder' /proc/modules 2>/dev/null; then
    printf 'PRESENT(module)'
  elif [ -e /dev/binderfs ] || [ -d /sys/fs/binder ]; then
    printf 'PRESENT(binderfs)'
  else
    printf 'ABSENT'
  fi
}

# ashmem: shared memory, or its modern replacement memfd
dev_ashmem() {
  if [ -e /dev/ashmem ] || [ -d /sys/module/ashmem ]; then
    printf 'PRESENT'
  elif grep -qiE 'ashmem' /proc/modules 2>/dev/null; then
    printf 'PRESENT(module)'
  else
    printf 'ABSENT'
  fi
}

# namespaces: /proc/self/ns lists the namespace types this kernel supports.
# This is live evidence, not a config guess.
ns_present() {
  [ -e "/proc/self/ns/$1" ] && printf 'y' || printf 'n'
}

# cgroups: /proc/cgroups lists controllers; a cgroup2 mount is stronger evidence
cgroup_state() {
  if [ -d /sys/fs/cgroup ]; then
    if grep -qw cgroup2 /proc/filesystems 2>/dev/null; then printf 'y(cgroup2)'
    else printf 'y(v1)'; fi
  elif [ -r /proc/cgroups ]; then
    printf 'y(listed)'
  else
    printf 'n'
  fi
}

# does the mounting table show this fs type?
fstype_available() {
  grep -qw "$1" /proc/filesystems 2>/dev/null && return 0
  return 1
}

# can we actually create a file here?
writable() {
  d="$1"
  [ -d "$d" ] || return 1
  t="$d/.probe-wtest.$$"
  ( : > "$t" ) 2>/dev/null || return 1
  rm -f "$t" 2>/dev/null
  return 0
}

# ---------------------------------------------------------------------------
# device identity
# ---------------------------------------------------------------------------
ID_UID=$(id 2>/dev/null)
ID_UID_N=$(id -u 2>/dev/null || echo "?")
KREL=$(uname -r 2>/dev/null)
KVER=$(uname -v 2>/dev/null)
MACH=$(uname -m 2>/dev/null)

CMDLINE=""
[ -r /proc/cmdline ] && CMDLINE=$(cat /proc/cmdline 2>/dev/null)

# ---------------------------------------------------------------------------
# the decisive capability questions
# ---------------------------------------------------------------------------
# Android userspace needs binder (IPC) and ashmem (shared memory).
# Config symbols are read first, but on a hardened device those files are absent,
# so fall back to observing the live system.
BINDER=$(koption CONFIG_ANDROID_BINDER_IPC)
BINDER_OLD=$(koption CONFIG_ANDROID_BINDER_DEVICES)
ASHMEM=$(koption CONFIG_ASHMEM)
LIVE_BINDER=$(probe_binder)
LIVE_ASHMEM=$(dev_ashmem)

# Containers (LXC/Anbox/Waydroid) need namespaces and cgroups.
NS=$(koption CONFIG_NAMESPACES)
CGROUPS=$(koption CONFIG_CGROUPS)
USERNS=$(koption CONFIG_USER_NS)
PIDNS=$(koption CONFIG_PID_NS)
NETNS=$(koption CONFIG_NET_NS)
UTSNS=$(koption CONFIG_UTS_NS)
LIVE_NS=$(ns_present mnt)
LIVE_USERNS=$(ns_present user)
LIVE_PIDNS=$(ns_present pid)
LIVE_NETNS=$(ns_present net)
LIVE_CGROUPS=$(cgroup_state)

# Tier 1 runtime modification needs a way to overlay a read-only rootfs.
# (bind mounts are always available; overlayfs may be built in or absent)
OVERLAY=$(koption CONFIG_OVERLAY_FS)

# A hypervisor-based Android (ARCVM-style) needs KVM.
KVM=$(koption CONFIG_KVM)

# Loading our own modules (binder/ashmem) needs module support.
MODULES=$(koption CONFIG_MODULES)
MODVERSION=""
[ -r /proc/sys/kernel/modules_disabled ] && MODVERSION=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)

# Alternative boot paths, for completeness (Tier 3).
KEXEC=$(koption CONFIG_KEXEC)
KEXEC_FILE=$(koption CONFIG_KEXEC_FILE)

# Display: is there any framebuffer/DRM node, or only the vendor stack?
FB_DEV=$(ls /dev/fb* 2>/dev/null | tr '\n' ' ')
DRI_DEV=$(ls /dev/dri/* 2>/dev/null | tr '\n' ' ')
MALI_DEV=$(ls /dev/mali* 2>/dev/null | tr '\n' ' ')
NTK_DEV=$(ls /dev/ntk* 2>/dev/null | tr '\n' ' ')
HWC_DEV=$(ls /dev/hwc* /dev/s3c* 2>/dev/null | tr '\n' ' ')

# ---------------------------------------------------------------------------
# print
# ---------------------------------------------------------------------------
say "==================================================================="
say " Tizen capability probe — how can Android run on THIS device"
say "==================================================================="

hdr "identity"
say "id          : $ID_UID"
say "uid         : $ID_UID_N"
say "kernel      : $KREL"
say "build       : $KVER"
say "arch        : $MACH"

hdr "kernel command line (leaks RAM map)"
say "${CMDLINE:-unavailable}"

hdr "Android kernel interfaces (the hard gate)"
say "CONFIG_ANDROID_BINDER_IPC : $BINDER        <- Android IPC"
say "CONFIG_ASHMEM             : $ASHMEM        <- Android shared memory"
say "live /dev/binder          : $LIVE_BINDER"
say "live /dev/ashmem          : $LIVE_ASHMEM"
if [ "$BINDER" = "y" ] || [ "$BINDER" = "m" ] || [ "$LIVE_BINDER" != "ABSENT" ]; then
  say "  -> binder is PRESENT on this kernel"
elif [ "$BINDER" = "UNKNOWN" ] && [ "$LIVE_BINDER" = "ABSENT" ]; then
  say "  -> no /dev/binder and no config file: binder likely ABSENT."
  say "     On a hardened TV this is the expected reading — confirm by modprobe."
else
  say "  -> binder is ABSENT; must be built as a module against this kernel"
fi

hdr "container support (Tier 1)"
say "CONFIG_NAMESPACES         : $NS"
say "CONFIG_UTS_NS             : $UTSNS"
say "CONFIG_USER_NS            : $USERNS"
say "CONFIG_PID_NS             : $PIDNS"
say "CONFIG_NET_NS             : $NETNS"
say "CONFIG_CGROUPS            : $CGROUPS"
say "CONFIG_OVERLAY_FS         : $OVERLAY        <- overlay a read-only rootfs"
say ""
say "LIVE namespace probe (authoritative when config is unreadable):"
say "  /proc/self/ns/mnt   : $LIVE_NS"
say "  /proc/self/ns/user  : $LIVE_USERNS"
say "  /proc/self/ns/pid   : $LIVE_PIDNS"
say "  /proc/self/ns/net   : $LIVE_NETNS"
say "  cgroup controllers  : $LIVE_CGROUPS"

hdr "module loading (to add binder/ashmem)"
say "CONFIG_MODULES            : $MODULES"
say "modules_disabled          : ${MODVERSION:-unknown}   (1 = loading forbidden)"
say "loaded modules:"
if [ -r /proc/modules ]; then
  if [ -s /proc/modules ]; then
    awk '{printf "  %s  %s bytes  used by %s\n", $1, $2, $4}' /proc/modules 2>/dev/null | head -40
  else
    say "  (none loaded — everything is built in)"
  fi
else
  say "  /proc/modules unavailable"
fi
say "module dirs:"
for d in /lib/modules/*/; do
  [ -d "$d" ] && say "  $d"
done
[ -d /lib/modules ] || say "  (no /lib/modules — cannot load out-of-tree modules)"

hdr "alternative boot paths (Tier 3 — expected closed)"
say "CONFIG_KEXEC              : $KEXEC"
say "CONFIG_KEXEC_FILE         : $KEXEC_FILE"
say "CONFIG_KVM                : $KVM"

hdr "display interfaces"
say "/dev/fb*    : ${FB_DEV:-none}"
say "/dev/dri/*  : ${DRI_DEV:-none}"
say "/dev/mali*  : ${MALI_DEV:-none}"
say "/dev/ntk*   : ${NTK_DEV:-none}   (Samsung proprietary media/display)"
say "/dev/hwc*   : ${HWC_DEV:-none}"
if [ -z "$FB_DEV$DRI_DEV" ] && [ -n "$NTK_DEV" ]; then
  say "  -> NO standard framebuffer or DRM. Panel is reachable only through the"
  say "     vendor NTK stack. This is why Tier 3 cannot show a picture."
fi

hdr "mounted filesystems and writability"
if [ -r /proc/mounts ]; then
  awk '{printf "  %-28s %-10s %s\n", $2, $3, $4}' /proc/mounts 2>/dev/null | head -30
fi
say ""
say "writability test:"
for d in / /tmp /opt /opt/usr /home /home/owner /mnt /var /run /media /mnt/opt/usr; do
  if [ -d "$d" ]; then
    if writable "$d"; then say "  WRITABLE   $d"; else say "  read-only  $d"; fi
  fi
done

hdr "available filesystems (for overlayfs)"
if [ -r /proc/filesystems ]; then
  tr '\n' ' ' < /proc/filesystems 2>/dev/null | sed 's/  */ /g'
  say ""
fi
for fs in overlay squashfs ext4 squashfs tmpfs fuse; do
  if fstype_available "$fs"; then say "  supported: $fs"; fi
done

hdr "memory (Android needs headroom)"
if [ -r /proc/meminfo ]; then
  grep -E '^(MemTotal|MemFree|MemAvailable|SwapTotal|SwapFree|Buffers|Cached)' \
    /proc/meminfo 2>/dev/null | sed 's/^/  /'
fi

hdr "storage"
df -h 2>/dev/null | head -15 | sed 's/^/  /'

hdr "security module (can root escape the sandbox?)"
if [ -r /sys/fs/selinux/enforce ]; then
  say "SELinux: enforcing=$(cat /sys/fs/selinux/enforce 2>/dev/null)"
else
  say "SELinux: not present"
fi
if [ -d /sys/fs/smack ] || [ -r /proc/self/attr/current ]; then
  say "SMACK current label: $(cat /proc/self/attr/current 2>/dev/null)"
fi

hdr "init / autostart (Tier 1 persistence)"
if have systemctl; then
  say "init: systemd present"
elif [ -d /etc/systemd/system ]; then
  say "init: systemd unit dirs exist"
elif [ -r /etc/init.d ]; then
  say "init: sysvinit"
else
  say "init: unknown — check PID 1"
fi
[ -r /proc/1/comm ] && say "PID 1 is: $(cat /proc/1/comm 2>/dev/null)"

hdr "dangerous vendor interfaces (already known from public research)"
for n in /dev/ntksys /dev/ntkhdma /dev/ntkxdma; do
  if [ -e "$n" ]; then
    say "  $(ls -l "$n" 2>/dev/null)"
  fi
done

# ---------------------------------------------------------------------------
# verdict
# ---------------------------------------------------------------------------
hdr "VERDICT"

tier1_needed=0
tier1_have=0

# prefer the config symbol when readable; otherwise trust the live probe
ns_ok=$NS
[ "$ns_ok" = "UNKNOWN" ] && ns_ok=$LIVE_NS

if [ "$CGROUPS" = "UNKNOWN" ]; then
  if [ "$LIVE_CGROUPS" = "n" ]; then cg_ok=n; else cg_ok=y; fi
else
  cg_ok=$CGROUPS
fi

ov_ok=$OVERLAY
if [ "$ov_ok" = "UNKNOWN" ]; then
  if fstype_available overlay; then ov_ok=y; else ov_ok=n; fi
fi

[ "$ns_ok" = "y" ] && tier1_have=$((tier1_have+1))
tier1_needed=$((tier1_needed+1))
[ "$cg_ok" = "y" ] && tier1_have=$((tier1_have+1))
tier1_needed=$((tier1_needed+1))
[ "$ov_ok" = "y" ] && tier1_have=$((tier1_have+1))
tier1_needed=$((tier1_needed+1))

if [ "$BINDER" = "y" ]; then binder_state="built in"
elif [ "$BINDER" = "m" ]; then binder_state="module"
elif [ "$LIVE_BINDER" != "ABSENT" ]; then binder_state="$LIVE_BINDER"
elif [ "$BINDER" = "UNKNOWN" ]; then binder_state="not found (config unreadable)"
else binder_state="absent"; fi

say "Tier 1 (runtime modification, Tizen keeps the panel):"
say "  namespaces/cgroups/overlay: ${tier1_have}/${tier1_needed} present"
say "  binder: ${binder_state}"
if [ "$MODULES" != "y" ] && [ "$binder_state" = "absent" ]; then
  say "  -> modules are off and binder is missing: not viable without a kernel rebuild"
elif [ "$binder_state" = "absent" ] && [ ! -d /lib/modules ]; then
  say "  -> binder missing and no module tree on device: would need headers + matching build"
else
  say "  -> VIABLE IN PRINCIPLE. Next: get root, then add binder/ashmem, then a"
  say "     container that renders off-screen while Tizen presents the frames."
fi
say ""
say "Tier 2 (signed .tpk app in Developer Mode):"
say "  always available; reach is limited to Tizen app APIs. No root needed."
say ""
say "Tier 3 (replace the OS in flash):"
say "  CLOSED. Per-section RSA signatures on boot-critical firmware."
say "  Nothing in this probe reopens it."

say ""
say "==================================================================="
say " probe complete"
say "==================================================================="

# ---------------------------------------------------------------------------
# emit
# ---------------------------------------------------------------------------
if [ -n "$SAVE" ] && [ -n "$REPORT" ]; then
  cp "$REPORT" "$SAVE" 2>/dev/null && say "saved: $SAVE"
elif [ -n "$SAVE" ]; then
  say "cannot save: no writable temp file on this device"
fi

if [ "$JSON" = "1" ]; then
  cat <<EOF
{
  "uid": "$ID_UID_N",
  "kernel": "$KREL",
  "arch": "$MACH",
  "binder": "$BINDER",
  "binder_live": "$LIVE_BINDER",
  "ashmem": "$ASHMEM",
  "namespaces": "$NS",
  "namespaces_live": "$LIVE_NS",
  "cgroups": "$CGROUPS",
  "cgroups_live": "$LIVE_CGROUPS",
  "overlayfs": "$OVERLAY",
  "modules": "$MODULES",
  "kexec": "$KEXEC",
  "kvm": "$KVM",
  "fb_devices": "${FB_DEV}",
  "drm_devices": "${DRI_DEV}",
  "mali_devices": "${MALI_DEV}",
  "ntk_devices": "${NTK_DEV}",
  "tier1_score": "${tier1_have}/${tier1_needed}",
  "tier3_reflash": "closed"
}
EOF
fi

if [ -n "$REPORT" ]; then
  # emit to the real stdout (fd 3), not the report file
  cat "$REPORT" >&3
  rm -f "$REPORT"
else
  :
fi
