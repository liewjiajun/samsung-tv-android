#!/bin/bash
# armrun.sh — run an arbitrary shell script inside the emulated armv7 guest.
#
# WHY
# ---
# The armv7 lane is only useful if testing new things is cheap. This stages a
# script plus any ARM binaries into a throwaway initramfs, boots the guest, runs
# the script, prints output, and halts. Each run is isolated; nothing persists.
#
# This is how ARM behaviour gets proven before any of it goes near a TV.
#
# USAGE
#   ./armrun.sh <script.sh> [file-to-stage ...]
#
# Staged files land in /stage/ inside the guest. The script runs as PID 1's
# child with /proc, /sys, /dev mounted.

set -uo pipefail
cd "$(dirname "$0")" || exit 1

SCRIPT="${1:-}"
shift || true
EXTRA=("$@")

[ -n "$SCRIPT" ] || { echo "usage: $0 <script.sh> [files...]" >&2; exit 2; }
[ -f "$SCRIPT" ] || { echo "error: no such script: $SCRIPT" >&2; exit 2; }
[ -s vmlinuz ] && [ -s initrd.gz ] || { echo "error: run ./tvvm.sh fetch first" >&2; exit 2; }
command -v qemu-system-arm >/dev/null || { echo "error: no qemu-system-arm" >&2; exit 2; }

WORK=$(mktemp -d /tmp/armrun.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

echo "== staging =="
( cd "$WORK" && zcat "$OLDPWD/initrd.gz" | cpio -idm --quiet 2>/dev/null )
# mknod warnings are expected (need root); verify what we need instead
for p in bin/busybox init; do
  [ -e "$WORK/$p" ] || { echo "error: extract incomplete ($p missing)" >&2; exit 1; }
done

mkdir -p "$WORK/stage"
cp "$SCRIPT" "$WORK/stage/run.sh"
chmod +x "$WORK/stage/run.sh"
for f in "${EXTRA[@]:-}"; do
  [ -n "$f" ] || continue
  [ -f "$f" ] || { echo "error: missing file: $f" >&2; exit 1; }
  cp "$f" "$WORK/stage/$(basename "$f")"
  chmod +x "$WORK/stage/$(basename "$f")"
  echo "  staged $(basename "$f") ($(stat -c%s "$f") bytes)"
done
echo "  staged run.sh"

cat > "$WORK/init" <<'INIT'
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/stage
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t sysfs sys /sys 2>/dev/null
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
mkdir -p /tmp
/bin/busybox mount -t tmpfs tmp /tmp 2>/dev/null

echo "=== GUEST READY ($(/bin/busybox uname -m)) ==="
/bin/sh /stage/run.sh
echo "=== GUEST DONE (rc=$?) ==="
/bin/busybox poweroff -f 2>/dev/null || /bin/busybox halt -f
INIT
chmod +x "$WORK/init"

( cd "$WORK" && find . -print0 | cpio --null -o --format=newc --quiet 2>/dev/null \
    | gzip -1 > "$WORK/test-initrd.gz" ) || { echo "error: repack failed" >&2; exit 1; }

echo "== booting armv7 =="
timeout 240 qemu-system-arm \
  -M virt -cpu cortex-a15 -m 512 -smp 2 -nographic \
  -kernel vmlinuz -initrd "$WORK/test-initrd.gz" \
  -append "console=ttyAMA0 panic=1 quiet" \
  < /dev/null 2>&1 | sed -n '/GUEST READY/,$p'
