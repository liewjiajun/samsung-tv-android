#!/bin/bash
# tvvm.sh — build and run the offline armv7 test lane.
#
# WHY THIS EXISTS
# ---------------
# JJ will not test on the real TV yet (brick worry, 2026-10-19). That is the
# correct call. This lane is the substitute: an emulated 32-bit ARM Linux that
# matches the TV's architecture, so tooling is exercised off-device.
#
# WHAT IT TESTS / WHAT IT CANNOT
#   CAN validate: shell portability, /proc parsing, the probe's own logic,
#                 behaviour when kernel config files are absent.
#   CANNOT validate: NTK display, SMACK policy, Samsung kernel specifics,
#                 anything vendor-specific. A green run here is NOT a verdict
#                 about the TV.
#
# USAGE
#   ./tvvm.sh fetch          # download kernel + initramfs (once)
#   ./tvvm.sh build          # repack initramfs with the probe baked in
#   ./tvvm.sh run            # boot and print the probe report
#   ./tvvm.sh shell          # interactive armv7 shell
#   ./tvvm.sh clean          # remove build artifacts (keeps downloads)

set -uo pipefail
cd "$(dirname "$0")" || exit 1

BASE_URL="https://deb.debian.org/debian/dists/stable/main/installer-armhf/current/images/netboot"
KERNEL="vmlinuz"
INITRD="initrd.gz"
PACKED="initrd-probe.gz"
IRD="irdir"
PROBE="../toolkit/tizen-capability-probe.sh"

MEM_MB=512
CPUS=2

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need_qemu() {
  command -v qemu-system-arm >/dev/null 2>&1 || \
    die "qemu-system-arm not installed (pacman -S qemu-system-arm)"
}

cmd_fetch() {
  echo "== fetching armv7 kernel + initramfs =="
  for f in "$KERNEL" "$INITRD"; do
    if [ -s "$f" ]; then
      echo "  have $f ($(stat -c%s "$f") bytes)"
      continue
    fi
    echo "  downloading $f ..."
    curl -fsSL -o "$f" "$BASE_URL/$f" || die "download failed: $f"
    echo "  got $f ($(stat -c%s "$f") bytes)"
  done
  file "$KERNEL" 2>/dev/null | grep -qi arm || \
    echo "  WARNING: kernel does not look like ARM — verify before trusting results"
}

cmd_build() {
  [ -s "$KERNEL" ] && [ -s "$INITRD" ] || die "run './tvvm.sh fetch' first"
  [ -f "$PROBE" ] || die "probe not found at $PROBE"

  echo "== rebuilding initramfs with the probe baked in =="
  rm -rf "$IRD"; mkdir -p "$IRD"

  # cpio exits non-zero on 'Cannot mknod' for dev/console and dev/null, because
  # creating device nodes needs root. That is expected and harmless: the guest
  # mounts devtmpfs over /dev anyway. So do NOT trust cpio's exit code — verify
  # the extraction by checking the paths we actually need.
  ( cd "$IRD" && zcat "../$INITRD" | cpio -idm --quiet 2>/dev/null )

  for p in init bin/busybox bin/sh; do
    [ -e "$IRD/$p" ] || die "extract incomplete: missing $p"
  done
  echo "  extracted $(find "$IRD" | wc -l) entries (mknod warnings expected, ignored)"

  mkdir -p "$IRD/probe"
  cp "$PROBE" "$IRD/probe/run.sh"
  chmod +x "$IRD/probe/run.sh"

  cat > "$IRD/init" <<'INIT'
#!/bin/sh
# Runs the probe at boot, then halts. No interactive shell needed.
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t sysfs sys /sys 2>/dev/null
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
/bin/busybox mkdir -p /tmp
/bin/busybox mount -t tmpfs tmp /tmp 2>/dev/null

echo "=== GUEST READY ==="
/bin/busybox uname -m

if [ -f /probe/run.sh ]; then
  /bin/sh /probe/run.sh
else
  echo "PROBE MISSING"
fi

echo "=== GUEST DONE ==="
/bin/busybox poweroff -f 2>/dev/null || /bin/busybox halt -f
INIT
  chmod +x "$IRD/init"

  ( cd "$IRD" && find . -print0 | cpio --null -o --format=newc --quiet 2>/dev/null \
      | gzip -9 > "../$PACKED" ) || die "repack failed"

  echo "  packed $PACKED ($(stat -c%s "$PACKED") bytes)"
  echo "  guest busybox arch: $(file "$IRD/bin/busybox" 2>/dev/null | grep -o 'ARM[^,]*' | head -1)"
}

cmd_run() {
  need_qemu
  [ -s "$PACKED" ] || die "run './tvvm.sh build' first"
  echo "== booting armv7 guest =="
  timeout 220 qemu-system-arm \
    -M virt -cpu cortex-a15 -m "$MEM_MB" -smp "$CPUS" -nographic \
    -kernel "$KERNEL" -initrd "$PACKED" \
    -append "console=ttyAMA0 panic=1 quiet" \
    < /dev/null 2>&1 | sed -n '/GUEST READY/,$p'
}

cmd_shell() {
  need_qemu
  [ -s "$KERNEL" ] && [ -s "$INITRD" ] || die "run './tvvm.sh fetch' first"
  echo "== interactive armv7 shell (exit to leave) =="
  exec qemu-system-arm \
    -M virt -cpu cortex-a15 -m "$MEM_MB" -smp "$CPUS" -nographic \
    -kernel "$KERNEL" -initrd "$INITRD" \
    -append "console=ttyAMA0 rdinit=/bin/sh panic=1 quiet"
}

cmd_clean() {
  echo "== cleaning build artifacts (downloads kept) =="
  rm -rf "$IRD" "$PACKED"
  echo "  done"
}

case "${1:-run}" in
  fetch) cmd_fetch ;;
  build) cmd_build ;;
  run)   cmd_run ;;
  shell) cmd_shell ;;
  clean) cmd_clean ;;
  *)     die "unknown command: $1 (fetch|build|run|shell|clean)" ;;
esac
