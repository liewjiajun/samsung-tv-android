#!/bin/sh
# uep-analogue-test.sh — prove memfd+execveat defeats a kernel-side, path-based
# exec denial, running on real armv7.
#
# WHY THIS MATTERS
# ----------------
# Samsung's UEP is a kernel-side check applied to the FILE being executed,
# performed during execve, that applies even at uid 0. We cannot reproduce UEP
# itself off-device. But we CAN reproduce its essential character: a kernel
# refusal to execute a particular file based on its path/provenance, which
# returns EACCES from execve regardless of privilege.
#
# A `noexec` mount is precisely that. The kernel refuses to execve a file by
# path. It does not care that we are root.
#
# If memfd+execveat runs those same bytes successfully while the direct exec is
# refused, then the mechanism we intend to use on the TV is sound: the check
# operates on a path, and the technique resolves no path.
#
# This is the difference between believing the bypass works and having watched
# it work.

set -u
FAIL=0
say() { printf '%s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL+1)); }

say "=== UEP-analogue: kernel path-based exec denial vs memfd ==="
say "kernel: $(uname -r)  arch: $(uname -m)  uid: $(id -u)"
say ""

# ---------------------------------------------------------------------------
# Build the denial: a noexec mount
# ---------------------------------------------------------------------------
say "[setup] tmpfs mounted noexec"
/bin/busybox mkdir -p /mnt/noexec
if ! /bin/busybox mount -t tmpfs -o noexec tmpfs /mnt/noexec 2>/dev/null; then
  bad "could not create noexec mount"
  exit 1
fi
if ! /bin/busybox grep -q 'noexec' /proc/mounts; then
  bad "noexec not visible in /proc/mounts"
  exit 1
fi
ok "noexec mount active"

# Put a real, working binary on it
if ! /bin/busybox cp /bin/busybox /mnt/noexec/busybox 2>/dev/null; then
  bad "could not stage binary"
  exit 1
fi
/bin/busybox chmod 755 /mnt/noexec/busybox
ok "binary staged at /mnt/noexec/busybox ($(/bin/busybox stat -c%s /mnt/noexec/busybox) bytes)"

# ---------------------------------------------------------------------------
# CONTROL A: the binary works from an executable location
# ---------------------------------------------------------------------------
say ""
say "[control A] exec the same binary from an exec-allowed path"
OUT=$(/bin/busybox /bin/busybox echo CONTROL-A-OK 2>&1)
if [ "$OUT" = "CONTROL-A-OK" ]; then
  ok "binary itself is valid and runnable"
else
  bad "binary does not run even from an allowed path: $OUT"
fi

# ---------------------------------------------------------------------------
# CONTROL B (THE DENIAL): exec it from noexec. Must be refused.
# ---------------------------------------------------------------------------
say ""
say "[control B] exec from noexec — expecting kernel refusal"
OUT=$(/mnt/noexec/busybox echo SHOULD-NOT-APPEAR 2>&1)
RC=$?
if [ $RC -eq 0 ]; then
  bad "noexec NOT enforced — this test proves nothing, abort conclusions"
else
  ok "kernel refused execution by path (rc=$RC): $(printf '%s' "$OUT" | /bin/busybox head -c 80)"
fi
# rc must be a denial, not a crash
case "$RC" in
  126|127) ok "exit code $RC is an exec denial (not a signal)" ;;
  *)       say "  NOTE  exit code $RC" ;;
esac

# ---------------------------------------------------------------------------
# THE TEST: same bytes, staged in memfd, executed with AT_EMPTY_PATH
# ---------------------------------------------------------------------------
say ""
say "[test] same bytes via memfd_create + execveat(AT_EMPTY_PATH)"

if [ ! -x /stage/memfd_run ]; then
  bad "memfd_run not staged"
else
  OUT=$(/stage/memfd_run /mnt/noexec/busybox echo MEMFD-BYPASS-OK 2>&1)
  RC=$?
  say "  memfd_run rc=$RC"
  say "  output: $(printf '%s' "$OUT" | /bin/busybox tr '\n' '|')"
  case "$OUT" in
    *MEMFD-BYPASS-OK*)
      ok "executed a noexec file from memory — path check bypassed" ;;
    *)
      bad "memfd exec did not produce program output" ;;
  esac
fi

# ---------------------------------------------------------------------------
# Sharper: /proc/self/exe tells us the program saw NO real path
# ---------------------------------------------------------------------------
say ""
say "[verify] what path did the in-memory program see itself as?"
OUT=$(/stage/memfd_run /mnt/noexec/busybox sh -c 'readlink /proc/self/exe 2>/dev/null || echo "(no /proc/self/exe)"' 2>&1)
say "  /proc/self/exe -> $(printf '%s' "$OUT" | /bin/busybox tail -1)"

# ---------------------------------------------------------------------------
# Negative control: memfd of a NON-executable / corrupt payload must fail
# ---------------------------------------------------------------------------
say ""
say "[negative control] memfd must not turn garbage into a working program"
printf 'not an elf at all' > /tmp/garbage.bin
OUT=$(/stage/memfd_run /tmp/garbage.bin 2>&1)
RC=$?
if [ $RC -ne 0 ]; then
  ok "garbage payload refused (rc=$RC) — bypass is not indiscriminate"
else
  bad "garbage executed?! rc=0"
fi

say ""
say "======================================================"
if [ $FAIL -eq 0 ]; then
  say " RESULT: PASS — memfd defeats a kernel path-based exec denial"
  say " on real armv7, with both controls and a negative control."
else
  say " RESULT: FAIL ($FAIL failed checks)"
fi
say "======================================================"
exit $FAIL
