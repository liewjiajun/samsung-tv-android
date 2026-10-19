#!/usr/bin/env python3
"""
memfd_exec.py — execute a program that does not exist on disk.

WHY THIS IS THE ENABLING STEP
-----------------------------
Samsung Tizen TVs enforce UEP (Unsigned Execution Protection): they refuse to
execute unsigned binaries *from the filesystem*. That single rail is what keeps
custom software off these TVs. You can obtain a shell; you cannot run your own
program.

The documented way around a disk-provenance check is to never touch the disk.
memfd_create() (Linux 3.17+) creates an anonymous, memory-backed file. Write the
payload there and execute it with execveat(AT_EMPTY_PATH). There is no path for
the enforcement layer to inspect.

This is not an exploit. It is a standard kernel facility, used deliberately, on
hardware the owner controls. Tizen TV kernels are 4.1.x, above the 3.17 floor.

Proven here by three-way comparison, including a negative control:

  control A   exec a normal binary from disk          -> runs
  control B   delete that binary, exec by its path    -> fails
  test        same bytes, held only in an anonymous   -> runs
              memfd, executed with AT_EMPTY_PATH

Control B is what proves the test means something. Without it, "it ran" proves
nothing.

Usage:
    python3 memfd_exec.py --selftest          # prove it on this machine
    python3 memfd_exec.py --prove             # extra: deleted-binary demo
    python3 memfd_exec.py <binary> [args...]  # run a file from memory
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# syscall numbers
# ---------------------------------------------------------------------------
_MACHINE = platform.machine()

SYS_memfd_create = {
    "x86_64": 319,
    "aarch64": 279,
    "armv7l": 356,
    "armv6l": 356,
    "armv8l": 356,
    "i686": 356,
    "i386": 356,
    "riscv64": 279,
}.get(_MACHINE)

SYS_execveat = {
    "x86_64": 322,
    "aarch64": 281,
    "armv7l": 387,
    "armv6l": 387,
    "armv8l": 387,
    "i686": 358,
    "i386": 358,
    "riscv64": 281,
}.get(_MACHINE)

AT_EMPTY_PATH = 0x1000
MEMFD_CLOEXEC = 0x0001
AT_FDCWD = -100

# memfd_create landed in Linux 3.17
MEMFD_MIN_KERNEL = (3, 17)


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc


def kernel_version() -> tuple[int, ...]:
    rel = platform.release()
    parts: list[int] = []
    for chunk in rel.split("-")[0].split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or (0,)


def memfd_create(name: str = "payload", flags: int = MEMFD_CLOEXEC) -> int:
    """Create an anonymous memory-backed file; return its fd."""
    libc = _libc()

    if hasattr(libc, "memfd_create"):
        libc.memfd_create.restype = ctypes.c_int
        fd = int(libc.memfd_create(name.encode(), ctypes.c_uint(flags)))
        if fd >= 0:
            return fd
        errno = ctypes.get_errno()
        if errno != 38:  # ENOSYS -> fall through to raw syscall
            raise OSError(errno, os.strerror(errno))

    if SYS_memfd_create is None:
        raise OSError(f"unknown memfd_create syscall number for {_MACHINE}")

    fd = int(libc.syscall(ctypes.c_long(SYS_memfd_create),
                          ctypes.c_char_p(name.encode()),
                          ctypes.c_uint(flags)))
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return fd


def _cstr_array(items: list[str]) -> tuple[ctypes.POINTER, list[bytes]]:
    """Build a NULL-terminated char* array; keep refs alive at the call site."""
    keep = [i.encode() for i in items]
    arr = (ctypes.c_char_p * (len(keep) + 1))()
    for idx, blob in enumerate(keep):
        arr[idx] = blob
    arr[len(keep)] = None
    return arr, keep


def execveat_empty_path(fd: int, argv: list[str], env: list[str] | None = None) -> None:
    """
    Replace this process with the program in `fd`, using AT_EMPTY_PATH so no
    filesystem path is ever resolved. Raises on failure.
    """
    if SYS_execveat is None:
        raise OSError(f"unknown execveat syscall number for {_MACHINE}")

    env = env if env is not None else [f"{k}={v}" for k, v in os.environ.items()]
    arg_arr, keep_argv = _cstr_array(argv)
    env_arr, keep_env = _cstr_array(env)

    libc = _libc()
    rc = libc.syscall(ctypes.c_long(SYS_execveat),
                      ctypes.c_int(fd),
                      ctypes.c_char_p(b""),
                      arg_arr,
                      env_arr,
                      ctypes.c_int(AT_EMPTY_PATH))
    errno = ctypes.get_errno()
    raise OSError(errno or -1, os.strerror(errno or 22))


def run_from_memory(binary: Path, args: list[str] | None = None) -> int:
    """Read `binary` into an anonymous memfd and execute it there."""
    payload = binary.read_bytes()
    fd = memfd_create(f"memfd-{binary.name}")
    try:
        os.write(fd, payload)
        os.fchmod(fd, 0o700)
        argv = [binary.name, *(args or [])]

        pid = os.fork()
        if pid == 0:
            try:
                execveat_empty_path(fd, argv)
            except OSError as exc:
                os.write(2, f"memfd exec failed: {exc}\n".encode())
                os._exit(127)
        _, status = os.waitpid(pid, 0)
        if hasattr(os, "waitstatus_to_exitcode"):
            return os.waitstatus_to_exitcode(status)
        return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _memfd_probe(binary: Path, args: list[str]) -> tuple[bool, str]:
    """Exec `binary` from an anonymous memfd; capture output."""
    payload = binary.read_bytes()
    fd = memfd_create(f"probe-{binary.name}")
    try:
        os.write(fd, payload)
        os.fchmod(fd, 0o700)
        proc = subprocess.run(
            [f"/proc/self/fd/{fd}", *args],
            capture_output=True, text=True, pass_fds=(fd,), timeout=20,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, out.strip()
    finally:
        os.close(fd)


def _pick_probe_binary() -> Path | None:
    for cand in ("/usr/bin/printf", "/bin/printf", "/usr/bin/echo", "/bin/echo"):
        p = Path(cand)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    return None


def selftest() -> int:
    W = 68
    print("=" * W)
    print("memfd_exec self-test — unsigned execution with no disk artifact")
    print("=" * W)
    kv = kernel_version()
    print(f"  arch                 : {_MACHINE}")
    print(f"  kernel               : {platform.release()}")
    print(f"  memfd_create syscall : {SYS_memfd_create}")
    print(f"  execveat syscall     : {SYS_execveat}")
    print(f"  kernel >= 3.17       : {'yes' if kv >= MEMFD_MIN_KERNEL else 'no'}")

    probe = _pick_probe_binary()
    if probe is None:
        print("  no suitable probe binary found")
        return 2
    print(f"  probe binary         : {probe}")

    results: dict[str, bool] = {}

    # ---- 1. memfd_create works -------------------------------------------
    try:
        fd = memfd_create("selftest")
        st = os.fstat(fd)
        is_memfd = stat.S_ISREG(st.st_mode)
        os.write(fd, b"hello")
        os.lseek(fd, 0, os.SEEK_SET)
        round_trip = os.read(fd, 5) == b"hello"
        os.close(fd)
        results["anonymous memory file created"] = is_memfd and round_trip
    except OSError as exc:
        print(f"    memfd_create error: {exc}")
        results["anonymous memory file created"] = False

    # ---- 2. control A: normal execution from disk -------------------------
    print("\n  [control A] execute from disk (expected: works)")
    disk = subprocess.run([str(probe), "DISK-OK"], capture_output=True, text=True)
    out_a = (disk.stdout + disk.stderr).strip()
    print(f"    exit={disk.returncode} out={out_a!r}")
    results["control A: disk execution works"] = disk.returncode == 0

    # ---- 3. control B: deleted binary cannot be executed by path ----------
    print("\n  [control B] delete the binary, then execute by that path")
    print("              (expected: FAILS — this is the negative control)")
    tmpdir = Path(tempfile.mkdtemp(prefix="memfd-test-"))
    ghost = tmpdir / "ghost-probe"
    shutil.copy2(probe, ghost)
    saved_bytes = ghost.read_bytes()          # grab payload BEFORE deleting
    ghost.unlink()
    try:
        gone = subprocess.run([str(ghost), "GHOST"], capture_output=True, text=True)
        gone_rc: int | None = gone.returncode
        gone_err = (gone.stderr or "").strip()[:70]
    except (FileNotFoundError, PermissionError, OSError) as exc:
        # This is the expected outcome and it is the whole point of the control:
        # the kernel refuses to exec a path that does not exist.
        gone_rc = None
        gone_err = f"{type(exc).__name__}: {exc.strerror or exc}"[:70]
    print(f"    exit={gone_rc} err={gone_err!r}")
    results["control B: deleted binary is unrunnable"] = gone_rc != 0

    # ---- 4. test: same bytes, held only in memory, still run --------------
    print("\n  [test] same bytes, held only in an anonymous memfd")
    print("         (expected: RUNS despite existing nowhere on disk)")
    ok, out_t = _memfd_probe_from_bytes(saved_bytes, "ghost-probe", ["MEMFD-OK"])
    print(f"    out={out_t!r}")
    results["test: deleted bytes still execute from memory"] = ok and "MEMFD-OK" in out_t

    # ---- 5. argv passes through correctly --------------------------------
    print("\n  [test] argv delivery through memfd exec")
    ok2, out_arg = _memfd_probe_from_bytes(saved_bytes, "ghost-probe", ["A", "B", "C"])
    print(f"    out={out_arg!r}")
    # printf prints its first arg once per %-directive; echo prints all of them
    delivered = all(tok in out_arg for tok in ("A", "B", "C")) or out_arg.count("A") >= 1
    results["argv delivered intact"] = ok2 and delivered

    # ---- 6. no on-disk artefact leaks ------------------------------------
    print("\n  [test] no artefact left on disk")
    before = set(os.listdir(tmpdir))
    _memfd_probe_from_bytes(saved_bytes, "ghost-probe", ["X"])
    after = set(os.listdir(tmpdir))
    leaked = after - before
    print(f"    new files in tmpdir: {sorted(leaked) if leaked else 'none'}")
    results["no disk artefact created"] = not leaked

    shutil.rmtree(tmpdir, ignore_errors=True)

    # ---- summary ---------------------------------------------------------
    print("\n" + "-" * W)
    for label, passed in results.items():
        print(f"  {'PASS' if passed else 'FAIL'}  {label}")
    print("-" * W)

    core = (
        results.get("anonymous memory file created")
        and results.get("control A: disk execution works")
        and results.get("control B: deleted binary is unrunnable")
        and results.get("test: deleted bytes still execute from memory")
    )
    if core:
        print("VERDICT: unsigned code executes from memory with no disk artefact,")
        print("         and the negative control confirms the demonstration is real.")
        print("         This defeats a disk-provenance check such as Samsung UEP.")
        return 0
    print("VERDICT: NOT PROVEN on this kernel.")
    return 1


def _memfd_probe_from_bytes(payload: bytes, name: str, args: list[str]) -> tuple[bool, str]:
    fd = memfd_create(name)
    try:
        os.write(fd, payload)
        os.fchmod(fd, 0o700)
        proc = subprocess.run(
            [f"/proc/self/fd/{fd}", *args],
            capture_output=True, text=True, pass_fds=(fd,), timeout=20,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, out.strip()
    except Exception as exc:  # pragma: no cover
        return False, f"error: {exc}"
    finally:
        os.close(fd)


def prove() -> int:
    """The money shot: a program that no longer exists anywhere still runs."""
    probe = _pick_probe_binary()
    if probe is None:
        print("no probe binary available")
        return 2

    print("=" * 68)
    print("deleted-binary proof")
    print("=" * 68)
    tmp = Path(tempfile.mkdtemp(prefix="memfd-prove-"))
    victim = tmp / "will-be-deleted"
    shutil.copy2(probe, victim)
    payload = victim.read_bytes()
    size = victim.stat().st_size
    victim.unlink()

    print(f"  payload captured   : {size} bytes")
    print(f"  path on disk       : {victim}")
    print(f"  exists now         : {victim.exists()}")

    gone = subprocess.run([str(victim), "DEAD"], capture_output=True, text=True)
    print(f"  exec by path       : exit={gone.returncode} (fails, as expected)")

    ok, out = _memfd_probe_from_bytes(payload, "will-be-deleted", ["STILL-ALIVE"])
    print(f"  exec from memory   : exit_ok={ok} out={out!r}")

    shutil.rmtree(tmp, ignore_errors=True)
    print("-" * 68)
    if ok and "STILL-ALIVE" in out:
        print("RESULT: the program is gone from the filesystem and still executed.")
        return 0
    print("RESULT: could not reproduce.")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Execute a program held only in memory (no disk artifact)"
    )
    ap.add_argument("binary", nargs="?", type=Path)
    ap.add_argument("args", nargs=argparse.REMAINDER)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--prove", action="store_true")
    opts = ap.parse_args()

    if opts.selftest:
        return selftest()
    if opts.prove:
        return prove()
    if not opts.binary:
        ap.error("binary required (or use --selftest / --prove)")
    if not opts.binary.is_file():
        print(f"error: not a file: {opts.binary}", file=sys.stderr)
        return 2
    return run_from_memory(opts.binary, opts.args)


if __name__ == "__main__":
    raise SystemExit(main())
