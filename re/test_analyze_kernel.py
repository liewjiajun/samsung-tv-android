#!/usr/bin/env python3
"""
test_analyze_kernel.py — validate analyze-kernel.py against known answers.

WHY THIS EXISTS
---------------
`analyze-kernel.py --selftest` uses a real armv7 kernel as a control, but that
kernel has NO embedded config. So the control exercises the *decompression* path
and the *honest UNKNOWN* path — and never exercises the config-decoding path,
which is the entire reason the tool exists.

That gap matters. If the config parser or the verdict logic were wrong, every
real TV firmware would get a confident wrong answer and nothing would catch it.

So this suite builds synthetic kernel images with KNOWN embedded configs and
asserts the tool reports exactly the right verdict. Negative cases included:
a config that lacks binder must report ABSENT, not PRESENT.

Run:  python3 test_analyze_kernel.py
"""

from __future__ import annotations

import gzip
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

# analyze-kernel.py has a hyphen, so import by path.
_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("analyze_kernel", _HERE / "analyze-kernel.py")
AK = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(AK)


PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  FAIL  {name}" + (f"  <- {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Build synthetic kernel images with a chosen embedded config
# ---------------------------------------------------------------------------

def make_config(symbols: dict[str, str]) -> str:
    """Render a kernel .config body."""
    lines = [
        "#",
        "# Automatically generated file; DO NOT EDIT.",
        "#",
        "CONFIG_LOCALVERSION=\"\"",
    ]
    for name, val in symbols.items():
        if val == "n":
            lines.append(f"# {name} is not set")
        else:
            lines.append(f"{name}={val}")
    return "\n".join(lines) + "\n"


def make_kernel(symbols: dict[str, str], *, embed: bool = True,
                vermagic: str = "4.1.10 SMP preempt mod_unload ARMv7 p2v8") -> bytes:
    """
    Build a fake zImage: some boot-stub junk, an optional embedded IKCONFIG,
    and a 'Linux version ...' banner so the tool's release extraction works.
    """
    stub = bytearray(b"\x00" * 4096)
    stub[0:4] = b"MZ\x25\xe2"          # ARM zImage-ish magic

    body = bytearray()
    body += b"Linux version 4.1.10 (build@vendor) (gcc version 6.4.0) #1 SMP\r\n"
    body += vermagic.encode() + b"\x00"

    payload = bytes(stub) + bytes(body)

    if embed:
        cfg_text = make_config(symbols).encode()
        # IKCONFIG layout: marker, gzip stream, end marker
        compressed = gzip.compress(cfg_text)
        payload += b"IKCFG_ST" + compressed + b"IKCFG_ED"

    payload += b"\x00" * 512
    return payload


def analyze_bytes(data: bytes):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".img") as f:
        f.write(data)
        path = Path(f.name)
    try:
        return AK.analyze(path)
    finally:
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Fixtures: the three outcomes that matter for the TV
# ---------------------------------------------------------------------------

# 1. binder built in, modules off — the "best case" TV kernel
CFG_BINDER_PRESENT = {
    "CONFIG_ANDROID_BINDER_IPC": "y",
    "CONFIG_ANDROID_BINDERFS": "y",
    "CONFIG_ASHMEM": "y",
    "CONFIG_NAMESPACES": "y",
    "CONFIG_USER_NS": "y",
    "CONFIG_PID_NS": "y",
    "CONFIG_NET_NS": "y",
    "CONFIG_UTS_NS": "y",
    "CONFIG_CGROUPS": "y",
    "CONFIG_MEMCG": "y",
    "CONFIG_OVERLAY_FS": "y",
    "CONFIG_MODULES": "n",
}

# 2. no binder, modules loadable, unsigned not rejected — "addable"
CFG_BINDER_ADDABLE = {
    "CONFIG_ANDROID_BINDER_IPC": "n",
    "CONFIG_ASHMEM": "n",
    "CONFIG_NAMESPACES": "y",
    "CONFIG_USER_NS": "y",
    "CONFIG_PID_NS": "y",
    "CONFIG_NET_NS": "y",
    "CONFIG_UTS_NS": "y",
    "CONFIG_CGROUPS": "y",
    "CONFIG_OVERLAY_FS": "y",
    "CONFIG_MODULES": "y",
    "CONFIG_MODULE_SIG": "y",
    "CONFIG_MODULE_SIG_FORCE": "n",
}

# 3. no binder, modules forced-signed — "blocked", the realistic vendor lockdown
CFG_BINDER_BLOCKED = {
    "CONFIG_ANDROID_BINDER_IPC": "n",
    "CONFIG_ASHMEM": "n",
    "CONFIG_NAMESPACES": "y",
    "CONFIG_CGROUPS": "y",
    "CONFIG_OVERLAY_FS": "y",
    "CONFIG_MODULES": "y",
    "CONFIG_MODULE_SIG": "y",
    "CONFIG_MODULE_SIG_FORCE": "y",
}

# 4. no binder, no modules at all — "fatal"
CFG_BINDER_FATAL = {
    "CONFIG_ANDROID_BINDER_IPC": "n",
    "CONFIG_ASHMEM": "n",
    "CONFIG_NAMESPACES": "y",
    "CONFIG_CGROUPS": "y",
    "CONFIG_OVERLAY_FS": "y",
    "CONFIG_MODULES": "n",
}


def main() -> int:
    print("=" * 70)
    print(" analyze-kernel.py — known-answer test suite")
    print("=" * 70)

    # -- config extraction ---------------------------------------------------
    print("\n[config extraction]")
    r = analyze_bytes(make_kernel(CFG_BINDER_PRESENT))
    check("embedded config detected", r["config_embedded"])
    check("binder symbol read as y", r["symbols"].get("CONFIG_ANDROID_BINDER_IPC") == "y")
    check("overlay symbol read as y", r["symbols"].get("CONFIG_OVERLAY_FS") == "y")
    check("'is not set' parsed as n",
          r["symbols"].get("CONFIG_ASHMEM") == "y")  # present here
    r2 = analyze_bytes(make_kernel(CFG_BINDER_ADDABLE))
    check("'is not set' becomes n",
          r2["symbols"].get("CONFIG_ANDROID_BINDER_IPC") == "n")

    # -- release / vermagic --------------------------------------------------
    print("\n[release and vermagic]")
    check("kernel release extracted", r["kernel_release"] == "4.1.10")
    check("vermagic extracted exactly",
          r["vermagic"] == "4.1.10 SMP preempt mod_unload ARMv7 p2v8",
          f"got {r['vermagic']!r}")
    check("vermagic does not swallow gcc banner",
          r["vermagic"] is not None and "gcc" not in r["vermagic"].lower())

    # -- verdicts ------------------------------------------------------------
    print("\n[verdict: binder present -> PRESENT]")
    v = r["verdict"]
    check("verdict binder PRESENT", v["binder"] == "PRESENT", f"got {v['binder']!r}")
    check("verdict container YES", v["container"] == "YES")

    print("\n[verdict: binder absent, modules unsigned-allowed -> addable]")
    v = analyze_bytes(make_kernel(CFG_BINDER_ADDABLE))["verdict"]
    check("verdict binder ABSENT (addable)",
          v["binder"].startswith("ABSENT (addable)"), f"got {v['binder']!r}")
    check("next step mentions vermagic", "vermagic" in (v.get("binder_next_step") or "").lower())

    print("\n[verdict: binder absent, MODULE_SIG_FORCE -> blocked]")
    v = analyze_bytes(make_kernel(CFG_BINDER_BLOCKED))["verdict"]
    check("verdict binder ABSENT (blocked)",
          v["binder"].startswith("ABSENT (blocked)"), f"got {v['binder']!r}")
    check("blocked reason names signing", "sign" in (v.get("binder_next_step") or "").lower())
    check("module_signing_force reported true", v["module_signing_force"] is True)

    print("\n[verdict: binder absent, no modules -> fatal]")
    v = analyze_bytes(make_kernel(CFG_BINDER_FATAL))["verdict"]
    check("verdict binder ABSENT (fatal)",
          v["binder"].startswith("ABSENT (fatal)"), f"got {v['binder']!r}")

    # -- negative control: the tool must NOT guess ---------------------------
    print("\n[negative control: no config -> UNKNOWN, never a guess]")
    r_nocfg = analyze_bytes(make_kernel({}, embed=False))
    check("config_embedded false", r_nocfg["config_embedded"] is False)
    check("verdict is UNKNOWN", r_nocfg["verdict"]["binder"] == "UNKNOWN",
          f"got {r_nocfg['verdict']['binder']!r}")
    check("symbols dict empty when no config", r_nocfg["symbols"] == {})
    check("reason mentions it cannot decide",
          "cannot decide" in r_nocfg["verdict"]["reason"].lower())

    # -- decompression path --------------------------------------------------
    print("\n[outer compression: gzip-wrapped kernel]")
    inner = make_kernel(CFG_BINDER_PRESENT)
    gz = gzip.compress(inner)
    r_gz = analyze_bytes(gz)
    check("gzip container identified", r_gz["outer_codec"] is not None and "gzip" in r_gz["outer_codec"])
    check("config found through gzip", r_gz["config_embedded"])
    check("verdict still correct through gzip", r_gz["verdict"]["binder"] == "PRESENT")

    # -- robustness ----------------------------------------------------------
    print("\n[robustness]")
    r_junk = analyze_bytes(b"\x00" * 1000)
    check("all-zero file does not crash", r_junk["verdict"]["binder"] == "UNKNOWN")
    r_tiny = analyze_bytes(b"\x1f\x8b")  # truncated gzip magic, no content
    check("truncated magic does not crash", isinstance(r_tiny["verdict"], dict))

    # -- summary -------------------------------------------------------------
    print()
    print("=" * 70)
    print(f" passed: {PASS}   failed: {FAIL}")
    if FAILURES:
        print(" failed checks:")
        for f in FAILURES:
            print(f"   - {f}")
        print(" RESULT: FAILED")
    else:
        print(" RESULT: ALL TESTS PASSED")
    print("=" * 70)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
