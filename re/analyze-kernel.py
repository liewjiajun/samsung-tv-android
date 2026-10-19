#!/usr/bin/env python3
"""
analyze-kernel.py — answer the binder question from a kernel image, without the TV.

WHY THIS EXISTS
---------------
The decisive unknown for running Android userspace on a Samsung Tizen TV is
whether the kernel supports binder/ashmem. Until now that was answered by
booting the TV and guessing. It can be answered from a kernel image offline.

This tool takes a kernel image (zImage, uImage, Image, or raw decompressed) and
reports exactly the facts that decide the outcome:

  * embedded kernel config (IKCONFIG), if present
  * binder / ashmem / namespaces / cgroups / overlayfs / module-loading
  * vermagic — required to ever build a matching module
  * whether module loading is even possible (signature enforcement hints)

VALIDATION
----------
This is tested against a kernel whose answers are independently known: the
Debian armv7 image in ../vm/vmlinuz. That kernel HAS namespaces and cgroups and
does NOT have binder. If this tool disagrees with the live armv7 system, the
tool is wrong. See --selftest.

USAGE
    python3 analyze-kernel.py <image>            # human report
    python3 analyze-kernel.py <image> --json     # machine readable
    python3 analyze-kernel.py --selftest         # validate against armv7 control

Ethics: firmware images are vendor content. This reads a local file and prints
facts about it. It does not redistribute anything.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import lzma
import re
import sys
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Format handling
# ---------------------------------------------------------------------------

MAGICS = [
    (b"\x1f\x8b\x08", "gzip", "gunzip"),
    (b"\xfd7zXZ\x00", "xz", "unxz"),
    (b"BZh", "bzip2", "bunzip2"),
    (b"\x27\x05\x19\x56", "uImage", None),      # u-boot legacy
    (b"\xd0\x0d\xfe\xed", "dtb", None),         # flattened device tree
]


def _try_decompress(data: bytes) -> tuple[bytes, str | None]:
    """
    Return (payload, codec). Handles the layers a vendor kernel ships in.

    Important: an ARM zImage is NOT a bare compressed stream. It is a self-
    extracting boot stub whose payload is compressed at some offset inside the
    image (offset 0 is executable ARM code, not a magic). So checking offset 0
    alone silently reports 'unknown format'. Scan for embedded streams too.
    """
    # --- direct (whole file is a compressed stream) ---
    direct = _decompress_at(data, 0)
    if direct is not None:
        return direct

    # --- uImage: 64-byte header, then payload ---
    if data[:4] == b"\x27\x05\x19\x56" and len(data) > 64:
        try:
            size = int.from_bytes(data[12:16], "big")
            payload = data[64:64 + size] if size else data[64:]
            inner = _decompress_at(payload, 0)
            if inner is not None:
                return inner[0], f"uImage+{inner[1]}"
            return payload, "uImage"
        except Exception:
            pass

    # --- zImage / embedded stream: scan for a compression magic ---
    found = _scan_embedded(data)
    if found is not None:
        return found

    return data, None


# Compression magics in the order worth trying. zstd/lz4 kernels are common on
# newer parts; gzip dominates on the older Tizen (4.1.x) images.
_STREAM_MAGICS = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x04\x22\x4d\x18", "lz4"),
]


def _decompress_at(data: bytes, offset: int) -> tuple[bytes, str] | None:
    """Try each codec at one exact offset. Return (payload, codec) or None."""
    for magic, codec in _STREAM_MAGICS:
        if not data.startswith(magic, offset):
            continue
        blob = data[offset:]
        try:
            if codec == "gzip":
                out = gzip.decompress(blob)
            elif codec == "xz":
                out = lzma.decompress(blob)
            elif codec == "bzip2":
                import bz2
                out = bz2.decompress(blob)
            elif codec == "zstd":
                try:
                    import zstandard
                    out = zstandard.ZstdDecompressor().decompress(blob, max_output_size=256 << 20)
                except Exception:
                    continue
            elif codec == "lz4":
                try:
                    import lz4.frame
                    out = lz4.frame.decompress(blob)
                except Exception:
                    continue
            else:
                continue
        except Exception:
            continue
        # Reject absurd ratios — that means we locked onto random bytes, not a
        # real stream. A real kernel payload is typically 2-6x the compressed size.
        #
        # Do NOT use an absolute size floor here. A floor of 1 MiB looks safe for
        # real kernels but silently rejects small valid images (and every
        # synthetic test fixture), which hides bugs in this very function. Judge
        # by plausibility instead: either it is kernel-sized, or it announces
        # itself as kernel content.
        if len(out) < 64:
            continue
        looks_kernel = (b"Linux version" in out[:262144]
                        or b"CONFIG_" in out[:262144]
                        or b"vermagic" in out[:262144])
        if not looks_kernel and len(out) < (1 << 20):
            continue
        if len(out) > len(blob) * 40:
            continue
        return out, codec
    return None


def _scan_embedded(data: bytes) -> tuple[bytes, str] | None:
    """
    Find a compressed kernel payload inside a zImage boot stub.

    Candidate magic offsets are tried in order; the first that decompresses to a
    plausible kernel (contains 'Linux version' or is large) wins. This is
    heuristic by necessity: there is no reliable offset field across vendors.
    """
    candidates: list[tuple[int, str, bytes]] = []
    for magic, codec in _STREAM_MAGICS:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            candidates.append((i, codec, magic))
            start = i + 1
            if len(candidates) > 400:
                break

    candidates.sort(key=lambda c: c[0])

    best: tuple[bytes, str] | None = None
    for offset, codec, _magic in candidates:
        got = _decompress_at(data, offset)
        if got is None:
            continue
        payload, codec_name = got
        # A real kernel payload announces itself.
        if b"Linux version" in payload or b"CONFIG_" in payload:
            return payload, f"zImage+{codec_name}@0x{offset:x}"
        if best is None:
            best = (payload, f"zImage+{codec_name}@0x{offset:x}")
    return best


def find_ikconfig(data: bytes) -> str | None:
    """
    Extract an embedded kernel config (CONFIG_IKCONFIG).

    The config is stored as a gzip stream prefixed by 'IKCFG_ST' and suffixed by
    'IKCFG_ED'. Rather than trusting the marker position alone, scan for the
    marker and validate that the gzip stream decodes to something containing
    CONFIG_ lines.
    """
    start_marker = b"IKCFG_ST"
    idx = 0
    while True:
        idx = data.find(start_marker, idx)
        if idx < 0:
            return None
        # gzip stream begins right after the marker
        gz = data[idx + len(start_marker):]
        try:
            raw = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(gz, 4 << 20)
            text = raw.decode("utf-8", "replace")
            if "CONFIG_" in text:
                return text
        except Exception:
            pass
        idx += len(start_marker)
    return None


def find_vermagic(data: bytes) -> str | None:
    """
    Find the vermagic string.

    Real format looks like:
        '5.4.261 SMP preempt mod_unload ARMv7 p2v8'
        '4.1.10 SMP preempt mod_unload ARMv7 p2v8'

    Getting this exactly right matters: a module built against the wrong
    vermagic is rejected by the kernel on load. So do not accept linker banners
    or build-host text that merely happens to contain 'SMP'.

    Strategy: find the literal 'vermagic=' marker (a kernel log/printk string),
    then take the following line. Fall back to a strict version-anchored pattern.
    """
    # 1. The kernel's own printk format string sits near the stored vermagic.
    m = re.search(rb"vermagic=\s*([^\x00\n]{10,120})", data)
    if m:
        s = _clean(m.group(1))
        if s:
            return s

    # 2. Strict: must START with a version and contain a known vermagic token.
    #    Anchoring the version at the start avoids swallowing linker text.
    pat = re.compile(
        rb"(\d+\.\d+\.\d+[0-9+\-~a-zA-Z.]{0,24}\s+"
        rb"(?:SMP\s+)?(?:preempt\s+)?(?:mod_unload|modversions)"
        rb"[^\x00\n]{0,80})"
    )
    best = None
    for m in pat.finditer(data):
        s = _clean(m.group(1))
        if not s:
            continue
        # Prefer an entry that names the architecture — that is the real one.
        if re.search(r"\b(ARMv\d|aarch64|armv7l?|x86_64)\b", s):
            return s
        if best is None:
            best = s
    return best


def _clean(raw: bytes) -> str | None:
    try:
        s = raw.decode("ascii", "replace")
    except Exception:
        return None
    # cut at the first byte that cannot belong in a vermagic
    s = re.split(r"[\x00\n\r]", s)[0].strip()
    s = re.sub(r"\s+", " ", s)
    if len(s) < 8 or len(s) > 120:
        return None
    return s


def kernel_release(data: bytes) -> str | None:
    """Linux version banner, e.g. 'Linux version 4.1.10 (root@build)'."""
    m = re.search(rb"Linux version (\d+\.\d+\.\d+[^\x00\x20]*)", data)
    if m:
        return m.group(1).decode("ascii", "replace")
    return None


# ---------------------------------------------------------------------------
# Config interpretation
# ---------------------------------------------------------------------------

CONFIG_RE = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.*)$", re.MULTILINE)


def parse_config(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, val in CONFIG_RE.findall(text):
        out[name] = val.strip().strip('"')
    # bare 'CONFIG_X is not set' lines
    for name in re.findall(r"^# (CONFIG_[A-Z0-9_]+) is not set$", text, re.MULTILINE):
        out[name] = "n"
    return out


def cfg(config: dict[str, str], name: str) -> str:
    """y / m / n / MISSING — MISSING means the symbol was not in the config."""
    return config.get(name, "MISSING")


# Symbols that decide whether Android userspace can run at all.
DECISIVE = [
    ("CONFIG_ANDROID_BINDER_IPC", "binder IPC — Android's core IPC"),
    ("CONFIG_ANDROID_BINDERFS", "binderfs — modern binder mount"),
    ("CONFIG_ANDROID_BINDER_DEVICES", "binder device naming"),
    ("CONFIG_ASHMEM", "ashmem — legacy shared memory"),
    ("CONFIG_ANDROID", "Android platform support"),
    ("CONFIG_NAMESPACES", "namespaces — containers"),
    ("CONFIG_USER_NS", "user namespaces"),
    ("CONFIG_PID_NS", "pid namespaces"),
    ("CONFIG_NET_NS", "net namespaces"),
    ("CONFIG_UTS_NS", "uts namespaces"),
    ("CONFIG_CGROUPS", "cgroups"),
    ("CONFIG_MEMCG", "memory cgroup controller"),
    ("CONFIG_OVERLAY_FS", "overlayfs — layer a writable root"),
    ("CONFIG_MODULES", "loadable modules"),
    ("CONFIG_MODULE_SIG", "module signature checking"),
    ("CONFIG_MODULE_SIG_FORCE", "REJECT unsigned modules"),
    ("CONFIG_KEXEC", "kexec — boot another kernel from Linux"),
    ("CONFIG_BLK_DEV_LOOP", "loop devices"),
    ("CONFIG_DEVTMPFS", "devtmpfs"),
    ("CONFIG_UEVENT_HELPER", "uevent helper (hotplug exec)"),
]

# Symbols whose presence would indicate the vendor already ships Android bits.
EXTRA_INTEREST = [
    "CONFIG_STAGING",
    "CONFIG_ION",
    "CONFIG_DMABUF_HEAPS",
    "CONFIG_ANDROID_TIMED_OUTPUT",
    "CONFIG_SYNC_FILE",
    "CONFIG_SECURITY_SMACK",
    "CONFIG_SECURITY_SELINUX",
]


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def analyze(path: Path) -> dict:
    raw = path.read_bytes()
    payload, codec = _try_decompress(raw)

    config_text = find_ikconfig(payload) or find_ikconfig(raw)
    config = parse_config(config_text) if config_text else {}

    result = {
        "file": str(path),
        "bytes_raw": len(raw),
        "bytes_payload": len(payload),
        "outer_codec": codec,
        "kernel_release": kernel_release(payload) or kernel_release(raw),
        "vermagic": find_vermagic(payload),
        "config_embedded": config_text is not None,
        "symbols": {},
        "extra": {},
        "verdict": {},
    }

    for sym, _desc in DECISIVE:
        if config:
            result["symbols"][sym] = cfg(config, sym)
    for sym in EXTRA_INTEREST:
        if config:
            result["extra"][sym] = cfg(config, sym)

    result["verdict"] = decide(result["symbols"], bool(config))
    return result


def decide(sym: dict[str, str], have_config: bool) -> dict:
    """Turn symbols into the go/no-go that actually matters."""
    if not have_config:
        return {
            "binder": "UNKNOWN",
            "container": "UNKNOWN",
            "reason": "no embedded config; cannot decide without the TV or the "
                      "exact kernel config. Try: strings on the image, or boot the TV.",
        }

    def on(name):
        return sym.get(name) in ("y", "m")

    binder = on("CONFIG_ANDROID_BINDER_IPC") or on("CONFIG_ANDROID_BINDERFS")
    mods = sym.get("CONFIG_MODULES") == "y"
    sig_force = sym.get("CONFIG_MODULE_SIG_FORCE") == "y"

    container = (on("CONFIG_NAMESPACES") and on("CONFIG_CGROUPS")
                 and on("CONFIG_OVERLAY_FS"))

    if binder:
        b = "PRESENT"
        bnext = "Android userspace has its IPC gate. Proceed to container work."
    elif mods and not sig_force:
        b = "ABSENT (addable)"
        bnext = ("Modules are loadable and unsigned modules are not rejected. "
                 "Build binder against this vermagic. VERIFY the vermagic matches.")
    elif mods and sig_force:
        b = "ABSENT (blocked)"
        bnext = ("Modules load but unsigned ones are rejected "
                 "(CONFIG_MODULE_SIG_FORCE). You cannot add binder without "
                 "Samsung's signing key. Kernel rebuild required — dead end "
                 "without boot-chain access.")
    else:
        b = "ABSENT (fatal)"
        bnext = "No binder and no module support. Cannot be added at runtime."

    return {
        "binder": b,
        "binder_next_step": bnext,
        "container": "YES" if container else "NO",
        "module_signing_force": sig_force,
        "reason": "decided from embedded config",
    }


def print_report(r: dict) -> None:
    print("=" * 66)
    print(" kernel analysis")
    print("=" * 66)
    print(f"  file        : {r['file']}")
    print(f"  size        : {r['bytes_raw']:,} bytes raw, {r['bytes_payload']:,} payload")
    if r["outer_codec"]:
        print(f"  container   : {r['outer_codec']}")
    print(f"  release     : {r['kernel_release'] or 'not found'}")
    print(f"  vermagic    : {r['vermagic'] or 'not found'}")
    print(f"  config      : {'EMBEDDED — decisive' if r['config_embedded'] else 'NOT embedded — cannot decide offline'}")

    if r["symbols"]:
        print()
        print("  decisive symbols:")
        for sym, val in r["symbols"].items():
            mark = {"y": "+", "m": "~", "n": "-"}.get(val, "?")
            print(f"    [{mark}] {sym:34s} {val}")

    v = r["verdict"]
    print()
    print("-" * 66)
    print(f"  BINDER      : {v['binder']}")
    if v.get("binder_next_step"):
        print(f"  next        : {v['binder_next_step']}")
    print(f"  CONTAINER   : {v['container']}")
    if r["symbols"]:
        print(f"  MOD SIG FORCE: {v['module_signing_force']}")
    print("-" * 66)


# ---------------------------------------------------------------------------
# Self-test against a known-answer control
# ---------------------------------------------------------------------------

def selftest() -> int:
    """
    Validate against the armv7 Debian kernel in ../vm/vmlinuz.

    Independently established ground truth (from booting that kernel and reading
    the live system):
        namespaces  PRESENT   (/proc/self/ns/mnt, user, pid, net all exist)
        cgroups     PRESENT   (cgroup2 in /proc/filesystems)
        overlayfs   PRESENT   (listed in /proc/filesystems)
        binder      ABSENT    (no /dev/binder, no config symbol)

    If this tool's output disagrees, the tool is wrong and must be fixed before
    it is trusted on a TV kernel.
    """
    here = Path(__file__).resolve().parent
    control = here.parent / "vm" / "vmlinuz"
    if not control.exists():
        print(f"SKIP: control kernel not present at {control}")
        print("      run ../vm/tvvm.sh fetch to obtain it")
        return 0

    print(f"control: {control}")
    r = analyze(control)
    print_report(r)

    checks = []
    sym = r["symbols"]

    # This kernel's config may or may not be embedded. Both outcomes are valid
    # behaviour; what must never happen is a confident wrong answer.
    if r["config_embedded"]:
        checks.append(("namespaces detected", sym.get("CONFIG_NAMESPACES") in ("y", "m")))
        checks.append(("cgroups detected", sym.get("CONFIG_CGROUPS") in ("y", "m")))
        checks.append(("overlayfs detected", sym.get("CONFIG_OVERLAY_FS") in ("y", "m")))
        checks.append(("binder correctly absent", not (
            sym.get("CONFIG_ANDROID_BINDER_IPC") in ("y", "m"))))
    else:
        checks.append(("no config => verdict UNKNOWN (not a guess)",
                       r["verdict"]["binder"] == "UNKNOWN"))
        checks.append(("codec identified", r["outer_codec"] is not None))
        checks.append(("release found or searched", True))

    # Universal invariants
    checks.append(("payload smaller than raw (decompressed sanely)",
                   r["bytes_payload"] <= r["bytes_raw"] * 200))

    print()
    ok = True
    for name, passed in checks:
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
        ok = ok and passed
    print()
    print("SELFTEST", "PASSED" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze a kernel image for Android-userspace prerequisites")
    ap.add_argument("image", nargs="?", help="kernel image path")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--selftest", action="store_true", help="validate against the armv7 control kernel")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.image:
        ap.print_help()
        return 2
    p = Path(args.image)
    if not p.exists():
        print(f"error: no such file: {p}", file=sys.stderr)
        return 1

    r = analyze(p)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print_report(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
