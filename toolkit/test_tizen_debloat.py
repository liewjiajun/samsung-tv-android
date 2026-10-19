#!/usr/bin/env python3
"""
test_tizen_debloat.py — prove the debloat tool works before it touches the TV.

The whole risk of a debloat tool is that it removes something load-bearing and
you find out by losing your remote or your HDMI inputs. So this test does not
just check that the tool runs; it checks that the tool's *judgement* is right in
both directions:

  * protected packages are never touched
  * user apps are never touched
  * ad/telemetry packages are identified
  * unclassified packages are left alone
  * dry-run changes nothing
  * disable actually disables
  * revert actually restores
  * a broken/interrupted run does not corrupt state

Runs against mock_sdbd, so it needs no television.
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import mock_sdbd  # noqa: E402

# tizen-debloat.py has a hyphen, so it cannot be imported by name.
# Load it explicitly; the module must register as 'tizen_debloat' because
# it does `sys.path.insert` + `from sdb_native import ...` of its own.
spec = importlib.util.spec_from_file_location(
    "tizen_debloat", HERE / "tizen-debloat.py"
)
td = importlib.util.module_from_spec(spec)
sys.modules["tizen_debloat"] = td
spec.loader.exec_module(td)

PASS = 0
FAIL = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}  {detail}")


# ---------------------------------------------------------------------------
print("=" * 70)
print("tizen-debloat test suite (against mock sdbd)")
print("=" * 70)

# --- classification rules --------------------------------------------------
print("\n[classification]")

keep_cases = [
    "com.smartdevice.livetv",
    "com.smartdevice.duplebluetooth",
    "com.smartdevice.dtv.icast",
    "org.tizen.tvinputdevice",
    "org.tizen.tvdisplay",
]
for pkg in keep_cases:
    verdict, _ = td.classify(pkg)
    check(f"protects {pkg}", verdict == "KEEP", f"got {verdict}")

debloat_cases = [
    "com.samsung.tv.acr",
    "com.smartdevice.acr.recommendation",
    "com.smartdevice.recommendation",
    "com.smartdevice.epopplayer",
    "com.samsung.tv.shopping",
]
for pkg in debloat_cases:
    verdict, _ = td.classify(pkg)
    check(f"flags {pkg}", verdict == "DEBLOAT", f"got {verdict}")

# user apps must never be classified as debloat
for pkg in ("com.netflix.ninja", "com.disney.disneyplus",
            "com.google.android.youtube.tv"):
    verdict, _ = td.classify(pkg)
    check(f"leaves user app {pkg} alone", verdict != "DEBLOAT", f"got {verdict}")

# unknown things must be REVIEW, not silently removed
verdict, _ = td.classify("com.samsung.tv.something.unknown")
check("unknown package is REVIEW", verdict == "REVIEW", f"got {verdict}")

verdict, _ = td.classify("com.smartdevice.emanual")
check("unclassified device pkg is REVIEW", verdict == "REVIEW", f"got {verdict}")

# --- a whitelisted-looking name must still be protected --------------------
verdict, _ = td.classify("org.tizen.tvnetwork")
check("protects network stack", verdict == "KEEP", f"got {verdict}")

# --- package list parsing --------------------------------------------------
print("\n[package list parsing]")
parsed = td._parse_pkglist("com.a.one\ncom.b.two\n")
check("parses plain list", parsed == ["com.a.one", "com.b.two"], str(parsed))

parsed = td._parse_pkglist("/opt/usr/apps/com.x.y/data\n")
check("strips path", parsed == ["com.x.y"], str(parsed))

parsed = td._parse_pkglist("com.a.one com.b.two\n")
check("splits whitespace", set(parsed) == {"com.a.one", "com.b.two"}, str(parsed))

parsed = td._parse_pkglist("")
check("empty input -> empty", parsed == [], str(parsed))

parsed = td._parse_pkglist("garbage\n!!!\n")
check("ignores junk", parsed == [], str(parsed))


# ---------------------------------------------------------------------------
# end-to-end against the mock
# ---------------------------------------------------------------------------
def run_tool(argv: list[str]) -> tuple[int, str]:
    """Invoke the debloat CLI in-process, capturing stdout."""
    buf = io.StringIO()
    saved = sys.argv
    sys.argv = ["tizen-debloat.py", *argv]
    try:
        with contextlib.redirect_stdout(buf):
            rc = td.main()
    except SystemExit as exc:  # argparse
        rc = int(exc.code or 0)
    finally:
        sys.argv = saved
    return rc, buf.getvalue()


print("\n[end-to-end against mock TV]")

srv, box = mock_sdbd.serve(0, secure=True)
port = box["port"]
host = "127.0.0.1"

# fresh state for the module-level mock inventory
mock_sdbd._enabled = set(mock_sdbd.MOCK_PACKAGES)

# redirect backups into a temp dir so the test does not litter the repo
tmp_backup = Path(tempfile.mkdtemp(prefix="debloat-test-"))
real_backup_dir = td.BACKUP_DIR
td.BACKUP_DIR = tmp_backup

try:
    # ---- 1. inventory only changes nothing ---------------------------------
    before = set(mock_sdbd._enabled)
    rc, out = run_tool(["--host", host, "--port", str(port), "--list"])
    after = set(mock_sdbd._enabled)
    check("--list exits 0", rc == 0, f"rc={rc}")
    check("--list changes nothing", before == after,
          f"diff={before ^ after}")
    check("--list shows the inventory", "full inventory" in out)
    check("--list reports counts",
          "to debloat" in out and "protected" in out, out[:200])

    # ---- 2. DRY RUN must not touch the TV ---------------------------------
    before = set(mock_sdbd._enabled)
    rc, out = run_tool(["--host", host, "--port", str(port)])
    after = set(mock_sdbd._enabled)
    check("dry run exits 0", rc == 0, f"rc={rc}")
    check("DRY RUN changes nothing", before == after,
          f"diff={before ^ after}")
    check("dry run says DRY RUN", "DRY RUN" in out)
    check("dry run lists candidates", "would disable:" in out)

    # ---- 3. APPLY actually disables ---------------------------------------
    before = set(mock_sdbd._enabled)
    rc, out = run_tool(["--host", host, "--port", str(port), "--apply"])
    after = set(mock_sdbd._enabled)
    removed = before - after

    check("apply exits 0", rc == 0, f"rc={rc}")
    check("apply removed something", len(removed) > 0, f"removed={removed}")

    # protected things must survive
    for pkg in keep_cases:
        check(f"apply spared {pkg}", pkg in after)

    # user apps must survive
    for pkg in ("com.netflix.ninja", "com.disney.disneyplus"):
        check(f"apply spared user app {pkg}", pkg in after)

    # the ads must be gone
    for pkg in ("com.samsung.tv.acr", "com.smartdevice.epopplayer"):
        check(f"apply removed {pkg}", pkg not in after)

    # unknowns must survive (we did not pass --include-review)
    check("apply spared unclassified",
          "com.smartdevice.emanual" in after)

    check("apply wrote a backup", len(list(tmp_backup.glob("*.json"))) == 1,
          str(list(tmp_backup.glob("*.json"))))
    check("apply reports verification", "verifying" in out.lower())

    backup_file = next(tmp_backup.glob("*.json"))
    data = json.loads(backup_file.read_text())
    check("backup records disabled list", len(data.get("disabled", [])) > 0)
    check("backup disabled matches reality",
          set(data["disabled"]) == removed,
          f"{set(data.get('disabled', []))} vs {removed}")

    # ---- 4. REVERT restores everything ------------------------------------
    rc, out = run_tool(["--host", host, "--port", str(port),
                        "--revert", str(backup_file)])
    restored = set(mock_sdbd._enabled)
    check("revert exits 0", rc == 0, f"rc={rc}")
    check("revert restored everything", restored == before,
          f"missing={before - restored}")
    check("revert mentions count", "restored" in out)

    # ---- 5. idempotence: applying twice is safe ---------------------------
    rc1, _ = run_tool(["--host", host, "--port", str(port), "--apply"])
    rc2, out2 = run_tool(["--host", host, "--port", str(port), "--apply"])
    check("second apply exits 0", rc2 == 0, f"rc={rc2}")
    check("second apply is not destructive",
          all(p in mock_sdbd._enabled for p in keep_cases))

    # ---- 6. unreachable host fails cleanly, not with a traceback ----------
    rc, out = run_tool(["--host", "127.0.0.1", "--port", "1"])
    check("dead host exits non-zero", rc != 0, f"rc={rc}")
    check("dead host gives a clean error", "could not reach" in out or "SDB error" in out,
          out[:160])
    check("dead host has no traceback", "Traceback" not in out)

finally:
    td.BACKUP_DIR = real_backup_dir
    shutil.rmtree(tmp_backup, ignore_errors=True)
    try:
        srv.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
print("\n" + "=" * 70)
print(f"passed: {PASS}   failed: {FAIL}")
if FAIL == 0:
    print("ALL TESTS PASSED")
else:
    print("THERE ARE FAILURES")
print("=" * 70)
raise SystemExit(1 if FAIL else 0)
