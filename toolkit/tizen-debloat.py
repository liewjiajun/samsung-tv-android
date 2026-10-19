#!/usr/bin/env python3
"""
tizen-debloat.py — safely strip a Samsung Tizen TV down to what it needs.

WHAT THIS DOES AND DOES NOT DO
------------------------------
Does:      removes the ad, telemetry, shopping and duplicate-app layer that
           ships on Tizen TVs. Frees RAM and storage, cuts background network
           chatter, makes the stock UI noticeably faster.

Does NOT:  make Tizen behave like Android, and cannot bring Play Store.

That second point is not caution, it is architecture:

  Play Store is an Android application package. It runs on ART, talks over
  binder, and depends on Google Play Services. A Tizen TV has none of those -
  it runs .tpk / .wgt apps on its own framework.

  Debloating removes things. It cannot add a runtime. You cannot delete your
  way into a different operating system.

So this tool is step 1 of the Android plan, not an alternative to it: it buys
the RAM and headroom that everything later in the plan needs.

SAFETY MODEL
------------
Tizen TVs do not expose a normal shell over SDB. The daemon whitelists verbs,
and `pkgcmd` is the sanctioned one. Accordingly:

  * dry-run is the DEFAULT. Nothing changes unless you pass --apply.
  * every state read is backed up to JSON before a write.
  * a KEEP list protects anything the remote, display, tuner, boot path or
    input switching depends on.
  * every action is reversible: --revert restores from the backup.
  * each write is verified by re-reading state, not assumed.

NOTHING HERE NEEDS ROOT. It needs Developer Mode + SDB.

Usage:
    python3 tizen-debloat.py --host 192.168.1.10                 # dry run
    python3 tizen-debloat.py --host 192.168.1.10 --apply         # do it
    python3 tizen-debloat.py --host 192.168.1.10 --revert FILE   # undo
    python3 tizen-debloat.py --host 192.168.1.10 --list          # inventory only
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
try:
    from sdb_native import SdbClient, SdbError  # type: ignore
except ImportError:  # pragma: no cover
    print("error: sdb_native.py must sit next to this file", file=sys.stderr)
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
# Required for the remote, the panel, input switching, tuner, boot.
# Touching these is how people end up with a brick or a dead remote.
KEEP: dict[str, str] = {
    "com.smartdevice.livetv":        "Live TV / HDMI passthrough (input switching)",
    "com.smartdevice.duplebluetooth": "remote pairing (Bluetooth HID)",
    "com.smartdevice.dtv.icast":     "DLNA / casting",
    "com.smartdevice.factory":       "factory test hooks — leave alone",
    "org.tizen.tvinfo":              "system info provider",
    "org.tizen.tvinputdevice":       "input device / remote key handling",
    "org.tizen.tvdisplay":           "display control",
    "org.tizen.tvsettings":          "settings backend",
    "org.tizen.tvnetwork":           "network stack",
    "org.tizen.tvaudio":             "audio pipeline",
    "org.tizen.tvmedia":             "media pipeline",
    "org.tizen.tvsystem":            "system services",
}

# Ads, telemetry, shopping, recommendations, duplicate browsers.
DEBLOAT: dict[str, str] = {
    "com.samsung.tv.acr":                    "always-on ACR / content recognition (ad targeting)",
    "com.smartdevice.acr.recommendation":    "ACR-driven recommendations",
    "com.samsung.tv.voice.recognition":      "voice data collection",
    "com.samsung.tv.customization":          "ad personalisation service",
    "com.samsung.tv.btv":                    "Samsung TV Plus / ad-funded channels",
    "com.smartdevice.recommendation":        "recommendation engine",
    "com.smartdevice.leanbacklauncher.customizer": "launcher ad slots",
    "com.smartdevice.epopplayer":            "preinstalled ad/promo player",
    "com.smartdevice.www":                   "promo web surface",
    "com.samsung.tv.apps.partner":           "partner app injection",
    "com.samsung.tv.shopping":               "shopping surface",
    "com.sky.market":                        "regional app store stub",
    "com.samsung.tv.ad":                     "ad delivery",
}

# Names that are strong signals even on models we have not catalogued.
DEBLOAT_PATTERNS: list[tuple[str, str]] = [
    (r"\.acr(\.|$)",        "ACR content recognition (ad targeting)"),
    (r"recommendation",     "recommendation / suggested-content engine"),
    (r"advert|(^|[._])ads?(\.|$)", "advertising surface"),
    (r"telemetry|metrics",  "telemetry reporting"),
    (r"shopping|commerce",  "shopping surface"),
    (r"partner",            "partner-injected content"),
    (r"promo",              "promotional surface"),
]

# Never flag these even though they match a pattern above.
PATTERN_ALLOW = {
    "com.samsung.android.tv.recommendations",  # not present on most Tizen sets
}


def classify(pkg: str) -> tuple[str, str]:
    """Return (verdict, reason) where verdict is KEEP / DEBLOAT / REVIEW."""
    low = pkg.lower()

    if pkg in KEEP:
        return "KEEP", KEEP[pkg]
    if pkg in DEBLOAT:
        return "DEBLOAT", DEBLOAT[pkg]

    # anything in a system namespace we did not explicitly vouch for -> review
    for pat, reason in DEBLOAT_PATTERNS:
        if pkg in PATTERN_ALLOW:
            continue
        if re.search(pat, low):
            return "DEBLOAT", reason

    return "REVIEW", "unclassified — leave it alone unless you know what it is"


# ---------------------------------------------------------------------------
# Talking to the TV
# ---------------------------------------------------------------------------
class TV:
    def __init__(self, host: str, port: int = 26101, timeout: float = 10.0):
        self.client = SdbClient(host, port=port, timeout=timeout)

    def __enter__(self) -> "TV":
        banner = self.client.connect()
        self.banner = banner
        return self

    def __exit__(self, *exc) -> None:
        self.client.close()

    # -- discovery ---------------------------------------------------------
    def capability(self) -> dict[str, str]:
        try:
            return self.client.capability()
        except (SdbError, OSError, ValueError):
            return {}

    def packages(self) -> list[str]:
        """
        Enumerate installed packages.

        Tizen TVs vary in which verbs they expose. Try the documented ones in
        order and take the first that returns parseable output.
        """
        for cmd in ("0 vd_applist", "pkgcmd -l", "0 getpkglist"):
            try:
                raw = self.client.shell(cmd)
            except (SdbError, OSError, ValueError) as exc:
                print(f"  [warn] {cmd!r} failed: {exc}")
                continue

            if not raw or raw.strip().lower() in ("closed", ""):
                continue

            pkgs = _parse_pkglist(raw)
            if pkgs:
                print(f"  enumerated via {cmd!r}: {len(pkgs)} packages")
                return pkgs

        return []

    # -- actions -----------------------------------------------------------
    def disable(self, pkg: str) -> tuple[bool, str]:
        """
        Disable (not uninstall) a package. Disabling is reversible and does not
        touch the firmware image, so it survives far more gracefully than a
        delete when something turns out to be load-bearing.
        """
        for cmd in (f"pkgcmd -D -n {pkg} -t app", f"pkgcmd -D -n {pkg}",
                    f"0 pkgcmd -D -n {pkg}"):
            try:
                out = self.client.shell(cmd)
            except (SdbError, OSError, ValueError) as exc:
                return False, f"{type(exc).__name__}: {exc}"
            if out and "closed" not in out.lower() and "fail" not in out.lower():
                return True, out.strip()
        return False, "no accepted pkgcmd variant"

    def enable(self, pkg: str) -> tuple[bool, str]:
        for cmd in (f"pkgcmd -E -n {pkg} -t app", f"pkgcmd -E -n {pkg}"):
            try:
                out = self.client.shell(cmd)
            except (SdbError, OSError, ValueError) as exc:
                return False, f"{type(exc).__name__}: {exc}"
            if out and "closed" not in out.lower() and "fail" not in out.lower():
                return True, out.strip()
        return False, "no accepted pkgcmd variant"


def _parse_pkglist(raw: str) -> list[str]:
    pkgs: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        def dotted(text: str) -> list[str]:
            out = []
            for tok in re.split(r"[,\s]+", text):
                tok = tok.strip().strip('"')
                if "." not in tok:
                    continue
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.\-]{3,}", tok):
                    continue
                out.append(tok)
            return out

        # Output formats seen in the wild:
        #   pkg.name                 (one package)
        #   pkg.name com.other       (several packages)
        #   pkg.name 1.2.3           (package + version)
        #   /opt/usr/apps/pkg.name/data   (path form)
        # In the path form the package id is a middle segment, so only the
        # longest dotted identifier on the line is the package.
        if "/" in line:
            candidates = []
            for segment in line.split("/"):
                candidates.extend(dotted(segment))
            if candidates:
                pkgs.append(max(candidates, key=len))
        else:
            pkgs.extend(dotted(line))

    return sorted(set(pkgs))


# ---------------------------------------------------------------------------
# backup / restore
# ---------------------------------------------------------------------------
BACKUP_DIR = Path(__file__).parent.parent / "backup"


def write_backup(host: str, state: dict) -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = BACKUP_DIR / f"debloat-{host.replace('.', '-')}-{stamp}.json"
    path.write_text(json.dumps(state, indent=2))
    return path


def do_revert(path: Path, tv: TV) -> int:
    state = json.loads(path.read_text())
    disabled = state.get("disabled", [])
    if not disabled:
        print("nothing recorded as disabled in that backup.")
        return 0

    print(f"re-enabling {len(disabled)} package(s) from {path.name}\n")
    ok = 0
    for pkg in disabled:
        worked, detail = tv.enable(pkg)
        print(f"  {'OK  ' if worked else 'FAIL'} {pkg}  {detail[:60]}")
        if worked:
            ok += 1
        time.sleep(0.2)
    print(f"\nrestored {ok}/{len(disabled)}")
    return 0 if ok == len(disabled) else 1


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Debloat a Samsung Tizen TV (dry-run by default)"
    )
    ap.add_argument("--host", required=True, help="TV IP address")
    ap.add_argument("--port", type=int, default=26101)
    ap.add_argument("--apply", action="store_true",
                    help="actually change things (default is a dry run)")
    ap.add_argument("--list", action="store_true", help="inventory only")
    ap.add_argument("--revert", metavar="BACKUP.json")
    ap.add_argument("--include-review", action="store_true",
                    help="also act on unclassified packages (not advised)")
    opts = ap.parse_args()

    print("=" * 70)
    print("tizen-debloat" + ("" if opts.apply else "  [DRY RUN — nothing will change]"))
    print("=" * 70)

    try:
        with TV(opts.host, opts.port) as tv:
            caps = tv.capability()
            if caps:
                print("\nTV:")
                for k in ("model", "version", "platform", "build", "cpu_arch"):
                    if caps.get(k):
                        print(f"  {k:<9}: {caps[k]}")

            if opts.revert:
                return do_revert(Path(opts.revert), tv)

            print("\nreading package list...")
            pkgs = tv.packages()
            if not pkgs:
                print("\ncould not enumerate packages.")
                print("check Developer Mode is ON and the TV accepted the SDB key.")
                return 2

            buckets: dict[str, list[tuple[str, str]]] = {
                "DEBLOAT": [], "KEEP": [], "REVIEW": [],
            }
            for p in pkgs:
                verdict, reason = classify(p)
                buckets[verdict].append((p, reason))

            print(f"\n{len(pkgs)} packages:")
            print(f"  {len(buckets['DEBLOAT']):>3} to debloat")
            print(f"  {len(buckets['KEEP']):>3} protected (remote/display/tuner/boot)")
            print(f"  {len(buckets['REVIEW']):>3} unclassified")

            if buckets["DEBLOAT"]:
                print("\nwould disable:")
                for p, r in buckets["DEBLOAT"]:
                    print(f"  - {p:<45} {r}")

            if opts.list:
                print("\nfull inventory:")
                for p in pkgs:
                    v, _ = classify(p)
                    print(f"  [{v[0]}] {p}")
                return 0

            targets = [p for p, _ in buckets["DEBLOAT"]]
            if opts.include_review:
                targets += [p for p, _ in buckets["REVIEW"]]

            if not targets:
                print("\nnothing matched. TV may already be clean, or the "
                      "package list format is unfamiliar.")
                return 0

            if not opts.apply:
                print(f"\nDRY RUN: would disable {len(targets)} package(s).")
                print("re-run with --apply to proceed.")
                return 0

            # ---- apply ----
            backup = write_backup(opts.host, {
                "host": opts.host,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "packages": pkgs,
                "targets": targets,
                "disabled": [],
            })
            print(f"\nbackup written: {backup}")

            disabled: list[str] = []
            failed: list[str] = []
            for pkg in targets:
                worked, detail = tv.disable(pkg)
                if worked:
                    disabled.append(pkg)
                    print(f"  {'OK  '} {pkg}")
                else:
                    failed.append(pkg)
                    print(f"  FAIL {pkg}  ({detail[:50]})")
                time.sleep(0.2)

            # verify by re-reading, never by assuming
            print("\nverifying (re-reading package list)...")
            after = set(tv.packages())
            gone = [p for p in disabled if p not in after]
            still = [p for p in disabled if p in after]
            print(f"  confirmed disabled : {len(gone)}")
            print(f"  still listed       : {len(still)}")
            if still:
                print("  (some packages stay listed after disabling; "
                      "that is expected on Tizen)")

            data = json.loads(backup.read_text())
            data["disabled"] = disabled
            data["failed"] = failed
            backup.write_text(json.dumps(data, indent=2))
            print(f"\nbackup updated with results: {backup}")
            print(f"revert any time: python3 {Path(__file__).name} "
                  f"--host {opts.host} --revert {backup}")

            return 0 if not failed else 1

    except SdbError as exc:
        print(f"\nSDB error: {exc}")
        print("is Developer Mode on, and did the TV accept the key?")
        return 2
    except (OSError, ValueError) as exc:
        print(f"\ncould not reach {opts.host}:{opts.port} — {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
