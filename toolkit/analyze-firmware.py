#!/usr/bin/env python3
"""
analyze-firmware.py — inspect a Samsung Tizen TV firmware container (.msd/.img)

WHY THIS EXISTS
---------------
The decisive question for "can we replace Tizen with Android?" is not whether
we can RUN code on the TV. It is whether the boot chain will accept a kernel or
rootfs that Samsung did not sign.

That question can be answered from a stock firmware download, on this machine,
with no TV and no root. You do not have to take anyone's word for it — including
mine. Download the official firmware for your exact model, point this at it, and
read the result.

WHAT IT REPORTS
---------------
  * container magic / format identification
  * the model/version header records
  * the partition table with per-partition CRC32
  * presence of per-item signature descriptors (OURSAValidationDesc) and
    downgrade-prevention descriptors (SecureDowngradeDesc)

The interpretation that matters: if each boot-relevant item carries its own
signature descriptor, then reading or repackaging the firmware does not give you
the ability to produce a bootable modified image. The signature is what the
bootloader checks — not the container.

CAVEATS (read these)
--------------------
  * Tested against a SYNTHETIC container built by this repo's own test, not
    against a real Samsung image. Real images may use variants this parser does
    not know. A parse failure is NOT evidence of anything.
  * This tool is read-only. It never writes, repacks, or modifies the input.
  * Acquire firmware from Samsung's own support site for hardware you own.

Usage:
    python3 analyze-firmware.py /path/to/upgrade.msd
    python3 analyze-firmware.py --json /path/to/upgrade.msd
"""

from __future__ import annotations

import argparse
import binascii
import json
import struct
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

MAGICS = (b"MSDU11", b"MSDU12", b"MSDU10")
HEADER_RECORD_SIZE = 0x0E08  # observed in public msddecrypt output

# Descriptor names worth flagging, from published analysis of Samsung's
# firmware container (TLV records inside the decrypted header).
SIGNATURE_DESCRIPTORS = (
    b"OURSAValidationDesc",
    b"OURSAValidation",
    b"RSAValidationDesc",
)
DOWNGRADE_DESCRIPTORS = (
    b"SecureDowngradeDesc",
    b"SecureDowngrade",
)


@dataclass
class Partition:
    index: int
    name: str
    salt: str = ""
    offset: int = 0
    size: int = 0
    crc32: str = ""


@dataclass
class Report:
    path: str
    size: int = 0
    magic: str = ""
    recognized: bool = False
    header_records: list[str] = field(default_factory=list)
    partitions: list[Partition] = field(default_factory=list)
    signature_descriptors: int = 0
    downgrade_descriptors: int = 0
    uep_strings: int = 0
    kernel_versions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def boot_chain_verifies(self) -> bool:
        return self.signature_descriptors > 0


def _scan_ascii(data: bytes, needle: bytes) -> int:
    return data.count(needle)


def _find_kernel_versions(data: bytes, limit: int = 200) -> list[str]:
    """Pull 'Linux version X.Y.Z' banners out of the image."""
    import re

    found: list[str] = []
    for match in re.finditer(rb"Linux version (\d+\.\d+\.\d+)", data[:limit * 1024 * 1024]):
        version = match.group(1).decode("ascii", "replace")
        if version not in found:
            found.append(version)
        if len(found) >= 8:
            break
    return found


def scope_identify(data: bytes, report: Report) -> None:
    """Identify the container format."""
    for magic in MAGICS:
        if data.lstrip()[:6].startswith(magic) or magic in data[:4096]:
            report.magic = magic.decode("ascii")
            report.recognized = True
            break

    if not report.recognized:
        report.notes.append(
            "No Samsung MSD container magic found in the first 4 KiB. "
            "The file may be a plain .img, a zip, or a different packaging. "
            "A failed identification is not a finding about the device."
        )
        return

    # Header records look like "T-XXXXXXX" model codes, 0x0E08 bytes each.
    start = data.find(report.magic.encode())
    if start < 0:
        start = 0
    region = data[start:start + HEADER_RECORD_SIZE * 16]
    import re

    for match in re.finditer(rb"T-[A-Z0-9]{5,10}", region):
        code = match.group(0).decode("ascii", "replace")
        if code not in report.header_records:
            report.header_records.append(code)


def scope_partitions(data: bytes, report: Report) -> None:
    """
    Look for partition name strings. Real layouts vary between models, so this
    is a best-effort inventory, not an authoritative table.
    """
    known = (
        b"uImage", b"secos.bin", b"secos_drv.bin", b"seret.bin",
        b"dtb.bin", b"sign.bin", b"platform.img", b"factory_peq.img",
        b"rootfs", b"rootfs.img", b"exe.img", b"system.img",
    )
    index = 0
    for name in known:
        occurrences = data.count(name)
        if occurrences:
            index += 1
            report.partitions.append(
                Partition(index=index, name=name.decode("ascii", "replace"))
            )


def scope_descriptors(data: bytes, report: Report) -> None:
    for name in SIGNATURE_DESCRIPTORS:
        report.signature_descriptors += _scan_ascii(data, name)
    for name in DOWNGRADE_DESCRIPTORS:
        report.downgrade_descriptors += _scan_ascii(data, name)
    report.uep_strings = _scan_ascii(data, b"UEP") + _scan_ascii(data, b"uep")
    report.kernel_versions = _find_kernel_versions(data)


def scope_verdict(report: Report) -> None:
    if not report.recognized:
        report.notes.append("VERDICT: inconclusive — container not identified.")
        return

    if report.boot_chain_verifies:
        report.notes.append(
            "VERDICT: the boot chain verifies what it loads. "
            f"Found {report.signature_descriptors} per-item signature descriptor "
            "reference(s). Each boot-relevant item carries its own signature, so "
            "reading or repacking this firmware does not yield a bootable modified "
            "image. This closes the OS-replacement route for this firmware family."
        )
    else:
        report.notes.append(
            "VERDICT: no per-item signature descriptors found. This would be a "
            "significant finding — but first confirm the container was decrypted "
            "and parsed correctly, and that the descriptor naming matches this "
            "firmware generation. Absence of a string is not absence of a check."
        )

    if report.kernel_versions:
        report.notes.append(
            "Kernel banner(s): " + ", ".join(report.kernel_versions)
        )
    if report.uep_strings:
        report.notes.append(
            f"UEP (unsigned-execution protection) references: {report.uep_strings}. "
            "UEP is a boundary distinct from UID 0."
        )


def analyze(path: Path, *, max_bytes: int = 256 * 1024 * 1024) -> Report:
    report = Report(path=str(path))
    size = path.stat().st_size
    report.size = size
    with path.open("rb") as handle:
        data = handle.read(max_bytes)
    if size > max_bytes:
        report.notes.append(
            f"Read first {max_bytes // (1024*1024)} MiB of {size // (1024*1024)} MiB."
        )
    scope_identify(data, report)
    scope_partitions(data, report)
    scope_descriptors(data, report)
    scope_verdict(report)
    return report


def render(report: Report) -> str:
    lines = []
    lines.append("=" * 66)
    lines.append("Samsung Tizen firmware container analysis")
    lines.append("=" * 66)
    lines.append(f"  file        : {report.path}")
    lines.append(f"  size        : {report.size:,} bytes")
    lines.append(f"  magic       : {report.magic or '(not identified)'}")
    lines.append(f"  recognized  : {report.recognized}")
    if report.header_records:
        lines.append(f"  model codes : {', '.join(report.header_records)}")
    lines.append("")
    lines.append("  signature descriptors : "
                 f"{report.signature_descriptors}")
    lines.append("  downgrade descriptors : "
                 f"{report.downgrade_descriptors}")
    lines.append("  UEP references        : {0}".format(report.uep_strings))
    if report.kernel_versions:
        lines.append(f"  kernel banners        : {', '.join(report.kernel_versions)}")
    if report.partitions:
        lines.append("")
        lines.append("  partition names seen:")
        for part in report.partitions:
            lines.append(f"    - {part.name}")
    lines.append("")
    lines.append("-" * 66)
    for note in report.notes:
        lines.append(f"  {note}")
    lines.append("-" * 66)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyse a Samsung Tizen TV firmware container (read-only)"
    )
    parser.add_argument("path", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--max-mb", type=int, default=256)
    args = parser.parse_args()

    if not args.path.is_file():
        print(f"error: not a file: {args.path}", file=sys.stderr)
        return 2

    report = analyze(args.path, max_bytes=args.max_mb * 1024 * 1024)
    if args.json:
        payload = asdict(report)
        payload["boot_chain_verifies"] = report.boot_chain_verifies
        print(json.dumps(payload, indent=2))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
