#!/usr/bin/env python3
"""
msd11.py - Samsung MSD11 firmware container reader (pure Python port of
the MSD11 path in theubusu/unixtract, which is Rust and needs cargo).

Purpose: decrypt a Samsung TV firmware MSD image offline, so the kernel can be
analysed without any shell on the TV.

No part of this writes to a TV. It reads a local .msd and writes local output.
"""
from __future__ import annotations

import hashlib
import io
import struct
import sys
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Published MSD11 passphrases, keyed by the firmware family they cover.
# Source: theubusu/unixtract keys.ukf. 32 bytes => AES-256 (sha256 derivation).
MSD11_KEYS = {
    "PontusM 2022": "9fb9856acb02348553fce0250379568f1f41c5fd995c284f5836717f3ca04fac",  # T-PTM*
    "PontusM 2023": "e67b632b431e5ea32c36ea2f0d705db38e0816a3ea54642cc7cc5c9701395173",  # T-PTMC*
    "PontusM 2024": "b8e0869e1be4b2dfe4f96f73734cd67ce6df80cc3df5052f3e0bb2112b55ee87",  # T-PTMD*
    "PontusM 2025": "3b912671e8af15aaef5a6cb2a3d97cdef2e777707c0067e7a593a968f0de570d",  # T-PTMF*
    "PontusM 2026": "7e04c3ac1804bcb6722b9d6c0565b6d561c17c5fb21145bbe69c746fa1ea700e",  # T-PTMH*
    "RoseM 2025": "84275d43789d291a532f5d13027483ac8aa65e5c568228c75843ce1a4283703d",  # T-RSMF*
    "NikeM2": "1c7b83f91c03b7cb942e18a7ad90b0bfa7cafef83637129188c12931af145f46",     # T-NKM2*
}

OUITH_SIGS = (
    b"Tizen Software Upgrade Tree Binary Format ver. 1.8",
    b"Tizen Software Upgrade Tree Binary Format ver. 1.9",
)

MAGIC = b"MSDU11"


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty plaintext")
    pad = data[-1]
    if pad < 1 or pad > 16 or pad > len(data):
        raise ValueError(f"bad PKCS#7 padding byte {pad}")
    return data[:-pad]


def decrypt_salted(data: bytes, passphrase: bytes) -> bytes:
    """OpenSSL 'Salted__' envelope: iv = sha256(salt)[:16], AES-256-CBC."""
    if data[:8] != b"Salted__":
        raise ValueError("not a Salted__ blob")
    salt = data[8:16]
    iv = hashlib.sha256(salt).digest()[:16]
    return pkcs7_unpad(aes_cbc_decrypt(passphrase, iv, data[16:]))


def decrypt_with_salt(data: bytes, passphrase: bytes, salt: bytes) -> bytes:
    """Section body: iv = sha256(salt)[:16], AES-256-CBC, no envelope."""
    iv = hashlib.sha256(salt).digest()[:16]
    return pkcs7_unpad(aes_cbc_decrypt(passphrase, iv, data))


def is_valid_toc(plain: bytes) -> bool:
    """Same three-position signature check unixtract uses."""
    for off in (256, 262, 518):
        end = off + len(OUITH_SIGS[1])
        if len(plain) >= end and plain[off:end] in OUITH_SIGS:
            return True
    return False


class Reader:
    def __init__(self, fh):
        self.fh = fh

    def read(self, n: int) -> bytes:
        b = self.fh.read(n)
        if len(b) != n:
            raise ValueError(f"short read: wanted {n}, got {len(b)}")
        return b

    def u8(self) -> int:
        return self.read(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]


def parse_header(fh) -> dict:
    r = Reader(fh)
    magic = r.read(6)
    if magic != MAGIC:
        raise ValueError(f"bad magic {magic!r}, expected MSDU11")
    checksum = r.u32()
    header_size = r.u64()
    section_count = r.u32()

    sections = []
    for _ in range(section_count):
        sections.append({"index": r.u32(), "offset": r.u64(), "size": r.u64()})

    header_count = r.u32()
    headers = []
    for _ in range(header_count):
        offset = r.u64()
        size = r.u32()
        name_len = r.u8()
        name = r.read(name_len).decode("utf-8", "replace")
        headers.append({"offset": offset, "size": size, "name": name})

    return {
        "checksum": checksum,
        "header_size": header_size,
        "sections": sections,
        "headers": headers,
    }


def open_image(path: Path):
    """Return a file-like object for the .msd, transparently from a .zip."""
    if path.suffix.lower() == ".zip":
        z = zipfile.ZipFile(path)
        names = [n for n in z.namelist() if n.lower().endswith(".msd")]
        if not names:
            raise ValueError("no .msd inside the zip")
        name = sorted(names)[0]
        print(f"  reading {name} directly from zip (no extraction)")
        return z.open(name), z, name
    return open(path, "rb"), None, str(path)


def find_key(toc_cipher: bytes) -> tuple[str, bytes, bytes] | None:
    """Try each published key against the TOC; the signature proves the match."""
    for name, hexkey in MSD11_KEYS.items():
        try:
            plain = decrypt_salted(toc_cipher, bytes.fromhex(hexkey))
        except Exception:
            continue
        if is_valid_toc(plain):
            return name, bytes.fromhex(hexkey), plain
    return None


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: msd11.py <firmware.msd|firmware.zip> [--extract DIR]")
        return 2

    path = Path(sys.argv[1])
    out_dir = None
    if "--extract" in sys.argv:
        out_dir = Path(sys.argv[sys.argv.index("--extract") + 1])

    print(f"=== {path.name} ===")
    fh, z, inner = open_image(path)
    try:
        hdr = parse_header(fh)
        print(f"  sections: {len(hdr['sections'])}")
        for s in hdr["sections"]:
            print(f"    [{s['index']}] offset={s['offset']:,} size={s['size']:,}")
        print(f"  headers : {len(hdr['headers'])}")
        for h in hdr["headers"]:
            print(f"    {h['name']}: offset={h['offset']:,} size={h['size']:,}")

        h0 = hdr["headers"][0]
        toc_off = h0["offset"] + 8
        toc_size = h0["size"] - 8
        fh.seek(toc_off)
        toc_cipher = fh.read(toc_size)
        print(f"\n  TOC: {toc_size:,} bytes at {toc_off:,}")
        print(f"      starts with: {toc_cipher[:8]!r} "
              f"({'Salted__ envelope' if toc_cipher[:8] == b'Salted__' else 'UNEXPECTED'})")

        found = find_key(toc_cipher)
        if not found:
            print("\n  RESULT: no published key matched this image.")
            return 1

        key_name, key_bytes, toc_plain = found
        print(f"\n  *** KEY MATCHED: {key_name} ***")
        print(f"      Tizen OUITH signature verified in decrypted TOC")
        print(f"      decrypted TOC: {len(toc_plain):,} bytes")

        sig_off = None
        for off in (256, 262, 518):
            if toc_plain[off:off + len(OUITH_SIGS[1])] in OUITH_SIGS:
                sig_off = off
                break
        print(f"      signature at offset {sig_off}")
        print(f"      sig text: {toc_plain[sig_off:sig_off+52]!r}")

        if out_dir:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "toc.bin").write_bytes(toc_plain)
            print(f"      wrote {out_dir/'toc.bin'}")

        return 0
    finally:
        fh.close()
        if z:
            z.close()


if __name__ == "__main__":
    sys.exit(main())
