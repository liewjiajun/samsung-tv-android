#!/usr/bin/env python3
"""
msd11_extract.py - full MSD11 extraction for Samsung TV firmware.

Ports the MSD11 + OUITH 1.9 paths from theubusu/unixtract (Rust) to Python so it
runs without cargo.

Reads a local firmware .msd/.zip and writes decrypted sections to a local dir.
Writes nothing to any TV.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zipfile
import zlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MSD11_KEYS = {
    "PontusM 2022": "9fb9856acb02348553fce0250379568f1f41c5fd995c284f5836717f3ca04fac",
    "PontusM 2023": "e67b632b431e5ea32c36ea2f0d705db38e0816a3ea54642cc7cc5c9701395173",
    "PontusM 2024": "b8e0869e1be4b2dfe4f96f73734cd67ce6df80cc3df5052f3e0bb2112b55ee87",
    "PontusM 2025": "3b912671e8af15aaef5a6cb2a3d97cdef2e777707c0067e7a593a968f0de570d",
    "PontusM 2026": "7e04c3ac1804bcb6722b9d6c0565b6d561c17c5fb21145bbe69c746fa1ea700e",
    "RoseM 2025": "84275d43789d291a532f5d13027483ac8aa65e5c568228c75843ce1a4283703d",
    "NikeM2": "1c7b83f91c03b7cb942e18a7ad90b0bfa7cafef83637129188c12931af145f46",
}

SIG19 = b"Tizen Software Upgrade Tree Binary Format ver. 1.9\x00"
SIG18 = b"Tizen Software Upgrade Tree Binary Format ver. 1.8"
OUITH_SIGS = (SIG18, SIG19)


class R:
    """Little-endian sequential reader over bytes."""

    def __init__(self, data: bytes, pos: int = 0):
        self.d = data
        self.p = pos

    def take(self, n: int) -> bytes:
        if self.p + n > len(self.d):
            raise ValueError(f"short read at {self.p}: want {n}, have {len(self.d)-self.p}")
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]


def aes_cbc_dec_bytes(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def decrypt_salted(data: bytes, passphrase: bytes) -> bytes:
    if data[:8] != b"Salted__":
        raise ValueError("not Salted__")
    salt = data[8:16]
    iv = hashlib.sha256(salt).digest()[:16]
    pt = aes_cbc_dec_bytes(passphrase, iv, data[16:])
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        return pt[:-pad]
    return pt


def toc_ok(pt: bytes) -> bool:
    for off in (256, 262, 518):
        if pt[off:off + len(SIG19)] in OUITH_SIGS:
            return True
    return False


def parse_header(fh) -> dict:
    fh.seek(0)
    magic = fh.read(6)
    if magic != b"MSDU11":
        raise ValueError(f"bad magic {magic!r}")
    checksum = struct.unpack("<I", fh.read(4))[0]
    header_size = struct.unpack("<Q", fh.read(8))[0]
    nsec = struct.unpack("<I", fh.read(4))[0]
    sections = []
    for _ in range(nsec):
        idx = struct.unpack("<I", fh.read(4))[0]
        off = struct.unpack("<Q", fh.read(8))[0]
        size = struct.unpack("<Q", fh.read(8))[0]
        sections.append({"index": idx, "offset": off, "size": size})
    nhdr = struct.unpack("<I", fh.read(4))[0]
    headers = []
    for _ in range(nhdr):
        off = struct.unpack("<Q", fh.read(8))[0]
        size = struct.unpack("<I", fh.read(4))[0]
        nlen = fh.read(1)[0]
        nm = fh.read(nlen).decode("utf-8", "replace")
        headers.append({"offset": off, "size": size, "name": nm})
    return {"checksum": checksum, "header_size": header_size,
            "sections": sections, "headers": headers}


def parse_toc(toc: bytes) -> list[dict]:
    r = R(toc)
    _pubkey = r.u32()
    sig_size = r.u16()
    r.take(sig_size)
    magic = r.take(51)
    if magic != SIG19:
        raise ValueError(f"unexpected tree magic {magic!r}")

    # DescriptorHeader is {flag:u8, size:u32, tag:u32} and `size` counts the tag
    # plus the payload. So after reading flag+size, the descriptor ends exactly
    # `size` bytes later. Resyncing to that boundary after each descriptor keeps
    # the stream aligned even where a sub-descriptor is one we do not parse.
    ntop = r.u32()
    items: list[dict] = []
    for _ in range(ntop):
        _flag = r.u8()
        size = r.u32()
        after_size = r.p
        tag = r.u32()
        end = after_size + size

        if tag == 0x01:
            # DescriptorHeader already consumed flag+size+tag. The payload then
            # begins with the struct's OWN _flag byte. Missing it shifts every
            # later field by one, which is what broke subdesc_count (read as 768
            # instead of a small number).
            r.u8()                      # OUUpgradeItemDesc._flag
            item_id = r.u32()
            _unk_flag = r.u8()
            orig = r.u64()
            proc = r.u64()
            _unk = r.u16()
            nsub = r.u32()
            name = None
            aes = False
            salt = None
            for _ in range(nsub):
                _sflag = r.u8()
                ssize = r.u32()
                s_after = r.p
                stag = r.u32()
                s_end = s_after + ssize
                if stag == 0x0A:
                    r.u8()
                    nlen = r.u8()
                    name = r.take(nlen).decode("utf-8", "replace")
                elif stag == 0x07:
                    r.u8()
                    dcount = r.u32()
                    for _ in range(dcount):
                        _dflag = r.u8()
                        dsize = r.u32()
                        d_after = r.p
                        dtag = r.u32()
                        d_end = d_after + dsize
                        if dtag == 0x12:
                            r.u8()
                            _crc = r.u32()
                        elif dtag == 0x10:
                            r.u8()
                            _pkid = r.u32()
                            ss = r.u16()
                            r.take(ss)
                        elif dtag == 0x0E:
                            r.u8()
                            slen = r.u8()
                            salt = r.take(slen)
                            _aproc = r.u64()
                            aes = True
                        r.p = d_end
                elif stag == 0x13:
                    r.u8()
                    _gid = r.u32()
                r.p = s_end
            if name:
                items.append({"item_id": item_id, "name": name, "aes": aes,
                              "salt": salt, "orig": orig, "proc": proc})

        elif tag == 0x02:
            r.u8()
            _gid = r.u32()
            gcount = r.u32()
            for _ in range(gcount):
                _gflag = r.u8()
                gsize = r.u32()
                g_after = r.p
                gtag = r.u32()
                g_end = g_after + gsize
                if gtag == 0x19:
                    r.u8()
                    nlen = r.u8()
                    vname = r.take(nlen).decode("utf-8", "replace")
                    if (gsize - nlen - 4) == 7:
                        r.u8()
                    major = r.u16()
                    minor = r.u16()
                    print(f"  SW image: {vname} {major}.{minor}")
                r.p = g_end

        r.p = end
    return items


def stream_decrypt(fh, offset: int, size: int, key: bytes, salt: bytes,
                   out_path: Path, chunk: int = 1 << 22) -> int:
    """CBC-decrypt [offset, offset+size) to out_path without loading it all."""
    iv = hashlib.sha256(salt).digest()[:16]
    fh.seek(offset)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    remaining = size
    written = 0
    tail = b""
    with open(out_path, "wb") as out:
        while remaining > 0:
            n = min(chunk, remaining)
            n -= n % 16
            if n == 0:
                break
            block = fh.read(n)
            if len(block) != n:
                raise ValueError(f"short read in body: {len(block)} != {n}")
            pt = dec.update(block)
            # hold back last block until we know if padding applies
            if tail:
                out.write(tail)
                written += len(tail)
            tail = pt
            remaining -= n
        # flush, stripping PKCS#7 from the very end
        final = dec.finalize()
        tail += final
        if tail:
            pad = tail[-1]
            if 1 <= pad <= 16 and tail[-pad:] == bytes([pad]) * pad:
                tail = tail[:-pad]
            out.write(tail)
            written += len(tail)
    return written


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: msd11_extract.py <zip|msd> [--out DIR] [--only NAME] [--list]")
        return 2

    src = Path(sys.argv[1])
    out_dir = Path("./extract")
    only = None
    list_only = "--list" in sys.argv
    if "--out" in sys.argv:
        out_dir = Path(sys.argv[sys.argv.index("--out") + 1])
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]

    # A firmware zip can hold several images with DIFFERENT key types (e.g. the
    # LS03B bundle carries both T-PTMUABC "PontusM rel key" and T-PTMLUABC
    # "PONTUSML rel key"). Do not guess from the name: try every member and
    # adopt the first whose TOC actually authenticates against a published key.
    # The signature check is the ground truth, not the filename.
    opened = []
    if src.suffix.lower() == ".zip":
        z = zipfile.ZipFile(src)
        cands = sorted(n for n in z.namelist() if n.lower().endswith(".msd"))
    else:
        z = None
        cands = [None]

    chosen = None
    try:
        for c in cands:
            fh = z.open(c) if z else open(src, "rb")
            try:
                hdr = parse_header(fh)
                h0 = hdr["headers"][0]
                fh.seek(h0["offset"] + 8)
                toc_cipher = fh.read(h0["size"] - 8)
                for kn, hk in MSD11_KEYS.items():
                    try:
                        pt = decrypt_salted(toc_cipher, bytes.fromhex(hk))
                    except Exception:
                        continue
                    if toc_ok(pt):
                        chosen = (fh, hdr, c, kn, bytes.fromhex(hk), pt)
                        break
            except Exception:
                pass
            if chosen:
                break
            fh.close()

        if not chosen:
            print("  no published key matched any image in this container")
            return 1

        fh, hdr, member, key_name, key_bytes, toc = chosen
        print(f"=== {src.name} :: {member or src.name} ===")

        print(f"  key: {key_name}  (TOC signature verified)")
        print("\n=== items ===")
        items = parse_toc(toc)
        secs = hdr["sections"]
        for i, it in enumerate(items):
            sec = secs[i] if i < len(secs) else None
            sz = sec["size"] if sec else 0
            print(f"  [{it['item_id']:>2}] {it['name']:<28} "
                  f"aes={str(it['aes']):<5} size={sz:>15,} "
                  f"orig={it['orig']:>15,}")
        if list_only:
            return 0

        out_dir.mkdir(parents=True, exist_ok=True)
        for i, it in enumerate(items):
            if only and only.lower() not in (it["name"] or "").lower():
                continue
            if i >= len(secs):
                continue
            sec = secs[i]
            target = out_dir / (it["name"] or f"item{it['item_id']}")
            print(f"\n  extracting {it['name']} ({sec['size']:,} bytes)...")
            if it["aes"] and it["salt"]:
                n = stream_decrypt(fh, sec["offset"], sec["size"], key_bytes,
                                   it["salt"], target)
            else:
                fh.seek(sec["offset"])
                data = fh.read(sec["size"])
                target.write_bytes(data)
                n = len(data)
            got = target.stat().st_size
            print(f"    -> {target} ({got:,} bytes)")
            if it["orig"] and got != it["orig"]:
                print(f"       note: orig_size says {it['orig']:,}")
        return 0
    finally:
        fh.close()
        if z:
            z.close()


if __name__ == "__main__":
    sys.exit(main())
