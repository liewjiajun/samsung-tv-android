#!/usr/bin/env python3
"""
Diagnose why the published MSD11 keys fail on this image.

Tries each key under every plausible Tizen/OpenSSL derivation and reports which
produce valid PKCS#7 padding, and whether the OUITH signature appears anywhere
in the plaintext. Read-only on local files.
"""
import hashlib
import struct
import sys
import zipfile
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
    "NikeM": "dd18df36fdbbd957bcdf1a69aa5c06d6",
    "KantM2": "29110e0ce940b3a9b67d3e158f3f1342",
}

SIGS = (b"Tizen Software Upgrade Tree Binary Format ver. 1.8",
        b"Tizen Software Upgrade Tree Binary Format ver. 1.9")


def dec(key, iv, data):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def pad_ok(b):
    if not b:
        return False
    p = b[-1]
    return 1 <= p <= 16 and p <= len(b) and b[-p:] == bytes([p]) * p


def evp_bytes_to_key(pw, salt, klen, ivlen, hfun):
    """Standard OpenSSL EVP_BytesToKey."""
    out = b""
    prev = b""
    while len(out) < klen + ivlen:
        prev = hfun(prev + pw + salt).digest()
        out += prev
    return out[:klen], out[klen:klen + ivlen]


def main():
    path = Path(sys.argv[1])
    z = zipfile.ZipFile(path)
    name = sorted(n for n in z.namelist() if n.lower().endswith(".msd"))[0]
    fh = z.open(name)

    # parse header
    fh.read(6)
    fh.read(4)
    fh.read(8)
    sc = struct.unpack("<I", fh.read(4))[0]
    for _ in range(sc):
        fh.read(20)
    hc = struct.unpack("<I", fh.read(4))[0]
    headers = []
    for _ in range(hc):
        off = struct.unpack("<Q", fh.read(8))[0]
        sz = struct.unpack("<I", fh.read(4))[0]
        nl = fh.read(1)[0]
        nm = fh.read(nl).decode()
        headers.append((off, sz, nm))

    off, sz, nm = headers[0]
    fh.seek(off + 8)
    blob = fh.read(sz - 8)
    fh.close()
    z.close()

    print(f"TOC blob: {len(blob):,} bytes, prefix={blob[:8]!r}")
    salt = blob[8:16]
    body = blob[16:]
    print(f"salt: {salt.hex()}")
    print(f"body: {len(body):,} bytes (multiple of 16: {len(body) % 16 == 0})\n")

    hits = 0
    for kname, hexkey in MSD11_KEYS.items():
        K = bytes.fromhex(hexkey)
        variants = {}

        # 1. unixtract style: key = K, iv = sha256(salt)[:16]
        if len(K) == 32:
            variants["sha256(salt) iv, K as key"] = (K, hashlib.sha256(salt).digest()[:16])
            # 2. EVP_BytesToKey sha256
            variants["EVP_BytesToKey sha256"] = evp_bytes_to_key(K, salt, 32, 16, hashlib.sha256)
            # 3. EVP_BytesToKey md5
            variants["EVP_BytesToKey md5"] = evp_bytes_to_key(K, salt, 32, 16, hashlib.md5)
        if len(K) == 16:
            variants["md5(salt) iv, K as key"] = (K, hashlib.md5(salt).digest())
            variants["EVP_BytesToKey md5"] = evp_bytes_to_key(K, salt, 16, 16, hashlib.md5)

        for vname, (key, iv) in variants.items():
            try:
                pt = dec(key, iv, body)
            except Exception:
                continue
            ok = pad_ok(pt)
            sig_hit = None
            for s in SIGS:
                pos = pt.find(s)
                if pos != -1:
                    sig_hit = (pos, s.decode())
                    break
            if ok or sig_hit:
                hits += 1
                print(f"  [{kname}] {vname}")
                print(f"      padding_ok={ok}  sig={sig_hit}")
                print(f"      head: {pt[:48]!r}")

    if not hits:
        print("  No key/derivation produced valid padding or a signature.")
        print("\n  Control: check the derivation is even reachable —")
        print("  decrypting with a wrong key should give random padding, but")
        print("  ~1/256 of wrong keys pass padding by luck. Zero passes here")
        print("  means the *container* assumption may be off, not just the key.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
