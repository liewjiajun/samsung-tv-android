#!/usr/bin/env python3
"""
Test suite for the native SDB client. Runs against mock_sdbd.py — no hardware.

Found two real bugs during development, which is why this exists:
  1. Client sent a redundant CLSE for an already-closed channel.
  2. Mock read the AUTH reply before consuming the client's opening CNXN.
Both were silent connection resets. Neither would have been visible without a
harness that speaks the real wire protocol.

Run:  python3 test_sdb_native.py
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import mock_sdbd  # noqa: E402
import sdb_native as S  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(f"{name}: {detail}")
        print(f"  FAIL  {name}  {detail}")


def test_framing() -> None:
    print("\n[framing]")
    for payload in (b"", b"hello", bytes(range(256)), b"x" * 5000):
        frame = S.Frame(S.WRTE, 1, 2, payload)
        decoded = S.Frame.decode(frame.encode())
        check(
            f"round-trip {len(payload)}B",
            decoded.payload == payload
            and decoded.arg0 == 1
            and decoded.arg1 == 2,
        )

    raw = bytearray(S.Frame(S.WRTE, 1, 2, b"data").encode())
    raw[24] ^= 0xFF
    try:
        S.Frame.decode(bytes(raw))
        check("rejects corrupted checksum", False, "accepted bad checksum")
    except S.SdbError:
        check("rejects corrupted checksum", True)

    raw = bytearray(S.Frame(S.WRTE, 1, 2, b"data").encode())
    raw[20] ^= 0xFF
    try:
        S.Frame.decode(bytes(raw))
        check("rejects bad magic", False, "accepted bad magic")
    except S.SdbError:
        check("rejects bad magic", True)

    raw = bytearray(S.Frame(S.WRTE, 1, 2, b"data").encode())
    raw[12:16] = (999).to_bytes(4, "little")
    try:
        S.Frame.decode(bytes(raw))
        check("rejects length lie", False, "accepted wrong length")
    except S.SdbError:
        check("rejects length lie", True)


def test_pubkey() -> None:
    print("\n[RSA / android pubkey blob]")
    key = S._ensure_key()
    blob = S._android_pubkey_blob(key)
    # 4 (words) + 4 (n0inv) + 256 (modulus) + 256 (rr) + 4 (exponent) = 524
    check("blob length 524", len(blob) == 524, f"got {len(blob)}")
    import struct

    words = struct.unpack("<I", blob[:4])[0]
    check("modulus words = 64", words == 64, f"got {words}")
    exponent = struct.unpack("<I", blob[-4:])[0]
    check("exponent = 65537", exponent == 65537, f"got {exponent}")

    signature = S._sign(key, b"test-token")
    check("signature is 256 bytes (RSA-2048)", len(signature) == 256, f"got {len(signature)}")


def test_handshake(secure: bool) -> None:
    label = "secure AUTH" if secure else "plain CNXN"
    print(f"\n[{label} handshake]")
    box: dict = {}
    server, box = mock_sdbd.serve(0, secure=secure, port_box=box)
    client = S.SdbClient("127.0.0.1", box["port"])
    try:
        device_id = client.connect()
        check(f"{label}: connects", bool(device_id), "no device id")
        if secure:
            check(f"{label}: RSA signature exchanged", bool(box.get("auth_signature")))

        caps = client.capability(timeout=3)
        check(f"{label}: capability parsed", len(caps) >= 5, f"got {len(caps)}")
        check(
            f"{label}: arch is userspace-only signal",
            caps.get("cpu_arch") == "armv7",
        )

        accepted = client.shell("0 getduid", timeout=3).strip()
        check(f"{label}: known verb accepted", accepted.startswith("verb-accepted"))

        rejected = client.shell("0 bogus_verb", timeout=3).strip()
        check(f"{label}: unknown verb rejected", rejected.lower() == "closed")

        # repeat calls must not kill the session (regression: redundant CLSE bug)
        again = client.shell("0 getduid", timeout=3).strip()
        check(f"{label}: session survives repeat call", again.startswith("verb-accepted"))
    except Exception:
        check(f"{label}: no exception", False)
        traceback.print_exc()
    finally:
        client.close()
        server.close()


def test_verb_probe() -> None:
    print("\n[verb probe against mock]")
    box: dict = {}
    server, box = mock_sdbd.serve(0, port_box=box)
    try:
        findings = S.sdb_verb_probe("127.0.0.1", box["port"], timeout=2.0)
        accepted = [c for c, ok, _ in findings if ok]
        check("probe returns findings", len(findings) > 0, f"got {len(findings)}")
        check("probe finds accepted verbs", len(accepted) > 0, "none accepted")
    finally:
        server.close()


if __name__ == "__main__":
    print("=" * 62)
    print("native SDB client test suite (mock sdbd, no hardware)")
    print("=" * 62)
    test_framing()
    test_pubkey()
    test_handshake(secure=False)
    test_handshake(secure=True)
    test_verb_probe()

    print("\n" + "=" * 62)
    print(f"passed: {len(PASSED)}   failed: {len(FAILED)}")
    if FAILED:
        for item in FAILED:
            print(f"  - {item}")
        sys.exit(1)
    print("ALL TESTS PASSED")
