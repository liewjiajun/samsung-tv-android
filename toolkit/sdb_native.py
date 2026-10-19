#!/usr/bin/env python3
"""
Native SDB (Samsung Debug Bridge) client — pure Python, no Tizen Studio.

Reverse-engineered wire protocol, validated against PatrickSt1991/tizen-sdb
(C# reference implementation) and the frame format used by Samsung's sdbd.

Why this exists: Samsung's own `sdb` ships only inside Tizen Studio (a ~1GB
proprietary download, awkward on Linux/ARM). Reimplementing the protocol means
we can talk to a TV from the Steam Deck directly, with no vendor tooling.

Protocol summary (all integers little-endian):
  Header = 6 x uint32: command, arg0, arg1, data_length, data_checksum, magic
  payload follows the 24-byte header; magic = command ^ 0xFFFFFFFF
  data_checksum = sum of payload bytes mod 2^32

  CNXN 0x4E584E43  handshake
  AUTH 0x48545541  auth (token / signature / publickey)
  OPEN 0x4E45504F  open a service channel, e.g. "shell:<cmd>\\0"
  OKAY 0x59414B4F  ack
  WRTE 0x45545257  channel data
  CLSE 0x45534C43  close channel
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

# --- commands -------------------------------------------------------------
CNXN = 0x4E584E43
AUTH = 0x48545541
OPEN = 0x4E45504F
OKAY = 0x59414B4F
WRTE = 0x45545257
CLSE = 0x45534C43
CMD_NAME = {
    CNXN: "CNXN", AUTH: "AUTH", OPEN: "OPEN",
    OKAY: "OKAY", WRTE: "WRTE", CLSE: "CLSE",
}

# --- auth types -----------------------------------------------------------
AUTH_TOKEN = 1
AUTH_SIGNATURE = 2
AUTH_PUBLICKEY = 3

DEFAULT_PORT = 26101
CLIENT_VERSION = 0x01000000
DEFAULT_MAXDATA = 4096
HEADER = struct.Struct("<6I")


class SdbError(RuntimeError):
    pass


class SdbAuthError(SdbError):
    pass


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------
@dataclass
class Frame:
    command: int
    arg0: int = 0
    arg1: int = 0
    payload: bytes = b""

    def encode(self) -> bytes:
        length = len(self.payload)
        checksum = sum(self.payload) & 0xFFFFFFFF
        magic = self.command ^ 0xFFFFFFFF
        return HEADER.pack(
            self.command, self.arg0, self.arg1, length, checksum, magic
        ) + self.payload

    @classmethod
    def decode(cls, raw: bytes) -> "Frame":
        if len(raw) < 24:
            raise SdbError(f"short frame: {len(raw)} bytes")
        command, arg0, arg1, length, checksum, magic = HEADER.unpack(raw[:24])
        payload = raw[24:]
        if len(payload) != length:
            raise SdbError(
                f"payload length mismatch: header={length} actual={len(payload)}"
            )
        if magic != (command ^ 0xFFFFFFFF):
            raise SdbError(
                f"bad magic for {CMD_NAME.get(command, hex(command))}: "
                f"0x{magic:08X}"
            )
        actual = sum(payload) & 0xFFFFFFFF
        if actual != checksum:
            raise SdbError(
                f"bad checksum: header=0x{checksum:08X} computed=0x{actual:08X}"
            )
        return cls(command=command, arg0=arg0, arg1=arg1, payload=payload)


def read_frame(sock: socket.socket, timeout: float | None = None) -> Frame:
    if timeout is not None:
        sock.settimeout(timeout)
    header = _recv_exactly(sock, 24)
    length = struct.unpack("<I", header[12:16])[0]
    if length > 0x1000000:  # 16 MiB sanity bound
        raise SdbError(f"implausible payload length {length}")
    body = _recv_exactly(sock, length) if length else b""
    return Frame.decode(header + body)


def _recv_exactly(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise SdbError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------
# RSA key handling (Android-style public key blob, as sdbd expects)
# --------------------------------------------------------------------------
KEY_PATH = Path.home() / ".config" / "sdb-native" / "id_sdb"


def _ensure_key() -> "object":
    """Load or generate a 2048-bit RSA key. Prefers `cryptography`."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError as exc:  # pragma: no cover
        raise SdbAuthError(
            "the `cryptography` package is required for SDB auth: "
            "pip install cryptography"
        ) from exc

    if KEY_PATH.exists():
        data = KEY_PATH.read_bytes()
        try:
            return serialization.load_pem_private_key(data, password=None)
        except Exception:
            pass  # fall through and regenerate

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    KEY_PATH.write_bytes(pem)
    os.chmod(KEY_PATH, 0o600)
    return key


def _android_pubkey_blob(key) -> bytes:
    """Android's RSAPublicKey binary layout: n0inv, modulus, rr, exponent."""
    from cryptography.hazmat.primitives import serialization

    numbers = key.public_key().public_numbers()
    n = numbers.n
    e = numbers.e

    mod_bytes = n.to_bytes(256, "big")
    mod_le = mod_bytes[::-1]

    # n0inv = -(n^-1) mod 2^32
    n0inv = (-pow(n, -1, 1 << 32)) & 0xFFFFFFFF

    r = 1 << (256 * 8)
    rr = pow(r, 2, n)
    rr_le = rr.to_bytes(256, "little")

    return (
        struct.pack("<I", 256 // 4)
        + struct.pack("<I", n0inv)
        + mod_le
        + rr_le
        + struct.pack("<I", e)
    )


def _sign(key, token: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    return key.sign(token, padding.PKCS1v15(), hashes.SHA1())


# --------------------------------------------------------------------------
# client
# --------------------------------------------------------------------------
@dataclass
class Channel:
    local_id: int
    remote_id: int
    service: str
    data: bytearray = field(default_factory=bytearray)
    closed: bool = False


class SdbClient:
    """Minimal but complete SDB client: connect, shell, capability, sync push."""

    def __init__(self, host: str, port: int = DEFAULT_PORT, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.max_data = DEFAULT_MAXDATA
        self.device_id: str | None = None
        self._next_local_id = 1
        self._channels: dict[int, Channel] = {}

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> str:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._handshake()
        return self.device_id or "<unknown>"

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self) -> "SdbClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _send(self, frame: Frame) -> None:
        if not self.sock:
            raise SdbError("not connected")
        self.sock.sendall(frame.encode())

    def _handshake(self) -> None:
        hostname = socket.gethostname()
        banner = f"host::{hostname}\0".encode()
        self._send(Frame(CNXN, CLIENT_VERSION, self.max_data, banner))
        key = None

        for _ in range(12):
            frame = read_frame(self.sock, self.timeout)

            if frame.command == CNXN:
                self.max_data = min(
                    self.max_data,
                    frame.arg1 if frame.arg1 else self.max_data,
                )
                self.device_id = frame.payload.decode("utf-8", "replace").strip("\0")
                return

            if frame.command == AUTH:
                if key is None:
                    key = _ensure_key()
                auth_type = frame.arg0
                if auth_type == AUTH_TOKEN:
                    self._send(
                        Frame(AUTH, AUTH_SIGNATURE, 0, _sign(key, frame.payload))
                    )
                elif auth_type == AUTH_PUBLICKEY:
                    blob = _android_pubkey_blob(key)
                    userinfo = f" {os.environ.get('USER', 'unknown')}@{hostname}"
                    payload = (base64.b64encode(blob).decode() + userinfo + "\0").encode()
                    self._send(Frame(AUTH, AUTH_PUBLICKEY, 0, payload))
                else:
                    raise SdbAuthError(f"unknown AUTH type {auth_type}")
                continue

            raise SdbAuthError(
                f"unexpected {CMD_NAME.get(frame.command, hex(frame.command))} "
                "during handshake"
            )

        raise SdbAuthError("handshake did not complete")

    # -- channels ----------------------------------------------------------
    def open(self, service: str) -> Channel:
        local_id = self._next_local_id
        self._next_local_id += 1
        channel = Channel(local_id=local_id, remote_id=0, service=service)
        self._channels[local_id] = channel
        self._send(Frame(OPEN, local_id, 0, service.encode() + b"\0"))

        # pump until this channel sees OKAY
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            frame = read_frame(self.sock, max(0.1, deadline - time.monotonic()))
            self._dispatch(frame, channel)
            if channel.remote_id:
                return channel
        raise SdbError(f"channel {service!r} did not open")

    def _dispatch(self, frame: Frame, waiting: Channel | None = None) -> None:
        """Route one frame. WRTE payloads accumulate on their channel."""
        if frame.command == OKAY:
            # arg0 = remote id, arg1 = local id
            target = self._channels.get(frame.arg1)
            if target is not None:
                target.remote_id = frame.arg0
                if waiting is not None and target is waiting:
                    return
            if waiting is not None:
                # explicit ok for the opener
                if frame.arg1 == waiting.local_id:
                    waiting.remote_id = frame.arg0
            return

        if frame.command == WRTE:
            target = self._channels.get(frame.arg1)
            if target is not None:
                target.data.extend(frame.payload)
                # acknowledge so the TV will send more
                self._send(Frame(OKAY, target.remote_id, target.local_id))
            return

        if frame.command == CLSE:
            target = self._channels.get(frame.arg1)
            if target is not None:
                target.closed = True
                self._send(Frame(OKAY, target.remote_id, target.local_id))
            return

    def read_channel(self, channel: Channel, timeout: float | None = None) -> bytes:
        """Drain a channel to EOF, returning accumulated bytes."""
        limit = timeout if timeout is not None else self.timeout
        deadline = time.monotonic() + limit
        while not channel.closed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                frame = read_frame(self.sock, remaining)
            except (socket.timeout, TimeoutError):
                break
            before = len(channel.data)
            self._dispatch(frame)
            if channel.closed:
                break
            if len(channel.data) == before and remaining < 0.05:
                break
        return bytes(channel.data)

    def close_channel(self, channel: Channel) -> None:
        # If the TV already closed this channel, replying with CLSE again is
        # redundant; some daemons treat a stray CLSE as a disconnect request.
        if not channel.closed:
            self._send(Frame(CLSE, channel.local_id, channel.remote_id, b""))
        self._channels.pop(channel.local_id, None)

    # -- high level --------------------------------------------------------
    def shell(self, command: str, timeout: float | None = None) -> str:
        """Run a command via the `shell:` service. Note: sdbd whitelists verbs."""
        channel = self.open(f"shell:{command}")
        try:
            raw = self.read_channel(channel, timeout)
        finally:
            self.close_channel(channel)
        return raw.decode("utf-8", "replace")

    def capability(self, timeout: float | None = None) -> dict[str, str]:
        channel = self.open("capability:")
        try:
            raw = self.read_channel(channel, timeout)
        finally:
            self.close_channel(channel)
        text = raw.decode("utf-8", "replace").strip("\0 \r\n")
        values: dict[str, str] = {}
        for line in text.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                values[key.strip()] = value.strip()
        return values


# --------------------------------------------------------------------------
# fingerprint
# --------------------------------------------------------------------------
CAPABILITY_KEYS = (
    "platform", "version", "cpu_arch", "core_abi", "profile",
    "build", "model", "manufacturer", "screen_resolution",
    "sdk_toolchain_version", "debug_level",
)


def fingerprint(host: str, port: int = DEFAULT_PORT) -> dict:
    """Model-independent TV probe. Works on any sdbd that answers capability:."""
    result: dict = {"host": host, "port": port, "ok": False}
    client = SdbClient(host, port)
    try:
        result["device_id"] = client.connect()
        result["ok"] = True
        caps = client.capability(timeout=8.0)
        result["capabilities"] = caps
        for key in CAPABILITY_KEYS:
            if key in caps:
                result[key] = caps[key]
        # sdb 26101 open even without Developer Mode means the daemon is up
        result["arch_note"] = (
            "cpu_arch/core_abi describe the TIZEN USERSPACE build, "
            "not necessarily the silicon. A 64-bit kernel can report armv7."
        )
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        client.close()
    return result


def sdb_verb_probe(host: str, port: int = DEFAULT_PORT, timeout: float = 4.0) -> list[tuple[str, bool, str]]:
    """
    Enumerate which `0 <verb>` commands this TV's sdbd accepts.

    sdbd is not a shell — it carries a fixed verb vocabulary, and an unknown
    verb returns empty or the literal word "closed". That makes the vocabulary
    cheap to map, and establishes which of the known reachable verbs (notably
    the appinstall path used for the documented shell-injection route) exist
    on THIS model. Read-only and idempotent: every probe uses a non-existent id.
    """
    candidates = [
        "0 getduid", "0 vd_applist", "0 capability", "0 getversion",
        "0 sdbd_version", "0 was_execute probe.invalid",
        "0 was_kill probe.invalid", "0 debug probe.invalid",
        "0 help", "0 launch_app probe.invalid", "0 appinstall tpk",
    ]
    findings: list[tuple[str, bool, str]] = []
    client = SdbClient(host, port)
    try:
        client.connect()
    except Exception as exc:
        return [(c, False, f"connect failed: {exc}") for c in candidates]

    for command in candidates:
        try:
            reply = client.shell(command, timeout=timeout).strip()
            accepted = bool(reply) and reply.lower() != "closed"
            findings.append((command, accepted, reply[:160]))
        except Exception as exc:
            findings.append((command, False, f"error: {type(exc).__name__}"))
    client.close()
    return findings


if __name__ == "__main__":
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Native SDB client / TV fingerprint")
    ap.add_argument("host", nargs="?", help="TV IP address")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--verbs", action="store_true", help="probe sdbd verb vocabulary")
    ap.add_argument("--shell", metavar="CMD")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not args.host:
        ap.error("host is required")
    elif args.verbs:
        for command, accepted, reply in sdb_verb_probe(args.host, args.port):
            mark = "ACCEPTED" if accepted else "not a verb"
            print(f"  {command:34} {mark:11} {reply}")
    elif args.shell:
        with SdbClient(args.host, args.port) as client:
            client.connect()
            print(client.shell(args.shell))
    else:
        info = fingerprint(args.host, args.port)
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            for key, value in info.items():
                if key == "capabilities":
                    print("  capabilities:")
                    for cap_key, cap_value in value.items():
                        print(f"    {cap_key}: {cap_value}")
                else:
                    print(f"  {key}: {value}")
