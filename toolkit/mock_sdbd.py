#!/usr/bin/env python3
"""
Mock sdbd — a fake Samsung TV debug daemon speaking the real SDB wire protocol.

Purpose: prove the native client (sdb_native.py) actually works end-to-end
without hardware. Validates framing, handshake (both CNXN-direct and the
secure AUTH path), channel open, WRTE/OKAY flow control, and shell routing.

This is the test harness that lets the toolkit be verified before it ever
touches a real television.
"""
from __future__ import annotations
import re, socket, struct, threading, sys

CNXN, AUTH, OPEN, OKAY, WRTE, CLSE = (
    0x4E584E43, 0x48545541, 0x4E45504F, 0x59414B4F, 0x45545257, 0x45534C43)
HEADER = struct.Struct("<6I")

# what our fake TV claims to be
CAPABILITY = """platform:1
version:9.0
cpu_arch:armv7
core_abi:arm_32
profile:rosel
model:QA55QEF1AULXL
manufacturer:Samsung
build:T-RSMFUABC-0090
debug_level:0
"""

VERBS = {"0 getduid", "0 vd_applist", "0 capability", "0 getversion",
         "0 was_execute", "0 was_kill", "0 debug", "0 rmfile"}

# A realistic Tizen package population for the mock TV: a mix of things the
# debloat tool must protect (remote/display/tuner), things it should remove
# (ads/telemetry/shopping), and things it must leave unclassified.
MOCK_PACKAGES = [
    # --- protected: remote, display, input switching, boot ---
    "com.smartdevice.livetv",
    "com.smartdevice.duplebluetooth",
    "com.smartdevice.dtv.icast",
    "com.smartdevice.factory",
    "org.tizen.tvinputdevice",
    "org.tizen.tvdisplay",
    "org.tizen.tvsettings",
    "org.tizen.tvnetwork",
    "org.tizen.tvaudio",
    # --- debloat: ads, ACR, telemetry, shopping ---
    "com.samsung.tv.acr",
    "com.smartdevice.acr.recommendation",
    "com.smartdevice.recommendation",
    "com.smartdevice.leanbacklauncher.customizer",
    "com.smartdevice.epopplayer",
    "com.sky.market",
    "com.samsung.tv.shopping",
    # --- user apps: must never be touched ---
    "com.netflix.ninja",
    "com.disney.disneyplus",
    "com.google.android.youtube.tv",
    # --- unclassified: REVIEW, left alone ---
    "com.smartdevice.emanual",
    "com.samsung.tv.something.unknown",
]

# packages the mock accepts a disable/enable for; mirrors real pkgcmd behaviour
_enabled: set[str] = set(MOCK_PACKAGES)


def _pkgcmd(command: str, pkg: str, *, disable: bool) -> bytes:
    """Emulate pkgcmd -D/-E well enough to exercise the client."""
    if pkg not in MOCK_PACKAGES:
        return b"Fail: package not found\n"
    if disable:
        _enabled.discard(pkg)
    else:
        _enabled.add(pkg)
    return ("Processing %s: %s\n" % (pkg, "Success" if disable else "Success")).encode()


def enc(cmd, a0=0, a1=0, payload=b""):
    return HEADER.pack(cmd, a0, a1, len(payload),
                       sum(payload) & 0xFFFFFFFF, cmd ^ 0xFFFFFFFF) + payload


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def read_frame(s):
    h = recv_exact(s, 24)
    if not h:
        return None
    cmd, a0, a1, ln, ck, mg = HEADER.unpack(h)
    pl = recv_exact(s, ln) if ln else b""
    if pl is None:
        return None
    if mg != (cmd ^ 0xFFFFFFFF):
        raise ValueError("bad magic")
    if (sum(pl) & 0xFFFFFFFF) != ck:
        raise ValueError("bad checksum")
    return cmd, a0, a1, pl


def handle(conn, *, secure: bool, port_box: dict):
    try:
        # --- handshake ---
        # The client opens with CNXN. A real sdbd reads it before deciding
        # whether to demand authentication, so consume it first.
        first = read_frame(conn)
        if first is None:
            return
        if first[0] != CNXN:
            port_box["unexpected_first_frame"] = first[0]
        if secure:
            # demand a signature first
            conn.sendall(enc(AUTH, 1, 0, b"challenge-token-0123456789"))
            fr = read_frame(conn)
            if not fr or fr[0] != AUTH or fr[1] != 2:
                return
            port_box["auth_signature"] = True
        # our CNXN reply, arg1 = our maxdata
        conn.sendall(enc(CNXN, 0x01000000, 4096, b"mock-tv::9.0\0"))

        channels: dict[int, str] = {}
        while True:
            fr = read_frame(conn)
            if fr is None:
                return
            cmd, a0, a1, pl = fr
            if cmd == CNXN:
                # duplicate client CNXN after handshake; ignore
                continue
            if cmd == OPEN:
                service = pl.rstrip(b"\0").decode("utf-8", "replace")
                rid = 100 + a0
                channels[rid] = service
                port_box.setdefault("services", []).append(service)
                conn.sendall(enc(OKAY, rid, a0))
                # stream the reply
                if service.startswith("capability"):
                    conn.sendall(enc(WRTE, rid, a0, CAPABILITY.encode()))
                    read_frame(conn)          # client OKAY
                elif service.startswith("shell:"):
                    command = service.split(":", 1)[1]
                    # strip a leading "0 " verb marker the way real sdbd does
                    verb = command.strip()
                    if verb.startswith("appinstall tpk"):
                        out = b"closed"      # the injection path exists but isn't a shell
                    elif verb.startswith("vd_applist") or verb.startswith("0 vd_applist"):
                        # the package inventory, one per line
                        body = "\n".join(sorted(_enabled)) + "\n"
                        out = body.encode()
                        port_box["applist_calls"] = port_box.get("applist_calls", 0) + 1
                    elif verb.startswith("pkgcmd"):
                        m = re.search(r"-([DE])\s+-n\s+(\S+)", verb)
                        if m:
                            out = _pkgcmd(verb, m.group(2), disable=(m.group(1) == "D"))
                        else:
                            out = b"Fail: bad pkgcmd syntax\n"
                    elif verb in VERBS or any(verb.startswith(v) for v in VERBS):
                        out = f"verb-accepted:{verb}\n".encode()
                    else:
                        out = b"closed"
                    conn.sendall(enc(WRTE, rid, a0, out))
                    read_frame(conn)
                conn.sendall(enc(CLSE, rid, a0))
                read_frame(conn)
            elif cmd == CLSE:
                # CLSE for a channel we still track means the client wants it
                # gone; a stray CLSE for an unknown id is not a disconnect.
                if a0 in channels:
                    channels.pop(a0, None)
                    continue
                return
    except Exception:
        pass
    finally:
        conn.close()


def serve(port=0, secure=False, port_box=None):
    port_box = port_box if port_box is not None else {}
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    port_box["port"] = srv.getsockname()[1]

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,),
                             kwargs={"secure": secure, "port_box": port_box},
                             daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv, port_box


if __name__ == "__main__":
    sec = "--secure" in sys.argv
    srv, box = serve(0, secure=sec)
    print(f"mock sdbd on 127.0.0.1:{box['port']} secure={sec}", flush=True)
    threading.Event().wait()
