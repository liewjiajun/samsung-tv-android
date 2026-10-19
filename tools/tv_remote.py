#!/usr/bin/env python3
"""Drive an unmodified Samsung Tizen TV over its websocket remote-control API.

Purpose: reach UI that has no visible Settings entry (e.g. the hidden
developer-mode dialog) without hunting menus, and capture the control token.

Auth model: token-auth sets show an on-screen Allow prompt on first connect and
stay on ms.channel.unauthorized until a human presses Allow with the physical
remote. Reconnecting while the prompt is up re-triggers the prompt and is
counter-productive, so `pair` holds ONE socket open and waits quietly.

Usage:
  tv_remote.py pair  [--wait S]         # hold one socket open for Allow
  tv_remote.py keys KEY_1 KEY_2 ...     # send key clicks (needs token)
  tv_remote.py text 12345               # digit helper (needs token)
"""

import argparse
import base64
import json
import os
import sys
import time

TV_IP = os.environ.get("TV_IP", "192.168.50.49")
TOKEN_FILE = os.path.expanduser("~/.tv_remote_token")
APP_NAME = "CrawdRemote"
PORTS = [8001, 8002]


def _url(port, token=""):
    name = base64.b64encode(APP_NAME.encode()).decode()
    u = f"ws://{TV_IP}:{port}/api/v2/channels/samsung.remote.control?name={name}"
    if token:
        u += f"&token={token}"
    return u


def _load_token():
    try:
        with open(TOKEN_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


def _save_token(tok):
    if not tok:
        return False
    try:
        with open(TOKEN_FILE, "w") as f:
            f.write(tok)
        os.chmod(TOKEN_FILE, 0o600)
        return True
    except OSError as e:
        print(f"[warn] cannot save token: {e}", file=sys.stderr)
        return False


def pair(wait=900):
    """Hold one open socket and wait for the human to press Allow."""
    import websocket

    tok = _load_token()
    print(f"[pair] connecting (cached token: {'yes' if tok else 'no'})", flush=True)
    ws = websocket.create_connection(
        _url(8001, tok), timeout=15, sslopt={"cert_reqs": "CERT_NONE"}
    )
    print("[pair] socket open — waiting for Allow on TV", flush=True)
    deadline = time.time() + wait
    prompted = False
    while time.time() < deadline:
        try:
            raw = ws.recv()
        except Exception as e:
            msg = str(e)
            if "1005" in msg or "opcode" in msg:
                # TV sent an empty close frame; harmless, keep the loop alive.
                time.sleep(1)
                continue
            print(f"[pair] recv ended: {msg}", flush=True)
            break
        if not raw:
            continue
        try:
            m = json.loads(raw)
        except json.JSONDecodeError:
            continue
        ev = m.get("event", "")
        if ev == "ms.channel.unauthorized" and not prompted:
            print("[pair] PROMPT VISIBLE — press Allow with the remote", flush=True)
            prompted = True
            continue
        if ev == "ms.channel.connect":
            newtok = (m.get("data") or {}).get("token")
            if newtok and _save_token(newtok):
                print("[pair] AUTHORIZED — token saved", flush=True)
            else:
                print("[pair] AUTHORIZED (cached token accepted)", flush=True)
            ws.close()
            return 0
    try:
        ws.close()
    except Exception:
        pass
    print("[pair] timed out without authorization", flush=True)
    return 2


def _send(ws, key):
    ws.send(json.dumps({
        "method": "ms.remote.control",
        "params": {
            "Cmd": "Click",
            "DataOfCmd": key,
            "Option": "false",
            "TypeOfRemote": "SendRemoteKey",
        },
    }))


def send(seq, delay):
    import websocket

    tok = _load_token()
    if not tok:
        print("NO_TOKEN — run `pair` and press Allow first", file=sys.stderr)
        return 3
    for port in PORTS:
        try:
            ws = websocket.create_connection(
                _url(port, tok), timeout=10, sslopt={"cert_reqs": "CERT_NONE"}
            )
        except Exception:
            continue
        try:
            first = ws.recv() or ""
            if "unauthorized" in first:
                continue
            for key in seq:
                print(f"[send] {key}", flush=True)
                _send(ws, key)
                time.sleep(delay)
            return 0
        finally:
            try:
                ws.close()
            except Exception:
                pass
    print("NO_CONNECTION", file=sys.stderr)
    return 4


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["pair", "keys", "text"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--wait", type=float, default=900)
    ap.add_argument("--delay", type=float, default=0.45)
    a = ap.parse_args()

    if a.action == "pair":
        return pair(a.wait)
    if a.action == "text":
        seq = [f"KEY_{c}" for c in "".join(a.args) if c.isdigit()]
    else:
        seq = a.args
    return send(seq, a.delay)


if __name__ == "__main__":
    sys.exit(main())
