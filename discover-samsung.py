#!/usr/bin/env python3
"""Find a Samsung TV on the LAN. Read-only discovery — no auth attempts, no writes.

Usage: python3 discover-samsung.py [--subnet 192.168.50]
"""
import socket, subprocess, sys, time, concurrent.futures, json, ipaddress

SUBNET = "192.168.50"
if "--subnet" in sys.argv:
    SUBNET = sys.argv[sys.argv.index("--subnet") + 1]

# Ports a Samsung Tizen TV is known to listen on
TV_PORTS = {
    8001: "Tizen websocket (remote control)",
    8002: "Tizen websocket (secure / msf)",
    26101: "SDB (Samsung Debug Bridge) - dev mode",
    9197: "Samsung (DMR / AllShare)",
    55000: "Samsung (old DTV app)",
    7676: "Samsung second screen",
    52235: "Samsung DTV (legacy)",
    8008: "Google Cast / DIAL",
    8009: "Google Cast (chromecast)",
    5555: "ADB (Android TV)",
    8080: "HTTP (generic)",
    8000: "HTTP (generic)",
}


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def ssdp(st, timeout=3.0):
    """Send an SSDP M-SEARCH and collect responders."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: 2\r\nST: {st}\r\n\r\n"
    )
    out = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
        s.settimeout(1.0)
        for _ in range(2):
            s.sendto(msg.encode(), ("239.255.255.250", 1900))
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                data, addr = s.recvfrom(65507)
            except socket.timeout:
                continue
            hdrs = {}
            for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            out.setdefault(addr[0], []).append({
                "st": st,
                "server": hdrs.get("server", ""),
                "location": hdrs.get("location", ""),
                "usn": hdrs.get("usn", ""),
            })
        s.close()
    except Exception:
        pass
    return out


def ping(ip):
    r = subprocess.run(
        ["ping", "-c1", "-W1", ip],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return ip if r.returncode == 0 else None


def portprobe(args):
    ip, port = args
    try:
        c = socket.socket()
        c.settimeout(0.6)
        c.connect((ip, port))
        try:
            c.settimeout(1.5)
            c.sendall(b"GET / HTTP/1.0\r\n\r\n")
            banner = c.recv(200).decode("utf-8", "replace").splitlines()
        except Exception:
            banner = []
        c.close()
        return (ip, port, banner[0][:80] if banner else "")
    except Exception:
        return None


def main():
    ip = local_ip()
    print(f"=== Samsung TV discovery on {SUBNET}.0/24 ===")
    print(f"this host: {ip}")
    print()

    # 1. mDNS / avahi
    print("--- mDNS (avahi-browse) ---")
    try:
        r = subprocess.run(["avahi-browse", "-a", "-t", "-p"],
                           capture_output=True, text=True, timeout=20)
        hits = [l for l in r.stdout.splitlines()
                if any(k in l.lower() for k in ("samsung", "tizen", "airplay", "_androidtvremote", "googlecast"))]
        print("\n".join(hits) if hits else "(no samsung/tizen/airplay service advertised)")
    except FileNotFoundError:
        print("(avahi-browse not installed)")
    except Exception as e:
        print(f"(mDNS error: {e})")
    print()

    # 2. SSDP
    print("--- SSDP ---")
    targets = [
        "ssdp:all",
        "urn:samsung.com:device:RemoteControlReceiver:1",
        "urn:samsung.com:device:MainTVServer2:1",
        "urn:samsung.com:device:TVServer:1",
        "urn:schemas-upnp-org:device:MediaRenderer:1",
    ]
    found = {}
    for st in targets:
        for k, v in ssdp(st).items():
            found.setdefault(k, []).extend(v)
    if found:
        for a in sorted(found, key=lambda x: [int(p) for p in x.split(".")]):
            print(f"{a}")
            for e in found[a][:4]:
                if e["server"]:
                    print(f"    server: {e['server'][:70]}")
                if e["location"]:
                    print(f"    {e['location'][:70]}")
    else:
        print("(no SSDP responders)")
    print()

    # 3. Live hosts via ARP + ping sweep
    print("--- host sweep ---")
    ips = [f"{SUBNET}.{i}" for i in range(1, 255)]
    live = set()
    with concurrent.futures.ThreadPoolExecutor(128) as ex:
        for r in ex.map(ping, ips):
            if r:
                live.add(r)
    # add anything already in ARP
    try:
        arp = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
        for line in arp.splitlines():
            p = line.split()
            if len(p) >= 5 and p[1] == "dev" and "INCOMPLETE" not in line and "FAILED" not in line:
                if p[0].startswith(SUBNET + "."):
                    live.add(p[0])
    except Exception:
        pass
    print(f"live hosts: {len(live)} — {', '.join(sorted(live, key=lambda x: int(x.split('.')[-1])))}")
    print()

    # 4. Port scan on live hosts
    print("--- TV port scan ---")
    tasks = [(h, p) for h in live for p in TV_PORTS]
    hits = []
    with concurrent.futures.ThreadPoolExecutor(64) as ex:
        for r in ex.map(portprobe, tasks):
            if r:
                hits.append(r)
    if hits:
        for h, p, banner in sorted(hits, key=lambda x: (x[0], x[1])):
            print(f"{h}:{p:<6} OPEN   {TV_PORTS[p]}" + (f"  [{banner}]" if banner else ""))
    else:
        print("(no TV ports open on any live host)")
    print()

    # 5. Verdict
    print("=== VERDICT ===")
    samsung_ips = {a for a, ev in found.items()
                   for e in ev if "samsung" in (e.get("server", "") + e.get("st", "")).lower()}
    tv_ports_open = {h for h, p, _ in hits if p in (8001, 8002, 26101, 9197)}
    cand = samsung_ips | tv_ports_open
    if cand:
        print(f"Samsung/Tizen TV likely at: {', '.join(sorted(cand))}")
    else:
        print("No Samsung TV detected. TV is probably powered off, or on a different")
        print("network/VLAN than this host (e.g. 2.4GHz-only SSID with client isolation).")


if __name__ == "__main__":
    main()
