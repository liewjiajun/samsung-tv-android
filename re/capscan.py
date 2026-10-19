#!/usr/bin/env python3
"""capscan.py - every capability-bearing file in a VDFS4 rootfs, ranked by
whether it actually GRANTS capabilities on exec.

The distinction that matters, per capabilities(7):

    P'(permitted) = (P(inheritable) & F(inheritable)) | (F(permitted) & P(bounding))
    P'(effective) = F(effective) ? P'(permitted) : P'(ambient)

A file whose *permitted* set is empty grants nothing to a normally-spawned
process, because P(inheritable) is 0 in any process that did not explicitly
set it. Such a file still reports as capability-bearing in `getcap` (the
inheritable bits are printed), which is why "=ei" alone is not evidence that
executing it yields privileges.

Only files with a non-empty PERMITTED set are usable levers.

Usage: capscan.py <platform.img>
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vdfs4 as V
from vdfs4_capdecode import decode, getcap_text

from vdfs4_capdecode import CAP as _FULL_CAP

# Use the full capability table: an earlier hand-written subset silently printed
# '-' for any bit outside it, which made real capabilities look like none.
CAP_BITS = {i: n[4:] for i, n in _FULL_CAP.items()}


def short(mask: int) -> str:
    if not mask:
        return '-'
    known = [CAP_BITS[i] for i in sorted(CAP_BITS) if mask >> i & 1]
    unknown = [f'bit{i}' for i in range(64) if mask >> i & 1 and i not in CAP_BITS]
    return ','.join(known + unknown)


def build_paths(img) -> dict[int, list[str]]:
    """object_id -> every path that references it (hardlinks share an id)."""
    kids: dict[int, list] = {}
    for rec in img.iter_leaf_records(V.CAT_TREE_INO):
        k = V.parse_cat_key(rec)
        if not k or k['key_len'] == 0 or k['name_len'] == 0:
            continue
        kids.setdefault(k['parent_id'], []).append(
            (k['object_id'], k['name'], k['record_type']))

    root_pid = next((p for p, ch in kids.items()
                     if any(n == 'root' for _, n, _ in ch)), None)
    if root_pid is None:
        raise SystemExit('no root directory found')

    paths: dict[int, list[str]] = {}
    stack = [(kids[root_pid][0][0], '')]
    seen = set()
    while stack:
        pid, pre = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for oid, nm, typ in kids.get(pid, []):
            p = pre + '/' + nm
            paths.setdefault(oid, []).append(p)
            if typ == V.REC_FOLDER and len(p) < 200:
                stack.append((oid, p))
    return paths


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    img = V.Vdfs4(Path(sys.argv[1]))
    print('building path map...', flush=True)
    paths = build_paths(img)
    print(f'  {len(paths):,} objects\n', flush=True)

    rows = []
    for rec in img.iter_leaf_records(V.XATTR_TREE_INO):
        if len(rec) < 17:
            continue
        oid = V.u64(rec, 8)
        nl = rec[16]
        name = rec[17:17 + nl].decode('latin1', 'replace')
        if name != 'security.capability':
            continue
        kl, rl = V.u16(rec, 4), V.u16(rec, 6)
        try:
            d = decode(rec[kl:rl])
        except Exception:
            continue
        for p in paths.get(oid, [f'<unresolved {oid}>']):
            rows.append((p, d))

    levers = [r for r in rows if r[1]['permitted']]
    inert = [r for r in rows if not r[1]['permitted']]

    print(f'capability-bearing files: {len(rows)}')
    print(f'  GRANT on exec (permitted non-empty): {len(levers)}')
    print(f'  DO NOT grant (permitted empty):      {len(inert)}\n')

    levers.sort(key=lambda r: (-bin(r[1]['permitted']).count('1'), r[0]))
    print('=== levers: executing these yields these capabilities ===')
    for p, d in levers[:40]:
        print(f'  {short(d["permitted"]):58} {p}')
    if len(levers) > 40:
        print(f'  ... {len(levers) - 40} more')

    print('\n=== inert: capability xattr present but grants nothing ===')
    for p, d in sorted(inert)[:15]:
        # permitted is empty by definition here; show what is actually set so the
        # difference from a real lever is visible rather than implied.
        union = sorted(set(d['perm_names']) | set(d['inh_names']))
        flags = ('e' if d['effective'] else '') + \
                ('i' if d['inheritable'] else '') + \
                ('p' if d['permitted'] else '')
        text = (','.join(union) or '(none)') + '=' + flags
        print(f'  {text:52} {p}')

    print('\n=== per-object caveat ===')
    print('  A file listed as inert may still be reachable when exec\'d by a parent')
    print('  that already holds the inheritable bits. Verify on device before')
    print('  concluding any route is open or closed.')

    img.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
