#!/usr/bin/env python3
"""xfile.py - extract files (or a whole tree) from a VDFS4 image.

Needed because 16,937 of the 59,381 files are compressed and the interesting
ones (launchers, UEP library) are all in that set.

Usage:
  xfile.py <platform.img> get <path> [outdir]     one file
  xfile.py <platform.img> ls <substring>          list matching paths
  xfile.py <platform.img> tree <prefix> <outdir>  extract everything under a path
  xfile.py <platform.img> cat <path>              write file to stdout

Every extraction is reported with size and, for ELF, class/machine so a silent
decompression failure is visible instead of looking like a small file.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vdfs4 as V


def build(img):
    """object_id -> [paths] and path -> (record, key). Hardlinks share ids."""
    kids = {}
    for rec in img.iter_leaf_records(V.CAT_TREE_INO):
        k = V.parse_cat_key(rec)
        if not k or k['key_len'] == 0 or k['name_len'] == 0:
            continue
        kids.setdefault(k['parent_id'], []).append(
            (k['object_id'], k['name'], k['record_type'], rec, k))

    root_pid = next((p for p, ch in kids.items()
                     if any(n == 'root' for _, n, _, _, _ in ch)), None)
    if root_pid is None:
        raise SystemExit('no root directory')

    files = {}
    stack = [(kids[root_pid][0][0], '')]
    seen = set()
    while stack:
        pid, pre = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for oid, nm, typ, rec, k in kids.get(pid, []):
            p = pre + '/' + nm
            if typ == V.REC_FILE:
                files[p] = (rec, k)
            elif typ == V.REC_FOLDER and len(p) < 200:
                stack.append((oid, p))
    return files


def describe(data: bytes) -> str:
    if data[:4] == b'\x7fELF':
        cls = {1: '32', 2: '64'}.get(data[4], '?')
        mach = int.from_bytes(data[18:20], 'little')
        return f'ELF{cls} machine=0x{mach:x}'
    if data[:2] == b'#!':
        return 'script ' + data[:32].decode('latin1').split('\n')[0]
    return f'{data[:8].hex()}'


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    img = V.Vdfs4(Path(sys.argv[1]))
    cmd = sys.argv[2]

    if cmd == 'ls':
        pat = sys.argv[3].lower()
        for p in sorted(build(img)):
            if pat in p.lower():
                print(p)
        img.close()
        return 0

    files = build(img)

    if cmd == 'get':
        path = sys.argv[3]
        outdir = Path(sys.argv[4]) if len(sys.argv) > 4 else Path('.')
        if path not in files:
            print(f'not found: {path}', file=sys.stderr)
            return 1
        rec, k = files[path]
        try:
            data = V.read_file(img, rec, k)
        except Exception as e:
            print(f'{path}: {type(e).__name__}: {e}', file=sys.stderr)
            return 1
        out = outdir / path.rsplit('/', 1)[-1]
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        print(f'{path} -> {out} ({len(data)}B, {describe(data)})')
        img.close()
        return 0

    if cmd == 'cat':
        path = sys.argv[3]
        if path not in files:
            print(f'not found: {path}', file=sys.stderr)
            return 1
        rec, k = files[path]
        sys.stdout.buffer.write(V.read_file(img, rec, k))
        img.close()
        return 0

    if cmd == 'tree':
        prefix = sys.argv[3]
        outdir = Path(sys.argv[4])
        n = bad = 0
        for p in sorted(files):
            if not p.startswith(prefix):
                continue
            rec, k = files[p]
            try:
                data = V.read_file(img, rec, k)
            except Exception as e:
                bad += 1
                print(f'  FAIL {p}: {e}', file=sys.stderr)
                continue
            out = outdir / p.lstrip('/')
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            n += 1
        print(f'extracted {n} files, {bad} failures -> {outdir}')
        img.close()
        return 0

    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main())
