#!/usr/bin/env python3
"""Decode a VDFS4 security.capability xattr value to getcap notation.

Layout is the Linux kernel ABI (vfs_cap_data rev2), little-endian:

    u32 magic_etc            (low byte = revision, 0x01 bit = EFFECTIVE)
    u32 data[2].permitted
    u32 data[2].inheritable
  => words: [P_lo, I_lo, P_hi, I_hi]

Ground truth is the getcap block in ROOTING-RESEARCH.md §5.1. The four vectors
disambiguate the two u32 orders, because getcap prints 'p' only when permitted
is non-empty:

    dotnet            =ei    no 'p'  -> permitted EMPTY
    dotnet-launcher   =ei    no 'p'  -> permitted EMPTY
    sdbd-tarlauncher  =eip        p  -> permitted non-empty
    launchpad-starter =eip        p  -> permitted non-empty

Only this order reproduces all four. The swapped order would put dotnet's bits
in permitted, which would have to print as '=ep', contradicting the record.
"""
import struct

CAP = {
    0: 'cap_chown', 1: 'cap_dac_override', 2: 'cap_dac_read_search',
    3: 'cap_fowner', 4: 'cap_fsetid', 5: 'cap_kill', 6: 'cap_setgid',
    7: 'cap_setuid', 8: 'cap_setpcap', 9: 'cap_linux_immutable',
    10: 'cap_net_bind_service', 11: 'cap_net_broadcast', 12: 'cap_net_admin',
    13: 'cap_net_raw', 14: 'cap_ipc_lock', 15: 'cap_ipc_owner',
    16: 'cap_sys_module', 17: 'cap_sys_rawio', 18: 'cap_sys_chroot',
    19: 'cap_sys_ptrace', 20: 'cap_sys_pacct', 21: 'cap_sys_admin',
    22: 'cap_sys_boot', 23: 'cap_sys_nice', 24: 'cap_sys_resource',
    25: 'cap_sys_time', 26: 'cap_sys_tty_config', 27: 'cap_mknod',
    28: 'cap_lease', 29: 'cap_audit_write', 30: 'cap_audit_control',
    31: 'cap_setfcap', 32: 'cap_mac_override', 33: 'cap_mac_admin',
}


def names(mask):
    return [CAP.get(i, str(i)) for i in range(64) if mask >> i & 1]


def decode(value: bytes) -> dict:
    """value = raw xattr record value: 1-byte length prefix, then payload."""
    n = value[0]
    body = value[1:1 + n]
    if len(body) < 12:
        raise ValueError(f'payload too short: {len(body)} bytes (n={n})')
    magic = struct.unpack_from('<I', body, 0)[0]
    w = struct.unpack_from('<IIII', body, 4) if len(body) >= 20 \
        else struct.unpack_from('<II', body, 4) + (0, 0)
    perm = w[0] | (w[2] << 32)
    inh = w[1] | (w[3] << 32)
    return {
        'effective': bool(magic & 1),
        'revision': (magic & 0xFF000000) >> 24,
        'permitted': perm,
        'inheritable': inh,
        'perm_names': names(perm),
        'inh_names': names(inh),
    }


def getcap_text(value: bytes) -> str:
    """Render like getcap: names = union, then '=' + e/i/p flags."""
    d = decode(value)
    union = sorted(set(d['perm_names']) | set(d['inh_names']))
    flags = ('e' if d['effective'] else '') + \
            ('i' if d['inheritable'] else '') + \
            ('p' if d['permitted'] else '')
    return ','.join(union) + '=' + flags


VECTORS = [
    ('dotnet', bytes.fromhex('140100000200000000400020000000000000000000'),
     'cap_setgid,cap_sys_admin=ei'),
    ('dotnet-launcher', bytes.fromhex('1401000002c001ac00c001ac000300000003000000'),
     'cap_mac_admin,cap_mac_override,cap_setgid,cap_setpcap,cap_setuid,'
     'cap_sys_admin,cap_sys_chroot,cap_sys_nice,cap_sys_ptrace=ei'),
    ('sdbd-tarlauncher', bytes.fromhex('1401000002c0000000c0000000000000000000000000000000'),
     'cap_setgid,cap_setuid=eip'),
    ('launchpad-starter', bytes.fromhex('1401000002c901ac00c901ac000300000003000000'),
     'cap_chown,cap_fowner,cap_mac_admin,cap_mac_override,cap_setgid,'
     'cap_setpcap,cap_setuid,cap_sys_admin,cap_sys_chroot,cap_sys_nice,'
     'cap_sys_ptrace=eip'),
]


def selftest():
    ok = 0
    for label, raw, expected in VECTORS:
        got = getcap_text(raw)
        good = got == expected
        ok += good
        print(f'  {label:18} {"PASS" if good else "FAIL"}  {got}')
        if not good:
            print(f'  {"":18}   expected {expected}')
    print(f'  {ok}/{len(VECTORS)} published vectors reproduced')
    return ok == len(VECTORS)


if __name__ == '__main__':
    raise SystemExit(0 if selftest() else 1)
