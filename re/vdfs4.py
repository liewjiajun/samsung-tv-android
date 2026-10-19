#!/usr/bin/env python3
"""
vdfs4.py - minimal read-only Samsung VDFS4 (layout 2007) parser.

Purpose: answer, offline, whether specific binaries on the TV's read-only rootfs
carry the file capabilities that the archive-root technique depends on.

The full unpackers (gtors/vdfs-unpack, theubusu/vdfs4_driver, HinTak/vdfs-tools)
are Rust/C needing a toolchain that is not installed here, and upstream notes say
the public vdfs-tools build rejects layout 2007 without a patch. This walks only
the metadata and optionally decompresses individual files.

Reads a local image. Writes nothing anywhere else.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

SECTOR = 512
BNODE_FIRST_OFFSET = 4
META_BTREE_EXTENTS = 96
CAT_TREE_INO = 3
XATTR_TREE_INO = 7

REC_FOLDER = 0x01
REC_FILE = 0x02
REC_HLINK = 0x03
REC_ILINK = 0x05


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


class Superblock:
    def __init__(self, data: bytes):
        off = SECTOR * 2
        sig = data[off:off + 4]
        if sig != b"VDFS":
            raise ValueError(f"bad superblock signature {sig!r}")
        self.layout_version = data[off + 4:off + 8].decode("latin1")
        self.max_blocks = u64(data, off + 8)
        self.volume_uuid = data[off + 28:off + 44]
        self.volume_name = data[off + 44:off + 60].decode("latin1").rstrip("\x00")
        self.mkfs_version = data[off + 60:off + 124].decode("latin1").rstrip("\x00")
        # 40 unused, then the log/flag block
        p = off + 124 + 40
        self.log_block_size = data[p]
        self.log_super_page_size = data[p + 1]
        self.log_erase_block_size = data[p + 2]
        self.case_insensitive = data[p + 3]
        self.read_only = data[p + 4]
        self.image_crc32_present = data[p + 5]

        self.block_size = 1 << self.log_block_size
        self.super_page_size = 1 << self.log_super_page_size
        self.blocks_per_super_page = 1 << (self.log_super_page_size - self.log_block_size)
        self.block_size_shift = self.log_block_size

        # extended superblock at sector 3
        e = SECTOR * 3
        self.files_count = u64(data, e)
        self.folders_count = u64(data, e + 8)
        self.volume_body_begin = u64(data, e + 16)
        self.volume_body_len = u64(data, e + 24)
        # mount/sync/umount/generation = 4 x u32
        base = e + 32 + 16
        self.debug_begin = u64(data, base)
        self.debug_len = u64(data, base + 8)
        self.meta_tbc = u32(data, base + 16)
        self.tables_begin = u64(data, base + 24)
        self.tables_len = u64(data, base + 32)
        meta0 = base + 40
        self.meta = []
        for i in range(META_BTREE_EXTENTS):
            b = u64(data, meta0 + i * 16)
            l = u64(data, meta0 + i * 16 + 8)
            if b or l:
                self.meta.append((b, l))
        ext = meta0 + META_BTREE_EXTENTS * 16
        self.extension_begin = u64(data, ext)
        self.extension_len = u64(data, ext + 8)
        self.volume_blocks_count = u64(data, ext + 16)


class Vdfs4:
    def __init__(self, path: Path):
        self.path = path
        self.fh = open(path, "rb")
        head = self.fh.read(1 << 20)
        self.sb = Superblock(head)
        self._tables = self._load_tables()

    def close(self):
        self.fh.close()

    def read_at(self, off: int, n: int) -> bytes:
        self.fh.seek(off)
        return self.fh.read(n)

    def _load_tables(self):
        sb = self.sb
        tables_off = sb.tables_begin * sb.block_size
        self.fh.seek(tables_off)
        # Vdfs4BaseTable = SnapshotDescriptor(4+4+8+8 = 24)
        #                  + last_page_index[5] (40)
        #                  + translation_table_offsets[5] (40)  => 104 bytes total.
        # Reading 84 truncated the second array; read the whole struct.
        hdr = self.fh.read(104)
        if len(hdr) < 104:
            raise ValueError(f"short base table at {tables_off}: got {len(hdr)} bytes")
        sig = hdr[0:4]
        if sig != b"snap":
            # descriptor signature may differ; do not hard-fail, just report
            pass
        last_idx = [u64(hdr, 24 + i * 8) for i in range(5)]
        trans = [u64(hdr, 24 + 40 + i * 8) for i in range(5)]
        tables = []
        for sf in range(5):
            recs = []
            if last_idx[sf] > 0:
                base = tables_off + trans[sf]
                for i in range(last_idx[sf] + 1):
                    raw = self.read_at(base + i * 16, 16)
                    if len(raw) < 16:
                        break
                    recs.append((u64(raw, 0), u32(raw, 8), u32(raw, 12)))
            tables.append(recs)
        return tables

    def meta_iblock_to_block(self, meta_iblock: int) -> int:
        cum = 0
        for begin, length in self.sb.meta:
            if meta_iblock < cum + length:
                return begin + (meta_iblock - cum)
            cum += length
        raise ValueError(f"meta_iblock {meta_iblock} outside meta extents")

    def read_meta_page(self, ino: int, page_index: int) -> bytes:
        sf = ino - CAT_TREE_INO
        if sf < 0 or sf >= 5:
            raise ValueError(f"bad special-file ino {ino}")
        is_tree = CAT_TREE_INO <= ino <= 7
        if is_tree:
            shift = (self.sb.log_super_page_size - self.sb.log_block_size) \
                    + self.sb.block_size_shift - 12
            table_page = page_index >> shift
        else:
            table_page = page_index
        recs = self._tables[sf]
        if table_page >= len(recs):
            raise ValueError(f"page {table_page} out of range for ino {ino} ({len(recs)} recs)")
        blk = self.meta_iblock_to_block(recs[table_page][0])
        off = blk * self.sb.block_size
        return self.read_at(off, self.sb.super_page_size)

    def btree_head(self, ino: int):
        page = self.read_meta_page(ino, 0)
        magic = page[0:4]
        if magic != b"eHND":
            raise ValueError(f"bad btree head magic {magic!r} for ino {ino}")
        root = u32(page, 12)
        height = u16(page, 16)
        return root, height

    def read_bnode(self, ino: int, node_id: int):
        if node_id == 0:
            raw = self.read_meta_page(ino, 0)
        else:
            blocks_per_node = self.sb.blocks_per_super_page
            pages_per_node = blocks_per_node * self.sb.block_size // 4096
            raw = self.read_meta_page(ino, node_id * pages_per_node)
        recs_count = u16(raw, 14)
        node_type = u32(raw, 28)
        offsets = []
        ns = self.sb.super_page_size
        for i in range(recs_count + 1):
            addr = ns - BNODE_FIRST_OFFSET - 4 * (i + 1)
            if addr < 0 or addr + 4 > len(raw):
                break
            offsets.append(u32(raw, addr))
        return {"raw": raw, "node_type": node_type, "recs_count": recs_count,
                "offsets": offsets}

    def iter_leaf_records(self, ino: int):
        """Walk the btree and yield every record in leaf nodes."""
        root, height = self.btree_head(ino)
        if height <= 1:
            # single-node tree
            node = self.read_bnode(ino, 0)
            yield from self._node_records(node)
            return
        stack = [root]
        seen = set()
        while stack:
            nid = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            node = self.read_bnode(ino, nid)
            if node["node_type"] == 2:  # leaf
                yield from self._node_records(node)
            else:
                for i in range(node["recs_count"]):
                    key_len = self._key_len(node, i)
                    off = node["offsets"][i]
                    if off + key_len + 4 <= len(node["raw"]):
                        stack.append(u32(node["raw"], off + key_len))

    def _key_len(self, node, i):
        off = node["offsets"][i]
        if off + 8 > len(node["raw"]):
            return 0
        return u16(node["raw"], off + 4)

    def _rec_len(self, node, i):
        off = node["offsets"][i]
        if off + 8 > len(node["raw"]):
            return len(node["raw"]) - off
        return u16(node["raw"], off + 6)

    def _node_records(self, node):
        for i in range(node["recs_count"]):
            off = node["offsets"][i]
            rl = self._rec_len(node, i)
            if off + rl > len(node["raw"]) or rl <= 0:
                continue
            yield node["raw"][off:off + rl]


def parse_cat_key(rec: bytes):
    """Cattree key, layout from the published driver."""
    if len(rec) < 26:
        return None
    return {
        "magic": rec[0:4],
        "key_len": u16(rec, 4),
        "rec_len": u16(rec, 6),
        "parent_id": u64(rec, 8),
        "object_id": u64(rec, 16),
        "record_type": rec[24],
        "name_len": rec[25],
        "name": rec[26:26 + rec[25]].decode("utf-8", "replace"),
    }


def main():
    if len(sys.argv) < 2:
        print("usage: vdfs4.py <platform.img> [--find NAME] [--caps] [--dump PATH]")
        return 2

    img = Vdfs4(Path(sys.argv[1]))
    sb = img.sb
    print("=== VDFS4 superblock ===")
    print(f"  layout          : {sb.layout_version}")
    print(f"  volume name     : {sb.volume_name!r}")
    print(f"  mkfs version    : {sb.mkfs_version!r}")
    print(f"  block size      : {sb.block_size}")
    print(f"  super page      : {sb.super_page_size}")
    print(f"  read_only       : {bool(sb.read_only)}")
    print(f"  crc32 present   : {bool(sb.image_crc32_present)}")
    print(f"  files / folders : {sb.files_count:,} / {sb.folders_count:,}")
    print(f"  volume blocks   : {sb.volume_blocks_count:,}")
    print(f"  meta extents    : {len(sb.meta)}")

    find = None
    if "--find" in sys.argv:
        find = sys.argv[sys.argv.index("--find") + 1]

    root, height = img.btree_head(CAT_TREE_INO)
    print(f"\n  cattree root={root} height={height}")

    # Build object_id -> (name, type) and parent map by walking the whole cattree.
    print("\n=== walking catalog tree ===")
    entries = {}
    n = 0
    for rec in img.iter_leaf_records(CAT_TREE_INO):
        k = parse_cat_key(rec)
        # Do NOT filter on the generic-key magic: on this volume it is zeros,
        # not "eHdr". Filtering on it silently rejected every record.
        if not k or k["key_len"] == 0 or k["rec_len"] == 0:
            continue
        if k["name_len"] == 0 or k["name_len"] > 255:
            continue
        n += 1
        entries[(k["parent_id"], k["object_id"])] = k

    print(f"  records: {n}")
    names = {oid: k for (pid, oid), k in entries.items() if k["name"]}

    if find:
        print(f"\n=== matches for {find!r} ===")
        hits = [k for k in names.values() if k["name"] == find]
        if not hits:
            hits = [k for k in names.values() if find in k["name"]]
        for k in hits[:20]:
            print(f"  obj={k['object_id']:>10} parent={k['parent_id']:>10} "
                  f"type=0x{k['record_type']:02x} {k['name']}")
        if not hits:
            print("  none")

    img.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())


# ---------------------------------------------------------------------------
# File content reading
#
# A catalog FILE record is: generic key || vdfs4_catalog_folder_record (80B)
#                        || vdfs4_fork(size 8, blocks 8, data[216]).
# So the fork starts at 80 and its extent table at 96.
#
# Inline files keep their payload in fork.data. Everything else (configs,
# binaries, the whole real rootfs) lives in extents addressed in blocks.
# ---------------------------------------------------------------------------
FLAG_INLINE = 1 << 19
FLAG_COMPRESSED = 1 << 13
COMMON_SIZE = 80
FORK_OFF = COMMON_SIZE
EXT_IN_FORK = 9
IEXTENT_SIZE = 24


class FileFork:
    __slots__ = ('flags', 'size', 'blocks', 'data', 'inline', 'compressed')

    def __init__(self, val: bytes):
        self.flags = u32(val, 0)
        self.size = u64(val, FORK_OFF)
        self.blocks = u64(val, FORK_OFF + 8)
        self.data = val[FORK_OFF + 16:FORK_OFF + 16 + 216]
        self.inline = bool(self.flags & FLAG_INLINE)
        self.compressed = bool(self.flags & FLAG_COMPRESSED)

    def extents(self):
        out = []
        for i in range(EXT_IN_FORK):
            o = i * IEXTENT_SIZE
            if o + IEXTENT_SIZE > len(self.data):
                break
            begin = u64(self.data, o)
            length = u64(self.data, o + 8)
            if begin == 0 and length == 0:
                continue
            out.append((begin, length))
        return out


def fork_of(rec: bytes, k: dict) -> FileFork:
    return FileFork(rec[k['key_len']:k['rec_len']])


def read_file(img, rec: bytes, k: dict) -> bytes:
    """Return a file's bytes. Raises on compressed files (not yet handled)."""
    f = fork_of(rec, k)
    if f.inline:
        return f.data[:min(f.size, len(f.data))]
    if f.compressed:
        raise NotImplementedError('compressed file (vdfs4_comp_file_descr)')
    out = bytearray()
    for begin, length in f.extents():
        out += img.read_at(begin * img.sb.block_size,
                           length * img.sb.block_size)
    return bytes(out[:f.size])
