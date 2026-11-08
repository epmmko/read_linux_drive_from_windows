#!/usr/bin/env python3
"""
extfs_backend.py - read-only ext2/ext3/ext4 reader for raw Windows disks.

Pure Python, standard library only (no pip installs). It never writes to the
source disk: the device is opened read-only and every read is sector-aligned.

Windows: run from an *Administrator* terminal (raw disk access needs it).
It also works on disk image files, which is how it was tested.

---- Python API --------------------------------------------------------------
    from extfs_backend import list_disks, scan_partitions, open_ext4, extract

    list_disks()                      # [DiskInfo(number=2, name='PNY ...', ...)]
    scan_partitions(2)                # partitions of \\\\.\\PHYSICALDRIVE2 + detected fs
    fs = open_ext4(disk=2, part=4)    # or open_ext4(image="disk.img", part=3)

    for e in fs.listdir("/home"):     # Entry(name, path, kind, size, mtime, ...)
        print(e.kind, e.size, e.name)
    data = fs.open("/home/me/notes.txt").read()
    fs.readlink("/etc/localtime")

    for dirpath, dirs, files in fs.walk("/home/me"): ...

    res = extract(fs, ["/home/me/Pictures", "/home/me/doc.pdf"], r"D:\\rescue",
                  include_ext={"jpg", "png", "pdf"})      # include_ext is optional
    print(res.copied, res.failed)

---- Command line ------------------------------------------------------------
    python extfs_backend.py disks
    python extfs_backend.py parts --disk 2
    python extfs_backend.py info  --disk 2 --part 4
    python extfs_backend.py ls    --disk 2 --part 4 /home
    python extfs_backend.py cp    --disk 2 --part 4 --dest D:\\rescue /home/me/Pictures
    (use --image file.img instead of --disk N for an image file)

Limitations: no decryption (LUKS, fscrypt, eCryptfs), no LVM/btrfs, no journal
replay (a Linux that was not shut down cleanly may show slightly stale data),
no meta_bg or inline_data >60 bytes.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import datetime
import dataclasses
import fnmatch
import io
import json
import os
import posixpath
import shutil
import struct
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field

__all__ = [
    "Ext4", "Ext4File", "Entry", "RawPartition", "PartInfo", "DiskInfo",
    "Progress", "ExtractResult", "list_disks", "scan_partitions", "open_ext4",
    "extract", "estimate", "human_size", "win_safe_name", "is_admin",
    "Ext4Error", "NotExt4", "EncryptedError", "UnsupportedFeature", "Cancelled",
]

# --------------------------------------------------------------------------- errors


class Ext4Error(Exception):
    pass


class NotExt4(Ext4Error):
    pass


class EncryptedError(Ext4Error):
    pass


class UnsupportedFeature(Ext4Error):
    pass


class Cancelled(Exception):
    pass


# --------------------------------------------------------------------------- raw access

ALIGN = 4096            # raw-disk reads must be sector aligned; 4096 covers 512 and 4Kn drives
MAX_RAW_READ = 1 << 20  # some USB drivers reject very large single reads


def disk_path(disk):
    """int -> \\\\.\\PHYSICALDRIVEn, str -> used as given (image file / device path)."""
    if isinstance(disk, int):
        return r"\\.\PHYSICALDRIVE%d" % disk
    return str(disk)


class RawPartition:
    """Read-only window [offset, offset+size) onto a disk or image file."""

    def __init__(self, disk, offset=0, size=None):
        self.path = disk_path(disk)
        self._f = open(self.path, "rb", buffering=0)
        self.offset = int(offset)
        if size is None:
            try:
                self._f.seek(0, 2)
                total = self._f.tell()
            except OSError:
                total = 0
            size = total - self.offset if total > self.offset else (1 << 62)
        self.size = int(size)
        self._lock = threading.RLock()

    def pread(self, pos, n):
        """Read up to n bytes at partition-relative position pos. Thread-safe."""
        if pos < 0 or n < 0:
            raise ValueError("negative position/length")
        n = max(0, min(n, self.size - pos))
        if n == 0:
            return b""
        start = self.offset + pos
        end = start + n
        a_start = start - start % ALIGN
        a_end = end + (-end) % ALIGN
        buf = bytearray()
        with self._lock:
            p = a_start
            while p < a_end:
                self._f.seek(p)
                chunk = self._f.read(min(MAX_RAW_READ, a_end - p))
                if not chunk:
                    break
                buf += chunk
                p += len(chunk)
        lo = start - a_start
        return bytes(buf[lo:lo + n])

    def close(self):
        self._f.close()


class _FileAdapter:
    """Gives any seekable file object (BytesIO, open file) a pread()."""

    def __init__(self, f):
        self._f = f
        self._lock = threading.RLock()

    def pread(self, pos, n):
        with self._lock:
            self._f.seek(pos)
            return self._f.read(n)

    def close(self):
        pass


# --------------------------------------------------------------------------- ext4 core

EXTENTS_FL = 0x80000
ENCRYPT_FL = 0x800
INLINE_DATA_FL = 0x10000000

INCOMPAT_NAMES = {0x1: "compression", 0x2: "filetype", 0x4: "needs_recovery", 0x8: "journal_dev",
                  0x10: "meta_bg", 0x40: "extents", 0x80: "64bit", 0x100: "mmp", 0x200: "flex_bg",
                  0x400: "ea_inode", 0x1000: "dirdata", 0x2000: "csum_seed", 0x4000: "largedir",
                  0x8000: "inline_data", 0x10000: "encrypt", 0x20000: "casefold"}
COMPAT_NAMES = {0x1: "dir_prealloc", 0x2: "imagic_inodes", 0x4: "has_journal", 0x8: "ext_attr",
                0x10: "resize_inode", 0x20: "dir_index", 0x200: "sparse_super2"}
RO_NAMES = {0x1: "sparse_super", 0x2: "large_file", 0x4: "btree_dir", 0x8: "huge_file",
            0x10: "gdt_csum", 0x20: "dir_nlink", 0x40: "extra_isize", 0x100: "quota",
            0x200: "bigalloc", 0x400: "metadata_csum"}


def _kind(mode):
    return {0o040000: "dir", 0o100000: "file", 0o120000: "symlink"}.get(mode & 0o170000, "other")


@dataclass
class Entry:
    name: str
    path: str
    ino: int
    kind: str          # "dir" | "file" | "symlink" | "other"
    size: int
    mtime: float
    mode: int
    encrypted: bool = False

    @property
    def is_dir(self):
        return self.kind == "dir"

    @property
    def display(self):
        """Name safe to show in a GUI (invalid UTF-8 bytes replaced)."""
        return self.name.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


class _Inode:
    __slots__ = ("ino", "mode", "size", "flags", "atime", "ctime", "mtime", "block")


class Ext4:
    """Read-only ext2/3/4 filesystem. `source` is a RawPartition or any seekable file object."""

    def __init__(self, source, cache_blocks=4096):
        self._src = source if hasattr(source, "pread") else _FileAdapter(source)
        self._lock = threading.RLock()
        self._bcache = collections.OrderedDict()
        self._dcache = collections.OrderedDict()
        self._cache_blocks = cache_blocks

        sb = self._src.pread(1024, 1024)
        if len(sb) < 1024 or struct.unpack_from("<H", sb, 56)[0] != 0xEF53:
            raise NotExt4("not an ext2/3/4 filesystem (superblock magic not found)")

        def g32(o):
            return struct.unpack_from("<I", sb, o)[0]

        def g16(o):
            return struct.unpack_from("<H", sb, o)[0]

        self.inodes_count = g32(0)
        blocks_lo = g32(4)
        self.first_data_block = g32(20)
        self.block_size = 1024 << g32(24)
        self.blocks_per_group = g32(32)
        self.inodes_per_group = g32(40)
        self.last_mount = g32(44)
        self.state = g16(58)
        self.rev = g32(76)
        if self.rev >= 1:
            self.inode_size = g16(88)
            self.compat, self.incompat, self.ro_compat = g32(92), g32(96), g32(100)
        else:
            self.inode_size = 128
            self.compat = self.incompat = self.ro_compat = 0
        self.is64 = bool(self.incompat & 0x80)
        self.desc_size = g16(254) if self.is64 else 32
        if self.is64 and self.desc_size < 64:
            self.desc_size = 64
        self.blocks_count = blocks_lo | ((g32(336) << 32) if self.is64 else 0)
        self.label = sb[120:136].split(b"\0")[0].decode("utf-8", "replace")
        self.uuid = str(uuid.UUID(bytes=bytes(sb[104:120])))
        first_meta_bg = g32(260)

        if not (1024 <= self.block_size <= 65536 and self.blocks_per_group and self.inodes_per_group
                and 128 <= self.inode_size <= self.block_size
                and self.inode_size & (self.inode_size - 1) == 0):
            raise NotExt4("ext superblock found but its geometry looks corrupt")
        self.groups = -(-(self.blocks_count - self.first_data_block) // self.blocks_per_group)
        if self.incompat & 0x1:
            raise UnsupportedFeature("filesystem uses the obsolete 'compression' feature")
        if self.incompat & 0x10 and first_meta_bg < self.groups:
            raise UnsupportedFeature("filesystem uses the 'meta_bg' layout (not supported)")
        self.has_filetype = bool(self.incompat & 0x2)
        self.needs_recovery = bool(self.incompat & 0x4)
        self.clean = bool(self.state & 1) and not self.needs_recovery

    # ---- low level -----------------------------------------------------------------
    def _pread(self, pos, n):
        return self._src.pread(pos, n)

    def _block(self, n):
        with self._lock:
            b = self._bcache.get(n)
            if b is not None:
                self._bcache.move_to_end(n)
                return b
        data = self._src.pread(n * self.block_size, self.block_size)
        if len(data) != self.block_size:
            raise Ext4Error("short read at block %d (damaged or truncated filesystem)" % n)
        with self._lock:
            self._bcache[n] = data
            if len(self._bcache) > self._cache_blocks:
                self._bcache.popitem(last=False)
        return data

    def _group_inode_table(self, g):
        if g >= self.groups:
            raise Ext4Error("block group %d out of range" % g)
        per = self.block_size // self.desc_size
        blk = self._block(self.first_data_block + 1 + g // per)
        off = (g % per) * self.desc_size
        lo = struct.unpack_from("<I", blk, off + 8)[0]
        hi = struct.unpack_from("<I", blk, off + 0x28)[0] if self.desc_size >= 64 else 0
        return lo | (hi << 32)

    def _inode(self, ino):
        if not 1 <= ino <= self.inodes_count:
            raise Ext4Error("bad inode number %d" % ino)
        g, idx = divmod(ino - 1, self.inodes_per_group)
        off = self._group_inode_table(g) * self.block_size + idx * self.inode_size
        blk = self._block(off // self.block_size)
        o = off % self.block_size
        raw = blk[o:o + 128]
        i = _Inode()
        i.ino = ino
        i.mode = struct.unpack_from("<H", raw, 0)[0]
        size_lo, i.atime, i.ctime, i.mtime = struct.unpack_from("<IIII", raw, 4)
        i.flags = struct.unpack_from("<I", raw, 32)[0]
        i.block = bytes(raw[40:100])
        size_hi = struct.unpack_from("<I", raw, 108)[0]
        i.size = size_lo | (size_hi << 32) if (i.mode & 0o170000) == 0o100000 and self.rev >= 1 else size_lo
        return i

    # ---- block mapping -------------------------------------------------------------
    def _extents(self, inode):
        """Sorted list of (logical_block, length, physical_block or None for zeros)."""
        out = []
        if inode.flags & EXTENTS_FL:
            self._parse_extent_node(inode.block, out, 0)
            out.sort(key=lambda e: e[0])
            return out
        bs = self.block_size
        ppb = bs // 4
        nblocks = -(-inode.size // bs)
        ptrs = struct.unpack("<15I", inode.block)

        def add(l, p):
            if out and out[-1][0] + out[-1][1] == l and out[-1][2] + out[-1][1] == p:
                out[-1] = (out[-1][0], out[-1][1] + 1, out[-1][2])
            else:
                out.append((l, 1, p))

        for i in range(12):
            if ptrs[i] and i < nblocks:
                add(i, ptrs[i])

        def walk(blkno, level, lbase):
            if not blkno or lbase >= nblocks:
                return
            entries = struct.unpack("<%dI" % ppb, self._block(blkno))
            span = ppb ** (level - 1)
            for i, p in enumerate(entries):
                if not p:
                    continue
                if lbase + i * span >= nblocks:
                    break
                if level == 1:
                    add(lbase + i, p)
                else:
                    walk(p, level - 1, lbase + i * span)

        base = 12
        walk(ptrs[12], 1, base)
        base += ppb
        walk(ptrs[13], 2, base)
        base += ppb ** 2
        walk(ptrs[14], 3, base)
        return out

    def _parse_extent_node(self, data, out, level):
        magic, entries, _max, depth = struct.unpack_from("<HHHH", data, 0)
        if magic != 0xF30A or level > 6:
            raise Ext4Error("corrupt extent tree")
        for i in range(entries):
            o = 12 + 12 * i
            if depth == 0:
                lblk, ln, hi, lo = struct.unpack_from("<IHHI", data, o)
                if ln > 32768:               # uninitialised (preallocated) extent reads as zeros
                    out.append((lblk, ln - 32768, None))
                else:
                    out.append((lblk, ln, lo | (hi << 32)))
            else:
                _lblk, lo, hi, _u = struct.unpack_from("<IIHH", data, o)
                self._parse_extent_node(self._block(lo | (hi << 32)), out, level + 1)

    # ---- files / directories ---------------------------------------------------------
    def _read_all(self, inode):
        if inode.flags & INLINE_DATA_FL:
            raise UnsupportedFeature("inline_data directory/file is not supported")
        return Ext4File(self, inode).read()

    def _dirmap(self, ino):
        with self._lock:
            d = self._dcache.get(ino)
            if d is not None:
                self._dcache.move_to_end(ino)
                return d
        inode = self._inode(ino)
        if _kind(inode.mode) != "dir":
            raise NotADirectoryError("inode %d is not a directory" % ino)
        data = self._read_all(inode)
        bs = self.block_size
        d = {}
        for b in range(0, len(data), bs):
            p, end = b, min(b + bs, len(data))
            while p + 8 <= end:
                cino, rec_len = struct.unpack_from("<IH", data, p)
                name_len = data[p + 6]
                ftype = 0
                if self.has_filetype:
                    ftype = data[p + 7]
                else:
                    name_len |= data[p + 7] << 8
                if rec_len < 8 or rec_len % 4 or p + rec_len > end:
                    break
                if cino and name_len and 8 + name_len <= rec_len:
                    name = data[p + 8:p + 8 + name_len].decode("utf-8", "surrogateescape")
                    if name not in (".", ".."):
                        d[name] = (cino, ftype)
                p += rec_len
        with self._lock:
            self._dcache[ino] = d
            if len(self._dcache) > 256:
                self._dcache.popitem(last=False)
        return d

    def _entry(self, name, path, ino):
        i = self._inode(ino)
        k = _kind(i.mode)
        return Entry(name=name, path=path, ino=ino, kind=k, size=0 if k == "dir" else i.size,
                     mtime=float(i.mtime), mode=i.mode, encrypted=bool(i.flags & ENCRYPT_FL))

    def _list_ino(self, ino, base):
        base = posixpath.normpath("/" + base.lstrip("/"))
        out = [self._entry(n, posixpath.join(base, n), c) for n, (c, _t) in self._dirmap(ino).items()]
        out.sort(key=lambda e: (e.kind != "dir", e.name.casefold(), e.name))
        return out

    def _readlink_inode(self, inode):
        if _kind(inode.mode) != "symlink":
            raise OSError("not a symbolic link")
        if inode.flags & ENCRYPT_FL:
            raise EncryptedError("encrypted symlink")
        if inode.flags & INLINE_DATA_FL or (inode.size < 60 and not inode.flags & EXTENTS_FL):
            raw = inode.block[:inode.size]
        else:
            raw = Ext4File(self, inode).read()
        return raw.decode("utf-8", "surrogateescape")

    def _resolve(self, path, follow_last=True):
        todo = [p for p in path.split("/") if p][::-1]
        stack = [2]
        hops = 0
        while todo:
            comp = todo.pop()
            if comp == ".":
                continue
            if comp == "..":
                if len(stack) > 1:
                    stack.pop()
                continue
            listing = self._dirmap(stack[-1])
            if comp not in listing:
                raise FileNotFoundError(path)
            child = listing[comp][0]
            ci = self._inode(child)
            if _kind(ci.mode) == "symlink" and (todo or follow_last):
                hops += 1
                if hops > 40:
                    raise Ext4Error("too many levels of symbolic links")
                target = self._readlink_inode(ci)
                if target.startswith("/"):
                    stack = [2]
                todo.extend(reversed([p for p in target.split("/") if p]))
                continue
            stack.append(child)
        return stack[-1]

    # ---- public API ------------------------------------------------------------------
    def stat(self, path, follow=False):
        path = posixpath.normpath("/" + path.lstrip("/"))
        ino = self._resolve(path, follow_last=follow)
        return self._entry(posixpath.basename(path) or "/", path, ino)

    def listdir(self, path="/"):
        ino = self._resolve(path, follow_last=True)
        return self._list_ino(ino, path)

    def open(self, path):
        ino = self._resolve(path, follow_last=True)
        return self._open_entry(self._entry(posixpath.basename(path), path, ino))

    def _open_entry(self, entry):
        inode = self._inode(entry.ino)
        if _kind(inode.mode) != "file":
            raise IsADirectoryError(entry.path)
        if inode.flags & ENCRYPT_FL:
            raise EncryptedError("file is encrypted (fscrypt); it cannot be read from Windows")
        if inode.flags & INLINE_DATA_FL:
            if inode.size <= 60:
                return io.BytesIO(inode.block[:inode.size])
            raise UnsupportedFeature("inline_data file larger than 60 bytes")
        return Ext4File(self, inode)

    def readlink(self, path):
        ino = self._resolve(path, follow_last=False)
        return self._readlink_inode(self._inode(ino))

    def walk(self, path="/"):
        """Like os.walk (top-down): yields (dirpath, [dir Entry], [other Entry]). Symlinks are not followed."""
        stack = [posixpath.normpath("/" + path.lstrip("/"))]
        while stack:
            p = stack.pop()
            try:
                ents = self.listdir(p)
            except (Ext4Error, OSError):
                continue
            dirs = [e for e in ents if e.kind == "dir"]
            yield p, dirs, [e for e in ents if e.kind != "dir"]
            stack.extend(reversed([e.path for e in dirs]))

    def info(self):
        names = []
        for val, table in ((self.compat, COMPAT_NAMES), (self.incompat, INCOMPAT_NAMES),
                           (self.ro_compat, RO_NAMES)):
            names += [n for bit, n in table.items() if val & bit]
        return {"label": self.label, "uuid": self.uuid, "block_size": self.block_size,
                "size_bytes": self.blocks_count * self.block_size,
                "clean": self.clean, "needs_recovery": self.needs_recovery,
                "last_mount": datetime.datetime.fromtimestamp(self.last_mount).isoformat(sep=" ")
                if self.last_mount else "", "features": names}

    def close(self):
        if hasattr(self._src, "close"):
            self._src.close()


class Ext4File:
    """Seekable read-only file object over an inode (extents or classic block map)."""

    def __init__(self, fs, inode):
        self.fs = fs
        self.size = inode.size
        self.pos = 0
        self._ext = fs._extents(inode)
        self._starts = [e[0] for e in self._ext]

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        self.pos = max(0, offset if whence == 0 else self.pos + offset if whence == 1 else self.size + offset)
        return self.pos

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        bs = self.fs.block_size
        out = []
        while n > 0:
            blk = self.pos // bs
            i = bisect.bisect_right(self._starts, blk) - 1
            take = 0
            if i >= 0:
                lblk, ln, pblk = self._ext[i]
                if blk < lblk + ln:
                    take = min(n, (lblk + ln) * bs - self.pos)
                    if pblk is None:
                        data = bytes(take)
                    else:
                        data = self.fs._pread(pblk * bs + (self.pos - lblk * bs), take)
                        if len(data) != take:
                            raise Ext4Error("short read inside file data (damaged filesystem?)")
            if take == 0:                          # hole (sparse region) -> zeros up to next extent
                nxt = self._ext[i + 1][0] * bs if i + 1 < len(self._ext) else self.size
                take = max(1, min(n, nxt - self.pos))
                data = bytes(take)
            out.append(data)
            self.pos += take
            n -= take
        return b"".join(out)


# --------------------------------------------------------------------------- partitions / disks

GUID_NAMES = {
    "C12A7328-F81F-11D2-BA4B-00A0C91E9B4B": "EFI System",
    "0FC63DAF-8483-4772-8E79-3B9D3EBD5B8B": "Linux filesystem",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux /home",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft basic data",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft reserved",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows recovery",
}


@dataclass
class PartInfo:
    index: int
    offset: int
    size: int
    scheme: str
    type_desc: str
    name: str
    fs: str
    readable: bool
    label: str = ""

    def describe(self):
        bits = ["#%d" % self.index, human_size(self.size), self.fs]
        if self.label:
            bits.append("'%s'" % self.label)
        elif self.name:
            bits.append("'%s'" % self.name)
        return "  ".join(bits)


def probe_fs(rp):
    """Identify what is in a partition. Returns (name, readable_by_this_tool, label)."""
    def rd(pos, n):
        try:
            return rp.pread(pos, n)
        except OSError:
            return b""

    head = rd(0, 8192)
    sb = head[1024:2048]
    if len(sb) >= 136 and struct.unpack_from("<H", sb, 56)[0] == 0xEF53:
        compat, incompat, ro = struct.unpack_from("<III", sb, 92)
        label = sb[120:136].split(b"\0")[0].decode("utf-8", "replace")
        if incompat & (0x40 | 0x80 | 0x200) or ro & (0x8 | 0x10 | 0x20 | 0x40 | 0x400):
            return "ext4", True, label
        return ("ext3" if compat & 0x4 else "ext2"), True, label
    if head[:6] == b"LUKS\xba\xbe":
        return "LUKS (encrypted)", False, ""
    if any(head[o:o + 8] == b"LABELONE" for o in (0, 512, 1024, 1536)):
        return "LVM2 volume", False, ""
    if head[3:11] == b"NTFS    ":
        return "NTFS", False, ""
    if head[3:11] == b"EXFAT   ":
        return "exFAT", False, ""
    if head[3:11] == b"-FVE-FS-":
        return "BitLocker", False, ""
    if head[82:90] == b"FAT32   ":
        return "FAT32", False, ""
    if head[0:4] == b"XFSB":
        return "XFS", False, ""
    if head[4086:4096] in (b"SWAPSPACE2", b"SWAP-SPACE"):
        return "swap", False, ""
    if rd(0x10040, 8) == b"_BHRfS_M":
        return "btrfs", False, ""
    return "unknown", False, ""


def _mbr_partitions(rp):
    sec = rp.pread(0, 512)
    if len(sec) < 512 or sec[510:512] != b"\x55\xaa":
        return []
    parts, idx = [], 0
    ext_start = None
    for i in range(4):
        e = sec[446 + 16 * i:462 + 16 * i]
        ptype, lba, nsec = e[4], struct.unpack_from("<I", e, 8)[0], struct.unpack_from("<I", e, 12)[0]
        if ptype == 0 or nsec == 0:
            continue
        if ptype in (0x05, 0x0F, 0x85):
            ext_start = lba
            continue
        idx = i + 1
        parts.append((idx, lba * 512, nsec * 512, "type 0x%02X" % ptype))
    if ext_start is not None:                       # logical partitions (EBR chain)
        nxt, n = ext_start, 5
        for _ in range(64):
            ebr = rp.pread(nxt * 512, 512)
            if len(ebr) < 512 or ebr[510:512] != b"\x55\xaa":
                break
            e1, e2 = ebr[446:462], ebr[462:478]
            ptype, lba, nsec = e1[4], struct.unpack_from("<I", e1, 8)[0], struct.unpack_from("<I", e1, 12)[0]
            if ptype and nsec:
                parts.append((n, (nxt + lba) * 512, nsec * 512, "type 0x%02X" % ptype))
                n += 1
            nl = struct.unpack_from("<I", e2, 8)[0]
            if not nl:
                break
            nxt = ext_start + nl
    return parts


def scan_partitions(disk):
    """Partitions of a disk (int N = \\\\.\\PHYSICALDRIVEN) or image file, with detected filesystems."""
    disk_rp = RawPartition(disk, 0, None)
    try:
        raw = []                                    # (index, offset, size, scheme, type_desc, name)
        head = disk_rp.pread(0, 8192)
        ss = 512 if head[512:520] == b"EFI PART" else 4096 if head[4096:4104] == b"EFI PART" else 0
        if ss:
            hdr = head[ss:ss + 92]
            entry_lba = struct.unpack_from("<Q", hdr, 72)[0]
            num, esz = struct.unpack_from("<II", hdr, 80)
            if 0 < num <= 1024 and 128 <= esz <= 4096:
                table = disk_rp.pread(entry_lba * ss, num * esz)
                for i in range(num):
                    e = table[i * esz:(i + 1) * esz]
                    if len(e) < 128 or e[:16] == bytes(16):
                        continue
                    first, last = struct.unpack_from("<QQ", e, 32)
                    guid = str(uuid.UUID(bytes_le=bytes(e[:16]))).upper()
                    name = e[56:128].decode("utf-16-le", "ignore").split("\0")[0]
                    raw.append((i + 1, first * ss, (last - first + 1) * ss, "GPT",
                                GUID_NAMES.get(guid, guid), name))
        else:
            for idx, off, size, desc in _mbr_partitions(disk_rp):
                raw.append((idx, off, size, "MBR", desc, ""))
        out = []
        for idx, off, size, scheme, desc, name in raw:
            rp = RawPartition(disk, off, size)
            try:
                fs, ok, label = probe_fs(rp)
            finally:
                rp.close()
            out.append(PartInfo(idx, off, size, scheme, desc, name, fs, ok, label))
        if not out:                                 # no partition table: maybe a whole-disk filesystem
            sb = disk_rp.pread(1024, 1024)
            if len(sb) == 1024 and struct.unpack_from("<H", sb, 56)[0] == 0xEF53:
                bs = 1024 << struct.unpack_from("<I", sb, 24)[0]
                size = struct.unpack_from("<I", sb, 4)[0] * bs
                rp = RawPartition(disk, 0, size)
                try:
                    fs, ok, label = probe_fs(rp)
                finally:
                    rp.close()
                out.append(PartInfo(0, 0, size, "none", "whole disk", "", fs, ok, label))
        return out
    finally:
        disk_rp.close()


def open_ext4(disk=None, part=None, *, image=None, offset=None, size=None):
    """Open an ext filesystem. open_ext4(disk=2, part=4) | open_ext4(image='disk.img', part=3)
    | open_ext4(image='fs.img') | open_ext4(disk=2, offset=..., size=...)."""
    target = image if image is not None else disk
    if target is None:
        raise ValueError("give disk=N or image=PATH")
    if offset is not None:
        rp = RawPartition(target, offset, size)
    else:
        parts = scan_partitions(target)
        if part is None:
            if len(parts) == 1 and parts[0].index == 0:
                part = 0
            else:
                raise ValueError("this disk has several partitions - pass part=N (see scan_partitions)")
        match = [p for p in parts if p.index == part]
        if not match:
            raise ValueError("no partition #%s on this disk" % part)
        rp = RawPartition(target, match[0].offset, match[0].size)
    try:
        return Ext4(rp)
    except Exception:
        rp.close()
        raise


@dataclass
class DiskInfo:
    number: int
    name: str
    size: int
    style: str = ""
    is_boot: bool = False
    is_system: bool = False
    offline: bool = False

    def describe(self):
        return "Disk %d - %s - %s" % (self.number, self.name, human_size(self.size))


def is_admin():
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def list_disks():
    """Physical disks (Windows only; elsewhere returns [])."""
    if os.name != "nt":
        return []
    ps = ("Get-Disk | ForEach-Object { [pscustomobject]@{Number=$_.Number;Name=$_.FriendlyName;"
          "Size=$_.Size;Style=$_.PartitionStyle.ToString();IsBoot=$_.IsBoot;IsSystem=$_.IsSystem;"
          "IsOffline=$_.IsOffline} } | ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, text=True, timeout=45, creationflags=0x08000000)
        data = json.loads(r.stdout)
        if isinstance(data, dict):
            data = [data]
        return [DiskInfo(int(d["Number"]), (d.get("Name") or "").strip(), int(d.get("Size") or 0),
                         d.get("Style") or "", bool(d.get("IsBoot")), bool(d.get("IsSystem")),
                         bool(d.get("IsOffline"))) for d in data]
    except Exception:
        found = []                                  # fallback: probe PHYSICALDRIVE0..31
        for n in range(32):
            try:
                open(disk_path(n), "rb", buffering=0).close()
                found.append(DiskInfo(n, "PhysicalDrive%d" % n, 0))
            except OSError:
                pass
        return found


# --------------------------------------------------------------------------- extraction

_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {"COM%d" % i for i in range(1, 10)} | {"LPT%d" % i for i in range(1, 10)}
_BAD = '<>:"/\\|?*'
CHUNK = 4 * 1024 * 1024


def win_safe_name(name):
    """Make a Linux file name legal on Windows (invalid chars -> '_', reserved names, trailing dots)."""
    s = "".join("_" if (ord(c) < 32 or c in _BAD or 0xD800 <= ord(c) <= 0xDFFF) else c for c in name)
    s = s.rstrip(" .") or "_"
    if s.split(".")[0].upper() in _RESERVED:
        s = "_" + s
    return s


def _unique(name, used):
    base, ext = os.path.splitext(name)
    cand, n = name, 1
    while cand.lower() in used:
        n += 1
        cand = "%s (%d)%s" % (base, n, ext)
    used.add(cand.lower())
    return cand


def _wp(path):
    """Windows extended-length path so deep folders (>260 chars) work."""
    if os.name != "nt":
        return path
    p = os.path.abspath(path)
    if p.startswith("\\\\?\\"):
        return p
    return "\\\\?\\UNC\\" + p[2:] if p.startswith("\\\\") else "\\\\?\\" + p


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024


class Progress:
    """Shared state for a running extraction; a GUI can poll it, and set `cancel` to stop."""

    def __init__(self):
        self.phase = "idle"
        self.current = ""
        self.files_total = 0
        self.bytes_total = 0
        self.files_done = 0
        self.bytes_done = 0
        self.errors = 0
        self.cancel = threading.Event()


@dataclass
class ExtractResult:
    copied: int = 0
    skipped: int = 0
    bytes: int = 0
    renamed: int = 0
    cancelled: bool = False
    failed: list = field(default_factory=list)    # [(linux_path, message)]
    special: list = field(default_factory=list)   # symlinks / devices / sockets that were not copied


class _Opts:
    def __init__(self, include_ext, exclude):
        self.include_ext = {e.lower().lstrip(".") for e in include_ext} if include_ext else None
        self.exclude = [p.lower() for p in (exclude or [])]

    def excluded(self, entry):
        n = entry.name.lower()
        return any(fnmatch.fnmatchcase(n, p) for p in self.exclude)

    def wants_file(self, entry):
        if self.include_ext is None:
            return True
        return os.path.splitext(entry.name)[1].lower().lstrip(".") in self.include_ext


def _iter_tree(fs, entry, dest_rel, opts, res, cancel):
    """Depth-first: yields (kind, entry, dest_rel_tuple); directories come before their children."""
    if cancel.is_set():
        return
    if entry.kind == "dir":
        yield "dir", entry, dest_rel
        try:
            kids = fs._list_ino(entry.ino, entry.path)
        except Exception as e:
            res.failed.append((entry.path, "cannot read folder: %s: %s" % (type(e).__name__, e)))
            return
        used = set()
        for k in kids:
            if opts.excluded(k):
                continue
            if k.kind == "file" and not opts.wants_file(k):
                continue
            dn = _unique(win_safe_name(k.name), used)
            if dn != k.name:
                res.renamed += 1
            yield from _iter_tree(fs, k, dest_rel + (dn,), opts, res, cancel)
    else:
        yield entry.kind, entry, dest_rel


def _resolve_source(fs, src):
    ent = fs.stat(src)
    if ent.kind == "symlink":                       # a link the user picked explicitly: copy its target
        tgt = fs.stat(src, follow=True)
        ent = dataclasses.replace(tgt, name=ent.name)
    return ent


def estimate(fs, sources, include_ext=None, exclude=None, progress=None):
    """(file_count, total_bytes) that extract() would copy. Metadata only, fast."""
    prog = progress or Progress()
    opts, res = _Opts(include_ext, exclude), ExtractResult()
    files = total = 0
    for src in sources:
        try:
            ent = _resolve_source(fs, src)
        except Exception:
            continue
        for kind, e, _rel in _iter_tree(fs, ent, (ent.name,), opts, res, prog.cancel):
            if kind == "file":
                files += 1
                total += e.size
    return files, total


def _copy_one(fs, ent, target, prog, res, if_exists):
    prog.current = ent.path
    tp = _wp(target)
    os.makedirs(os.path.dirname(tp), exist_ok=True)
    if if_exists == "skip_same" and os.path.isfile(tp) and os.path.getsize(tp) == ent.size:
        res.skipped += 1
        prog.files_done += 1
        prog.bytes_done += ent.size
        return
    f = fs._open_entry(ent)
    tmp = tp + ".part"
    before = prog.bytes_done
    written = 0
    try:
        with open(tmp, "wb") as out:
            while True:
                if prog.cancel.is_set():
                    raise Cancelled()
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                out.write(chunk)
                written += len(chunk)
                prog.bytes_done += len(chunk)
        if written != ent.size:
            raise Ext4Error("size mismatch: wrote %d of %d bytes" % (written, ent.size))
        os.replace(tmp, tp)
    except BaseException:
        prog.bytes_done = before + ent.size
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    try:
        os.utime(tp, (ent.mtime, ent.mtime))
    except (OSError, ValueError, OverflowError):
        pass
    res.copied += 1
    res.bytes += written
    prog.files_done += 1


def extract(fs, sources, dest, *, include_ext=None, exclude=None, progress=None,
            on_file=None, if_exists="skip_same"):
    """Copy files/folders from the Linux filesystem into the Windows folder `dest`.

    sources     list of Linux paths ("/home/me/Pictures", "/home/me/a.pdf")
    include_ext only copy these extensions, e.g. {"jpg", "png", "pdf"}
    exclude     name patterns to skip, e.g. [".cache", "node_modules", "*.tmp"]
    progress    optional Progress object (poll it from a GUI; set progress.cancel to stop)
    on_file     optional callback(linux_path, status) with status "copied" / "failed"
    if_exists   "skip_same" (default: skip files already there with the same size - makes
                re-runs resumable) or "overwrite"
    Per-file errors never stop the run; they are collected in result.failed.
    """
    prog = progress or Progress()
    prog.phase = "copying"
    res = ExtractResult()
    opts = _Opts(include_ext, exclude)
    dest = os.path.abspath(dest)
    os.makedirs(_wp(dest), exist_ok=True)
    used_top = set()
    for src in sources:
        if prog.cancel.is_set():
            break
        try:
            ent = _resolve_source(fs, src)
        except Exception as e:
            res.failed.append((src, "%s: %s" % (type(e).__name__, e)))
            prog.errors += 1
            continue
        top = _unique(win_safe_name(ent.name if ent.name != "/" else (fs.label or "root")), used_top)
        for kind, e, rel in _iter_tree(fs, ent, (top,), opts, res, prog.cancel):
            target = os.path.join(dest, *rel)
            try:
                if kind == "dir":
                    if opts.include_ext is None:
                        os.makedirs(_wp(target), exist_ok=True)
                elif kind == "file":
                    _copy_one(fs, e, target, prog, res, if_exists)
                    if on_file:
                        on_file(e.path, "copied")
                else:
                    res.special.append(e.path)
            except Cancelled:
                break
            except Exception as ex:
                res.failed.append((e.path, "%s: %s" % (type(ex).__name__, ex)))
                prog.errors += 1
                if on_file:
                    on_file(e.path, "failed")
    res.cancelled = prog.cancel.is_set()
    prog.phase = "done"
    return res


# --------------------------------------------------------------------------- command line


def _open_from_args(a):
    if a.image:
        return open_ext4(image=a.image, part=a.part)
    if a.disk is None:
        sys.exit("give --disk N or --image FILE")
    return open_ext4(disk=a.disk, part=a.part)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only ext2/3/4 explorer for Windows raw disks")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def target(p):
        p.add_argument("--disk", type=int, help="physical disk number (Get-Disk)")
        p.add_argument("--image", help="disk image file instead of --disk")
        p.add_argument("--part", type=int, help="partition number")

    sub.add_parser("disks", help="list physical disks")
    p = sub.add_parser("parts", help="list partitions and detected filesystems")
    target(p)
    p = sub.add_parser("info", help="filesystem details")
    target(p)
    p = sub.add_parser("ls", help="list a folder")
    target(p)
    p.add_argument("path", nargs="?", default="/")
    p = sub.add_parser("cp", help="copy files/folders to a Windows folder")
    target(p)
    p.add_argument("--dest", required=True)
    p.add_argument("--ext", help="only these extensions, e.g. jpg,png,pdf")
    p.add_argument("--exclude", help="comma-separated name patterns to skip, e.g. .cache,*.tmp")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("sources", nargs="+")
    a = ap.parse_args(argv)

    if a.cmd == "disks":
        if not list_disks():
            print("(no disks listed - this command is for Windows)")
        for d in list_disks():
            print(d.describe(), d.style, "BOOT" if d.is_boot else "", "SYSTEM" if d.is_system else "")
        return 0
    if a.cmd == "parts":
        if a.image is None and a.disk is None:
            sys.exit("give --disk N or --image FILE")
        for p in scan_partitions(a.image or a.disk):
            print("%-3d %-9s %-12s %-22s offset=%-14d size=%-14d %s" % (
                p.index, p.scheme, p.fs, p.type_desc, p.offset, p.size, p.label or p.name))
        return 0
    fs = _open_from_args(a)
    if a.cmd == "info":
        for k, v in fs.info().items():
            print("%-15s %s" % (k, v))
    elif a.cmd == "ls":
        for e in fs.listdir(a.path):
            print("%-7s %12s  %s  %s" % (e.kind, e.size if e.kind == "file" else "",
                                         time.strftime("%Y-%m-%d %H:%M", time.localtime(e.mtime)), e.display))
    elif a.cmd == "cp":
        prog = Progress()
        n_files, n_bytes = estimate(fs, a.sources, a.ext.split(",") if a.ext else None,
                                    a.exclude.split(",") if a.exclude else None)
        print("%d files, %s to copy" % (n_files, human_size(n_bytes)))
        free = shutil.disk_usage(os.path.abspath(a.dest) if os.path.isdir(a.dest) else os.path.dirname(os.path.abspath(a.dest)) or ".").free
        if n_bytes > free:
            sys.exit("not enough free space on the destination (%s needed, %s free)" % (human_size(n_bytes), human_size(free)))
        res = extract(fs, a.sources, a.dest, include_ext=a.ext.split(",") if a.ext else None,
                      exclude=a.exclude.split(",") if a.exclude else None, progress=prog,
                      on_file=lambda p, s: print(s, p),
                      if_exists="overwrite" if a.overwrite else "skip_same")
        print("\ncopied %d, skipped %d, failed %d, not copied (links/special) %d" % (
            res.copied, res.skipped, len(res.failed), len(res.special)))
        for path, msg in res.failed:
            print("FAILED", path, "-", msg)
        return 1 if res.failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
