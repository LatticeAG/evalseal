"""Bounded STORE-only ZIP reader for attestation packs (spec §9.2).

Validation order: declared entry names against the disclosure allowlist
(PACK_PATH_INVALID), then each entry's declared uncompressed size against its
bound and the declared total against the pack bound (PACK_SIZE_LIMIT), then
signature/manifest checks, then extraction. No byte is allocated to
attacker-declared sizes before these checks pass.
"""

from __future__ import annotations

import struct
import zlib

PUBLIC_ENTRIES = (
    "audit.jsonl", "cases.json", "certificate.json", "checkpoint.json",
    "keyring.json", "manifest.json", "release.json", "report.pdf",
    "result.json", "scope.txt", "target.json",
)
PRIVATE_EXTRA = ("evidence.json", "transcript.bin")

MAX_ENTRY_DEFAULT = 32 * 1024 * 1024          # 32 MiB per ordinary entry
MAX_ENTRY_EVIDENCE = 336 * 1024 * 1024        # evidence class bound
MAX_ENTRY_TRANSCRIPT = 448 * 1024 * 1024      # transcript class bound
MAX_PUBLIC_PACK = 32 * 1024 * 1024
MAX_PRIVATE_PACK = 832 * 1024 * 1024
MAX_ENTRIES = 16

EOCD_SIG = 0x06054B50
CDIR_SIG = 0x02014B50
LOCAL_SIG = 0x04034B50


class ZipError(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


def _entry_bound(name: str) -> int:
    if name == "evidence.json":
        return MAX_ENTRY_EVIDENCE
    if name == "transcript.bin":
        return MAX_ENTRY_TRANSCRIPT
    return MAX_ENTRY_DEFAULT


def _valid_name(name: str) -> bool:
    return name in PUBLIC_ENTRIES + PRIVATE_EXTRA


def read_directory(data: bytes) -> list:
    """Parse the central directory; returns declared entries (no extraction)."""
    if len(data) < 22:
        raise ZipError("PACK_ENTRY_INVALID", "too small for ZIP")
    # find EOCD: scan last 64KiB
    tail = data[-min(len(data), 22 + 65536) :]
    idx = tail.rfind(struct.pack("<I", EOCD_SIG))
    if idx < 0:
        raise ZipError("PACK_ENTRY_INVALID", "no end of central directory")
    eocd = tail[idx : idx + 22]
    if len(eocd) < 22:
        raise ZipError("PACK_ENTRY_INVALID", "truncated EOCD")
    (_, disk, cd_disk, n_disk, n_total, cd_size, cd_off, com_len) = struct.unpack("<IHHHHIIH", eocd)
    if com_len != 0 or disk != 0 or cd_disk != 0 or n_disk != n_total:
        raise ZipError("PACK_ENTRY_INVALID", "multi-disk/comment archives unsupported")
    if n_total > MAX_ENTRIES:
        raise ZipError("PACK_SIZE_LIMIT", "entry count exceeds bound")
    if cd_off + cd_size > len(data):
        raise ZipError("PACK_ENTRY_INVALID", "central directory out of range")
    entries = []
    pos = cd_off
    seen = set()
    for _ in range(n_total):
        if pos + 46 > len(data) or struct.unpack("<I", data[pos : pos + 4])[0] != CDIR_SIG:
            raise ZipError("PACK_ENTRY_INVALID", "bad central directory entry")
        (sig, vmade, vneed, flags, method, mtime, mdate, crc, csize, usize,
         nlen, elen, clen, dstart, iattr, eattr, lhoff) = struct.unpack(
            "<IHHHHHHIIIHHHHHII", data[pos : pos + 46])
        name_b = data[pos + 46 : pos + 46 + nlen]
        try:
            name = name_b.decode("ascii")
        except UnicodeDecodeError:
            raise ZipError("PACK_PATH_INVALID", "non-ASCII entry name") from None
        if not _valid_name(name) or name in seen:
            raise ZipError("PACK_PATH_INVALID", "entry outside allowlist")
        seen.add(name)
        if flags != 0 or method != 0 or clen != 0 or elen != 0:
            raise ZipError("PACK_ENTRY_INVALID", "only plain STORE entries are supported")
        if csize != usize:
            raise ZipError("PACK_ENTRY_INVALID", "STORE entry with mismatched sizes")
        if usize > _entry_bound(name):
            raise ZipError("PACK_SIZE_LIMIT", "declared size exceeds entry bound")
        entries.append({"name": name, "size": usize, "crc": crc, "offset": lhoff})
        pos += 46 + nlen + elen + clen
    total = sum(e["size"] for e in entries)
    if total > MAX_PRIVATE_PACK:
        raise ZipError("PACK_SIZE_LIMIT", "declared total exceeds pack bound")
    if not any(e["name"] in PRIVATE_EXTRA for e in entries) and total > MAX_PUBLIC_PACK:
        raise ZipError("PACK_SIZE_LIMIT", "declared total exceeds public pack bound")
    return entries


def extract(data: bytes, entries: list) -> dict:
    """Extract previously validated entries; verifies CRC and local headers."""
    out = {}
    for e in entries:
        off = e["offset"]
        if off + 30 > len(data) or struct.unpack("<I", data[off : off + 4])[0] != LOCAL_SIG:
            raise ZipError("PACK_ENTRY_INVALID", "bad local header")
        (sig, vneed, flags, method, mtime, mdate, crc, csize, usize, nlen, elen) = struct.unpack(
            "<IHHHHHIIIHH", data[off : off + 30])
        name_b = data[off + 30 : off + 30 + nlen]
        if flags != 0 or method != 0:
            raise ZipError("PACK_ENTRY_INVALID", "unsupported local entry")
        try:
            if name_b.decode("ascii") != e["name"]:
                raise ZipError("PACK_PATH_INVALID", "local/central name mismatch")
        except UnicodeDecodeError:
            raise ZipError("PACK_PATH_INVALID", "non-ASCII local name") from None
        if csize != e["size"] or usize != e["size"]:
            raise ZipError("PACK_ENTRY_INVALID", "local size mismatch")
        start = off + 30 + nlen + elen
        end = start + usize
        if end > len(data):
            raise ZipError("PACK_ENTRY_INVALID", "entry data out of range")
        blob = data[start:end]
        if zlib.crc32(blob) & 0xFFFFFFFF != crc:
            raise ZipError("PACK_ENTRY_INVALID", "CRC mismatch")
        out[e["name"]] = blob
    return out


def read_pack(data: bytes) -> dict:
    """Directory validation then extraction; returns {name: bytes}."""
    entries = read_directory(data)
    return extract(data, entries)
