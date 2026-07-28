"""Recycle bin record parsers.

Two on-disk formats, both of which record what a file *was* before deletion —
its original path, its size, and when it was deleted. Without parsing them the
carver can only report that a recycle-bin entry exists, which tells an examiner
nothing about what was thrown away.

  INFO2   Windows 95 - XP. One index file per user SID holding fixed-size
          records, under RECYCLER/<SID>/INFO2.
  $I      Vista and later. One small file per deleted item, paired with the
          $R file holding the content, under $Recycle.Bin/<SID>/.
"""

import struct
from datetime import datetime, timedelta, timezone

# FILETIME epoch: 100-nanosecond intervals since 1601-01-01 UTC.
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

DRIVE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def filetime_to_datetime(value):
    """Convert a Windows FILETIME to an aware datetime, or None if implausible."""
    if not value:
        return None
    try:
        stamp = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, OSError, ValueError):
        return None
    # Anything outside this range is a misparse, not a real deletion time.
    if not (1980 <= stamp.year <= 2100):
        return None
    return stamp


def _clean_utf16(raw):
    text = raw.decode("utf-16-le", errors="ignore")
    return text.split("\x00", 1)[0].strip()


def _clean_ansi(raw):
    text = raw.decode("latin-1", errors="ignore")
    return text.split("\x00", 1)[0].strip()


def parse_info2(data):
    """Parse a Windows XP INFO2 index file.

    Header is 20 bytes; the record size lives at offset 0x0C because it differs
    between the ANSI-only and Unicode layouts. Each record:

        0x000  original path, ANSI, 260 bytes
        0x104  record index (uint32)
        0x108  drive number (uint32, 0 = A:)
        0x10C  deletion time (FILETIME)
        0x114  original size (uint32)
        0x118  original path, UTF-16LE, 520 bytes   (Unicode layout only)
    """
    records = []
    if not data or len(data) < 20:
        return records

    try:
        record_size = struct.unpack_from("<I", data, 0x0C)[0]
    except struct.error:
        return records
    if record_size not in (280, 800):          # ANSI-only vs Unicode layouts
        record_size = 800

    offset = 20
    while offset + record_size <= len(data):
        chunk = data[offset:offset + record_size]
        offset += record_size
        try:
            ansi_path = _clean_ansi(chunk[0x00:0x104])
            drive = struct.unpack_from("<I", chunk, 0x108)[0]
            deleted_raw = struct.unpack_from("<Q", chunk, 0x10C)[0]
            size = struct.unpack_from("<I", chunk, 0x114)[0]

            path = ""
            if record_size >= 800:
                path = _clean_utf16(chunk[0x118:0x320])
            if not path:
                path = ansi_path
            if not path:
                continue

            # A cleared entry keeps the record but zeroes the leading byte.
            if path.startswith("\x00"):
                continue

            records.append({
                "original_path": path,
                "drive": (DRIVE_LETTERS[drive] + ":") if drive < 26 else "?",
                "deleted_time": filetime_to_datetime(deleted_raw),
                "size": size,
            })
        except (struct.error, IndexError):
            continue

    return records


def parse_i_file(data):
    """Parse a Vista+ '$I' recycle-bin metadata file.

        0x00  format version (uint64): 1 = Vista-8.1, 2 = Windows 10+
        0x08  original size (uint64)
        0x10  deletion time (FILETIME)
        0x18  version 1: 520-byte UTF-16LE path
              version 2: uint32 character count, then the UTF-16LE path
    """
    if not data or len(data) < 0x18:
        return None

    try:
        version, size, deleted_raw = struct.unpack_from("<QQQ", data, 0)
    except struct.error:
        return None

    try:
        if version == 2:
            (char_count,) = struct.unpack_from("<I", data, 0x18)
            # Guard against a corrupt length driving a huge slice.
            char_count = max(0, min(char_count, 32768))
            raw = data[0x1C:0x1C + char_count * 2]
        else:
            raw = data[0x18:0x18 + 520]
    except struct.error:
        return None

    path = _clean_utf16(raw)
    if not path:
        return None

    return {
        "original_path": path,
        "deleted_time": filetime_to_datetime(deleted_raw),
        "size": size,
    }


def describe(record, source_path):
    """One-line summary for the artifact table."""
    size = record.get("size") or 0
    if size >= 1 << 20:
        size_str = f"{size / (1 << 20):.1f} MB"
    elif size >= 1024:
        size_str = f"{size / 1024:.1f} KB"
    else:
        size_str = f"{size} bytes"

    deleted = record.get("deleted_time")
    when = deleted.strftime("%Y-%m-%d %H:%M:%S UTC") if deleted else "unknown time"
    return (f"Recycle Bin: {record['original_path']} "
            f"({size_str}, deleted {when}) [record: {source_path}]")
