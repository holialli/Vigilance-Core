"""AppCompatCache (ShimCache) parsing.

ShimCache records executables the OS evaluated for compatibility shims, which is
strong evidence of program *presence* (and often execution) even after the binary
is deleted. Windows 7 and Windows 8/10 use different on-disk layouts.
"""

import struct
from datetime import datetime, timedelta, timezone

WIN7_MAGIC = 0xBADC0FEE
WIN8_MAGIC = 0xBADC0FE
WIN10_MAGIC = 0x30
WIN10_CREATORS_MAGIC = 0x34


def _filetime(value):
    """Windows FILETIME (100ns since 1601) -> ISO string."""
    if not value or value == 0x7FFFFFFFFFFFFFFF:
        return "N/A"
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
        if not (1980 <= dt.year <= 2100):
            return "N/A"
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (OverflowError, ValueError, OSError):
        return "N/A"


def _read_utf16(data, offset, length):
    if offset < 0 or length <= 0 or offset + length > len(data):
        return ""
    return data[offset:offset + length].decode('utf-16-le', errors='ignore').rstrip('\x00')


def parse_appcompatcache(data):
    """Parse a raw AppCompatCache registry value into entry dicts.

    Returns [] rather than raising on malformed input: a partially recoverable
    cache should not abort the whole carve.
    """
    if not data or len(data) < 8:
        return []

    try:
        signature = struct.unpack('<I', data[:4])[0]
    except struct.error:
        return []

    if signature == WIN7_MAGIC:
        return _parse_win7(data)
    if signature in (WIN10_MAGIC, WIN10_CREATORS_MAGIC):
        return _parse_win10(data, signature)
    if signature == WIN8_MAGIC:
        return _parse_win8(data)
    return []


def _parse_win7(data):
    """Windows 7 / Server 2008 R2 layout.

    x64 entries are 48 bytes with 4 bytes of padding after the two path-length
    WORDs (for QWORD alignment); x86 entries are 32 bytes with no padding.
    The layout is chosen by whichever yields usable path offsets.
    """
    try:
        count = struct.unpack('<I', data[4:8])[0]
    except struct.error:
        return []

    count = min(count, 4096)
    for entry_size, layout, header in ((48, '<HHIQQ', 128), (32, '<HHIII', 128)):
        entries = []
        offset = header
        for _ in range(count):
            if offset + entry_size > len(data):
                break
            try:
                fields = struct.unpack(
                    layout, data[offset:offset + struct.calcsize(layout)]
                )
            except struct.error:
                break
            path_len, _max_len, _pad, path_offset, last_modified = fields

            path = _read_utf16(data, path_offset, path_len)
            if path:
                entries.append({
                    "path": path.replace('\\??\\', ''),
                    "last_modified": _filetime(last_modified),
                    "source": "AppCompatCache (Win7)",
                })
            offset += entry_size

        # A correct layout recovers most of the advertised entries; a wrong one
        # reads garbage offsets and recovers almost nothing.
        if len(entries) >= max(1, count // 4):
            return entries

    return []


def _parse_win8(data):
    """Windows 8 layout: variable-length entries tagged '00ts'/'10ts'."""
    entries = []
    offset = 128
    while offset + 12 < len(data) and len(entries) < 1024:
        try:
            tag = data[offset:offset + 4]
            if tag not in (b'00ts', b'10ts'):
                offset += 1
                continue
            entry_len = struct.unpack('<I', data[offset + 8:offset + 12])[0]
            path_len = struct.unpack('<H', data[offset + 12:offset + 14])[0]
            path = _read_utf16(data, offset + 14, path_len)
            if path:
                entries.append({
                    "path": path.replace('\\??\\', ''),
                    "last_modified": "N/A",
                    "source": "AppCompatCache (Win8)",
                })
            offset += 12 + entry_len
        except (struct.error, IndexError):
            break
    return entries


def _parse_win10(data, signature):
    """Windows 10 layout: '10ts'-tagged entries after a 48/52-byte header."""
    entries = []
    offset = signature  # header length equals the magic value (0x30 / 0x34)
    while offset + 12 < len(data) and len(entries) < 1024:
        try:
            if data[offset:offset + 4] != b'10ts':
                offset += 1
                continue
            entry_len = struct.unpack('<I', data[offset + 8:offset + 12])[0]
            path_len = struct.unpack('<H', data[offset + 12:offset + 14])[0]
            path = _read_utf16(data, offset + 14, path_len)
            ts_off = offset + 14 + path_len
            last_modified = "N/A"
            if ts_off + 8 <= len(data):
                last_modified = _filetime(
                    struct.unpack('<Q', data[ts_off:ts_off + 8])[0]
                )
            if path:
                entries.append({
                    "path": path.replace('\\??\\', ''),
                    "last_modified": last_modified,
                    "source": "AppCompatCache (Win10)",
                })
            offset += 12 + entry_len
        except (struct.error, IndexError):
            break
    return entries
