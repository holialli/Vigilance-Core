"""Recycle-bin record parsing.

Records are synthesised from the documented on-disk layouts so the tests pin the
format, not one sample image.
"""
import struct
from datetime import datetime, timezone

from forensics.recyclebin import (describe, filetime_to_datetime, parse_i_file,
                                  parse_info2)

# 2004-08-27 10:46:33 UTC as a Windows FILETIME.
DELETED_AT = datetime(2004, 8, 27, 10, 46, 33, tzinfo=timezone.utc)
FILETIME = int(
    (DELETED_AT - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000
)


def _info2_record(path, drive=2, size=4096, filetime=FILETIME):
    rec = bytearray(800)
    ansi = path.encode("latin-1")[:259]
    rec[0:len(ansi)] = ansi
    struct.pack_into("<I", rec, 0x104, 1)
    struct.pack_into("<I", rec, 0x108, drive)
    struct.pack_into("<Q", rec, 0x10C, filetime)
    struct.pack_into("<I", rec, 0x114, size)
    wide = path.encode("utf-16-le")[:518]
    rec[0x118:0x118 + len(wide)] = wide
    return bytes(rec)


def _info2_file(paths):
    header = bytearray(20)
    struct.pack_into("<I", header, 0x00, 5)       # version 5 (XP)
    struct.pack_into("<I", header, 0x0C, 800)     # record size
    return bytes(header) + b"".join(_info2_record(p) for p in paths)


def test_filetime_conversion():
    assert filetime_to_datetime(FILETIME) == DELETED_AT


def test_filetime_rejects_implausible_values():
    assert filetime_to_datetime(0) is None
    assert filetime_to_datetime(1) is None            # year 1601
    assert filetime_to_datetime(2 ** 63) is None      # overflow


def test_info2_recovers_original_paths():
    data = _info2_file([r"C:\Documents and Settings\Mr. Evil\Desktop\nc.exe",
                        r"C:\Documents and Settings\Mr. Evil\My Documents\creds.txt"])
    records = parse_info2(data)

    assert len(records) == 2
    assert records[0]["original_path"].endswith("nc.exe")
    assert records[0]["drive"] == "C:"
    assert records[0]["size"] == 4096
    assert records[0]["deleted_time"] == DELETED_AT
    assert records[1]["original_path"].endswith("creds.txt")


def test_info2_counts_executables():
    """NIST Hacking Case Q28 asks how many executables are in the recycle bin."""
    data = _info2_file([r"C:\a\one.exe", r"C:\b\two.exe",
                        r"C:\c\notes.txt", r"C:\d\three.exe"])
    records = parse_info2(data)
    exes = [r for r in records if r["original_path"].lower().endswith(".exe")]
    assert len(exes) == 3


def test_info2_handles_truncated_and_empty_input():
    assert parse_info2(b"") == []
    assert parse_info2(b"\x00" * 10) == []
    assert parse_info2(_info2_file([r"C:\x\y.exe"])[:400]) == []


def test_i_file_version_1():
    data = struct.pack("<QQQ", 1, 123456, FILETIME)
    path = r"C:\Users\jimmy\Documents\secret.pdf"
    data += path.encode("utf-16-le").ljust(520, b"\x00")

    record = parse_i_file(data)
    assert record["original_path"] == path
    assert record["size"] == 123456
    assert record["deleted_time"] == DELETED_AT


def test_i_file_version_2():
    path = r"C:\Users\jimmy\Pictures\evidence.jpg"
    encoded = path.encode("utf-16-le") + b"\x00\x00"
    data = (struct.pack("<QQQ", 2, 999, FILETIME)
            + struct.pack("<I", len(path) + 1) + encoded)

    record = parse_i_file(data)
    assert record["original_path"] == path
    assert record["size"] == 999


def test_i_file_rejects_garbage():
    assert parse_i_file(b"") is None
    assert parse_i_file(b"\x00" * 8) is None
    # A corrupt length must not drive a huge read.
    assert parse_i_file(struct.pack("<QQQ", 2, 0, FILETIME)
                        + struct.pack("<I", 0xFFFFFFFF)) is None


def test_describe_is_readable():
    record = {"original_path": r"C:\a\nc.exe", "size": 2 << 20,
              "deleted_time": DELETED_AT}
    text = describe(record, "/RECYCLER/S-1-5-21-1003/INFO2")
    assert "nc.exe" in text
    assert "2.0 MB" in text
    assert "2004-08-27 10:46:33" in text
