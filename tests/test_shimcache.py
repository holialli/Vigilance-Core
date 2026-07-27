import struct

from forensics.shimcache import parse_appcompatcache


def _win7_blob(paths, x64=True):
    """Build a minimal Win7-layout AppCompatCache blob.

    x64 entries are 48 bytes and carry 4 bytes of padding after the two
    path-length WORDs; x86 entries are 32 bytes with 32-bit offsets.
    """
    header = struct.pack('<II', 0xBADC0FEE, len(paths)) + b'\x00' * 120
    entry_size = 48 if x64 else 32
    entries = b''
    strings = b''
    string_base = len(header) + entry_size * len(paths)
    for p in paths:
        encoded = p.encode('utf-16-le')
        offset = string_base + len(strings)
        if x64:
            head = struct.pack('<HHIQQ', len(encoded), len(encoded), 0, offset, 0)
        else:
            head = struct.pack('<HHIII', len(encoded), len(encoded), 0, offset, 0)
        entries += head + b'\x00' * (entry_size - len(head))
        strings += encoded
    return header + entries + strings


def test_parses_win7_x64_entries():
    """Regression: x64 entries pad 4 bytes after the length WORDs."""
    blob = _win7_blob([r'\??\C:\Windows\evil.exe', r'\??\C:\tools\nc.exe'])
    paths = [e["path"] for e in parse_appcompatcache(blob)]
    assert r'C:\Windows\evil.exe' in paths
    assert r'C:\tools\nc.exe' in paths


def test_parses_win7_x86_entries():
    blob = _win7_blob([r'\??\C:\Windows\evil.exe'], x64=False)
    paths = [e["path"] for e in parse_appcompatcache(blob)]
    assert r'C:\Windows\evil.exe' in paths


def test_recovers_many_entries():
    """A correct layout must recover essentially all advertised entries."""
    paths = [rf'\??\C:\bin\tool{i}.exe' for i in range(200)]
    assert len(parse_appcompatcache(_win7_blob(paths))) == 200


def test_device_prefix_stripped():
    entries = parse_appcompatcache(_win7_blob([r'\??\C:\a.exe']))
    assert entries[0]["path"] == r'C:\a.exe'


def test_source_recorded():
    entries = parse_appcompatcache(_win7_blob([r'\??\C:\a.exe']))
    assert "Win7" in entries[0]["source"]


def test_empty_input():
    assert parse_appcompatcache(b'') == []
    assert parse_appcompatcache(None) == []


def test_unknown_signature_returns_empty():
    assert parse_appcompatcache(struct.pack('<I', 0xDEADBEEF) + b'\x00' * 200) == []


def test_truncated_blob_does_not_raise():
    blob = _win7_blob([r'\??\C:\a.exe'])[:100]
    assert parse_appcompatcache(blob) == []


def test_garbage_does_not_raise():
    assert parse_appcompatcache(b'\xBA\xDC\x0F\xEE' + b'\xff' * 300) == []
