"""Regression guards for the directory-iteration bug class.

A pytsk3 directory listing is invalidated by any other filesystem access made
through the same handle: open a file (or descend into a subdirectory) while a
listing is still being iterated and the listing silently stops early. Nothing
raises — entries simply never appear. On the reference image this cost
System.evtx and Application.evtx, the two largest event logs, plus every user
profile after the first.

FakeFS below reproduces exactly that behaviour so the "collect names first,
read second" ordering stays enforced without needing a real disk image.
"""

import pandas as pd
import pytest

from forensics import extractors


class _Name:
    def __init__(self, name, type_):
        self.name = name.encode()
        self.type = type_


class _Meta:
    def __init__(self, size, type_):
        self.size = size
        self.type = type_
        self.mtime = 1_400_000_000
        self.crtime = 1_400_000_000
        self.flags = 1


class _Entry:
    def __init__(self, name, type_=1, size=4096):
        self.info = type("info", (), {})()
        self.info.name = _Name(name, type_)
        self.info.meta = _Meta(size, type_)


class _Listing:
    """Yields entries, but stops early if the filesystem is touched mid-iteration."""

    def __init__(self, fs, entries):
        self._fs = fs
        self._entries = entries

    def __iter__(self):
        token = self._fs.access_count
        for entry in self._entries:
            if self._fs.access_count != token:
                self._fs.truncated = True
                return  # listing invalidated — exactly what TSK does
            yield entry


class FakeFS:
    def __init__(self, tree, file_bytes=b"x" * 4096):
        self.tree = tree            # {path: [_Entry, ...]}
        self.file_bytes = file_bytes
        self.access_count = 0
        self.truncated = False
        self.opened = []

    def open_dir(self, path):
        self.access_count += 1
        if path not in self.tree:
            raise IOError(f"no such directory: {path}")
        return _Listing(self, self.tree[path])

    def open(self, path):
        self.access_count += 1
        self.opened.append(path)
        fs = self

        class _File:
            info = type("info", (), {"meta": _Meta(len(fs.file_bytes), 1)})()

            def read_random(self, offset, size):
                return fs.file_bytes[offset:offset + size]

        return _File()


LOG_DIR = "/Windows/System32/winevt/Logs"


@pytest.fixture
def evtx_fs():
    return FakeFS({
        LOG_DIR: [
            _Entry("Application.evtx"),
            _Entry("Security.evtx"),
            _Entry("System.evtx"),
            _Entry("Setup.evtx"),
        ],
    })


def test_every_evtx_file_is_read(evtx_fs, monkeypatch):
    """Reading file 1 must not stop the listing before files 2-4."""
    monkeypatch.setattr(
        extractors, "parse_evtx_file",
        lambda data: pd.DataFrame([{"Event ID": "1", "Task Category": "e"}]),
    )
    result = extractors.extract_all_evtx(evtx_fs)

    assert evtx_fs.opened == [
        f"{LOG_DIR}/Application.evtx",
        f"{LOG_DIR}/Security.evtx",
        f"{LOG_DIR}/System.evtx",
        f"{LOG_DIR}/Setup.evtx",
    ]
    assert not evtx_fs.truncated
    assert len(result) == 4
    assert set(result["LogSource"]) == {"APPLICATION", "SECURITY", "SYSTEM", "SETUP"}


def test_duplicate_directory_entries_are_not_read_twice(monkeypatch):
    """An unallocated entry can share a name with the live one."""
    fs = FakeFS({LOG_DIR: [_Entry("System.evtx"), _Entry("System.evtx")]})
    monkeypatch.setattr(
        extractors, "parse_evtx_file",
        lambda data: pd.DataFrame([{"Event ID": "1", "Task Category": "e"}]),
    )
    result = extractors.extract_all_evtx(fs)

    assert fs.opened == [f"{LOG_DIR}/System.evtx"]
    assert len(result) == 1


def test_unreadable_channel_is_reported_not_swallowed(evtx_fs, monkeypatch, capsys):
    """A channel that cannot be parsed is a gap in the evidence, not a non-event."""
    def _explode(data):
        raise IOError("$IDX_ROOT not found")

    monkeypatch.setattr(extractors, "parse_evtx_file", _explode)
    extractors.extract_all_evtx(evtx_fs)

    output = capsys.readouterr().out
    assert "4 EVTX file(s) could not be read" in output
    assert "System.evtx" in output
    assert "$IDX_ROOT not found" in output


def test_discovery_walks_all_siblings_not_just_the_first():
    """heuristic_discover_files recursed mid-iteration, hiding later siblings."""
    fs = FakeFS({
        "/": [_Entry("Users", type_=2)],
        "/Users": [
            _Entry("alice", type_=2),
            _Entry("bob", type_=2),
            _Entry("carol", type_=2),
        ],
        "/Users/alice": [_Entry("$INDEX.dat")],
        "/Users/bob": [_Entry("$INDEX.dat")],
        "/Users/carol": [_Entry("$INDEX.dat")],
    })

    found = extractors.heuristic_discover_files(fs, [r'^\$INDEX'], max_depth=4)

    assert not fs.truncated
    assert sorted(found) == [
        "/Users/alice/$INDEX.dat",
        "/Users/bob/$INDEX.dat",
        "/Users/carol/$INDEX.dat",
    ]


def test_filesystem_walk_indexes_siblings_after_a_subdirectory():
    """walk_filesystem recursed mid-iteration, so siblings after a dir vanished."""
    fs = FakeFS({
        "/": [
            _Entry("Users", type_=2),
            _Entry("pagefile.sys"),
            _Entry("boot.ini"),
        ],
        "/Users": [_Entry("alice", type_=2)],
        "/Users/alice": [_Entry("NTUSER.DAT")],
    })

    frame = extractors.walk_filesystem(fs, limit=1000, max_depth=5)

    assert not fs.truncated
    names = set(frame["_filename"])
    # pagefile.sys and boot.ini follow the Users directory in the listing —
    # they are precisely what the old recurse-while-iterating code lost.
    assert {"pagefile.sys", "boot.ini", "NTUSER.DAT", "alice", "Users"} <= names
