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


def _deep_tree():
    """A tree with the Firefox profile at the depth that was being truncated."""
    return {
        "/": [_Entry("Users", type_=2), _Entry("$Recycle.Bin", type_=2)],
        "/Users": [_Entry("jimmy", type_=2)],
        "/Users/jimmy": [_Entry("AppData", type_=2), _Entry("Cookies")],
        "/Users/jimmy/AppData": [_Entry("Roaming", type_=2)],
        "/Users/jimmy/AppData/Roaming": [_Entry("Mozilla", type_=2)],
        "/Users/jimmy/AppData/Roaming/Mozilla": [_Entry("Firefox", type_=2)],
        "/Users/jimmy/AppData/Roaming/Mozilla/Firefox": [_Entry("Profiles", type_=2)],
        "/Users/jimmy/AppData/Roaming/Mozilla/Firefox/Profiles": [
            _Entry("8pp14cbi.default", type_=2),
        ],
        "/Users/jimmy/AppData/Roaming/Mozilla/Firefox/Profiles/8pp14cbi.default": [
            _Entry("places.sqlite"),
        ],
        "/$Recycle.Bin": [_Entry("S-1-5-21-1001", type_=2)],
        "/$Recycle.Bin/S-1-5-21-1001": [_Entry("$IABCDEF.txt"), _Entry("$RABCDEF.txt")],
    }


def test_shared_index_matches_a_direct_walk():
    """The shared index must find exactly what walking per-caller found."""
    patterns = [r'^places\.sqlite$', r'^Cookies$']

    walked = extractors.heuristic_discover_files(
        FakeFS(_deep_tree()), patterns, max_depth=14)

    fs = FakeFS(_deep_tree())
    index = extractors.build_path_index(fs, max_depth=14)
    filtered = extractors.heuristic_discover_files(
        fs, patterns, max_depth=14, index=index)

    assert sorted(walked) == sorted(filtered)
    assert "/Users/jimmy/AppData/Roaming/Mozilla/Firefox/Profiles/" \
           "8pp14cbi.default/places.sqlite" in filtered


def test_index_is_built_from_exactly_one_traversal():
    """The whole point: four callers, one walk."""
    fs = FakeFS(_deep_tree())
    index = extractors.build_path_index(fs, max_depth=14)
    walks_for_index = fs.access_count

    for patterns in ([r'^\$I'], [r'^Cookies$'], [r'^.*\.eml$'], [r'^SRUDB\.dat$']):
        extractors.heuristic_discover_files(fs, patterns, max_depth=14, index=index)

    # Filtering four times must not touch the filesystem at all.
    assert fs.access_count == walks_for_index


def test_index_reaches_recycle_bin_contents():
    """$Recycle.Bin is skipped by the per-call walk but must be in the index."""
    fs = FakeFS(_deep_tree())
    index = extractors.build_path_index(fs, max_depth=14)

    hits = extractors.heuristic_discover_files(
        fs, [r'^\$I', r'^\$R'], max_depth=14, index=index)

    assert "/$Recycle.Bin/S-1-5-21-1001/$IABCDEF.txt" in hits
    assert "/$Recycle.Bin/S-1-5-21-1001/$RABCDEF.txt" in hits


@pytest.mark.parametrize("max_depth", [0, 1, 2, 3, 4, 6, 10, 14])
def test_index_depth_cutoff_matches_the_walk(max_depth):
    """Caught a real off-by-one: the filter was one level shallower than the walk."""
    tree = {
        "/": [_Entry("a", type_=2)],
        "/a": [_Entry("b", type_=2)],
        "/a/b": [_Entry("c", type_=2)],
        "/a/b/c": [_Entry("d.txt")],
    }
    patterns = [r'^a$', r'^b$', r'^c$', r'^d\.txt$']

    walked = sorted(extractors.heuristic_discover_files(
        FakeFS(tree), patterns, max_depth=max_depth))

    fs = FakeFS(tree)
    index = extractors.build_path_index(fs, max_depth=14)
    filtered = sorted(extractors.heuristic_discover_files(
        fs, patterns, max_depth=max_depth, index=index))

    assert walked == filtered


def test_index_respects_start_path_and_depth():
    fs = FakeFS(_deep_tree())
    index = extractors.build_path_index(fs, max_depth=14)

    scoped = extractors.heuristic_discover_files(
        fs, [r'^places\.sqlite$'], start_path="/$Recycle.Bin",
        max_depth=14, index=index)
    assert scoped == []

    too_shallow = extractors.heuristic_discover_files(
        fs, [r'^places\.sqlite$'], max_depth=3, index=index)
    assert too_shallow == []


def test_filesystem_walk_does_not_double_count_overlapping_roots():
    """'/Users' and '/USERS' resolve to the same directory; '/' reaches both.

    Without dedup the same file is recorded two to four times, which inflated
    the reference image's deleted-file count from 663 to 1,334.
    """
    shared = [_Entry("secret.doc"), _Entry("notes.txt")]
    tree = {
        "/": [_Entry("Users", type_=2), _Entry("$OrphanFiles", type_=2)],
        "/Users": shared,
        "/USERS": shared,            # same directory, different spelling
        "/$OrphanFiles": [_Entry("deleted.bin")],
    }

    frame = extractors.walk_filesystem(FakeFS(tree), limit=1000, max_depth=5)

    paths = [p.lower() for p in frame["_filepath"]]
    assert len(paths) == len(set(paths)), f"duplicate paths recorded: {paths}"
    assert paths.count("/users/secret.doc") == 1
    assert paths.count("/$orphanfiles/deleted.bin") == 1


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
