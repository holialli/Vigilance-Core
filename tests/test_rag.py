import pytest
import pandas as pd

from forensics.rag import (_embed_fingerprint, _normalize_for_embedding,
                           _read_fingerprint, _write_fingerprint)


def test_timestamps_collapse():
    a = _normalize_for_embedding("Logon at 2024-03-01 09:15:00 UTC")
    b = _normalize_for_embedding("Logon at 2025-11-22 23:01:44 UTC")
    assert a == b


def test_guid_collapses():
    a = _normalize_for_embedding("AppID {1234ABCD-1234-1234-1234-123456789ABC}")
    b = _normalize_for_embedding("AppID {FFFFFFFF-0000-1111-2222-333333333333}")
    assert a == b


def test_distinct_events_stay_distinct():
    a = _normalize_for_embedding("The audit log was cleared")
    b = _normalize_for_embedding("A user account was created")
    assert a != b


def _frame(texts):
    return pd.DataFrame({"Task Category": texts})


def test_index_fingerprint_is_order_sensitive():
    """A cached index is only reusable if its vectors still line up row for row.
    Same texts in a different order is a *different* index, because retrieval
    resolves vector i to embed_df row i — and the old check, `ntotal ==
    len(embed_df)`, could not see the difference. On the real case that let
    51,195 of 60,414 positions shift while the index still read as valid."""
    a = _frame(["logon failed", "audit log cleared", "usb attached"])
    b = _frame(["audit log cleared", "logon failed", "usb attached"])

    assert _embed_fingerprint(a) == _embed_fingerprint(a.copy())
    assert _embed_fingerprint(a) != _embed_fingerprint(b), \
        "reordering the same texts produced the same fingerprint"


def test_index_fingerprint_notices_changed_content():
    a = _frame(["logon failed", "audit log cleared"])
    b = _frame(["logon failed", "audit log CLEARED"])
    assert _embed_fingerprint(a) != _embed_fingerprint(b)


def test_a_mismatched_index_is_never_opened(tmp_path, monkeypatch):
    """Reading the index to decide it is useless costs a faiss import and the
    whole allocation (93 MB here) in the process that is about to re-encode.
    Doing it in that order segfaulted the parent. The sidecar decides first."""
    import sys
    import types

    import forensics.rag as rag

    cache = tmp_path / "faiss.index"
    cache.write_bytes(b"stale index")
    _write_fingerprint(str(cache), "0000000000000000")

    opened = []
    fake = types.ModuleType("faiss")
    fake.read_index = lambda p: opened.append(p)
    monkeypatch.setitem(sys.modules, "faiss", fake)
    monkeypatch.setattr(rag, "CACHE_DIR", str(tmp_path.parent))

    # Stop at the decision point — the rebuild itself is not what is under test,
    # and letting it run would load a real model.
    class _Rebuilt(Exception):
        pass

    def _stop(*a, **k):
        raise _Rebuilt

    monkeypatch.setattr(rag, "encode_bulk", _stop)

    import threading

    class _S:
        current_audit_df = pd.DataFrame({
            "ArtifactType": ["EVTX"], "Task Category": ["logon failed"]})
        faiss_index = None
        image_hash_sha256 = tmp_path.name
        faiss_lock = threading.Lock()

    with pytest.raises(_Rebuilt):
        rag.build_rag_context("Init", _S())
    assert opened == [], "opened an index whose fingerprint already ruled it out"


def test_missing_fingerprint_reads_as_unverifiable(tmp_path):
    """An index written before fingerprinting has no sidecar. That must read as
    'cannot vouch for this' rather than as a match."""
    cache = tmp_path / "faiss.index"
    cache.write_bytes(b"not really an index")
    assert _read_fingerprint(str(cache)) is None
    assert _read_fingerprint(str(cache)) != _embed_fingerprint(_frame(["x"]))

    _write_fingerprint(str(cache), _embed_fingerprint(_frame(["x"])))
    assert _read_fingerprint(str(cache)) == _embed_fingerprint(_frame(["x"]))
