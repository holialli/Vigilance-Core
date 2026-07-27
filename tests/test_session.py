from forensics.session import CaseSession


def test_sessions_do_not_share_mutable_state():
    a, b = CaseSession(), CaseSession()

    a.session_log.append({"question": "q", "answer": "a", "time": "t"})
    a.artifact_counts["evtx"] = 5
    a.current_audit_df = "case-a-frame"

    assert b.session_log == []
    assert b.artifact_counts == {}
    assert b.current_audit_df is None


def test_each_session_has_its_own_lock():
    assert CaseSession().faiss_lock is not CaseSession().faiss_lock


def test_fresh_session_defaults():
    s = CaseSession()
    assert s.current_audit_df is None
    assert s.faiss_index is None
    assert s.image_hash_sha256 is None
    assert s.cached_system_facts is None
