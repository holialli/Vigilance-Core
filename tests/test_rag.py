from forensics.rag import _normalize_for_embedding


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
