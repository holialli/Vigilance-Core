import pandas as pd

from forensics.rag import _query_terms, _routed_types, _score_frame


def _frame(rows):
    return pd.DataFrame([
        {'Task Category': desc, 'ArtifactType': atype} for desc, atype in rows
    ])


def test_stopwords_dropped():
    assert _query_terms("Show me all the USB devices") == {"usb", "devices"}


def test_routing_detects_usb():
    assert 'USB' in _routed_types("Show me USB device history")


def test_routing_detects_browser():
    assert 'BROWSER' in _routed_types("What websites were visited?")


def test_routing_empty_for_generic_question():
    assert _routed_types("what happened here") == set()


def test_routed_type_outranks_semantically_similar_noise():
    """A rare USB row must beat bulk registry rows that merely look similar."""
    frame = _frame([
        ("Registry [SYSTEM] ControlSet001\\Enum\\PCI\\device_stuff", "REGISTRY"),
        ("USB Device: LEXAR JUMPDRIVE (Serial: 123)", "USB"),
    ])
    # registry row has a strong semantic score, USB row has none
    scored = _score_frame(frame, {0: 0.85}, _query_terms("USB device history"),
                          {'USB'}, limit=10)
    best = max(scored, key=lambda s: s[0])
    assert best[2] == 1, "USB row should win once routing is applied"


def test_near_duplicate_rows_collapsed():
    """One noisy registry family must not fill every slot."""
    frame = _frame([
        (f"Registry [SYSTEM] CMI-CreateHive\\ControlSet001\\services\\svc{i}\\Start = 2",
         "REGISTRY")
        for i in range(10)
    ])
    scored = _score_frame(frame, {i: 0.5 for i in range(10)},
                          _query_terms("registry services"), set(), limit=10)
    assert len(scored) < 10


def test_empty_frame_scores_nothing():
    assert _score_frame(pd.DataFrame(), {}, {"usb"}, set(), 10) == []
