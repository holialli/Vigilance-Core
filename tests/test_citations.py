from forensics.llm import format_evidence_block
from forensics.rag import format_citations

ROWS = [
    {"tag": "E1", "time": "2024-03-01 03:02:00", "event_id": "1102",
     "source": "SECURITY", "artifact_type": "EVTX",
     "description": "The audit log was cleared", "distance": 0.1},
    {"tag": "E2", "time": "2024-03-01 09:15:00", "event_id": "4624",
     "source": "SECURITY", "artifact_type": "EVTX",
     "description": "TargetUserName: alice", "distance": 0.4},
]


def test_no_rows_yields_nothing():
    assert format_citations([]) == ""


def test_only_cited_evidence_is_rendered():
    out = format_citations(ROWS, answer_text="The log was cleared [E1].")
    assert "[E1]" in out
    assert "audit log was cleared" in out
    assert "E2" not in out


def test_multiple_citations_render():
    out = format_citations(ROWS, answer_text="Cleared [E1] then logon [E2].")
    assert "[E1]" in out and "[E2]" in out


def test_uncited_answer_falls_back_to_all_retrieved():
    """If the model cites nothing, still show what was retrieved rather than hiding it."""
    out = format_citations(ROWS, answer_text="No relevant evidence found.")
    assert "[E1]" in out and "[E2]" in out


def test_long_descriptions_truncated():
    rows = [{**ROWS[0], "description": "x" * 500}]
    out = format_citations(rows, answer_text="see [E1]")
    assert "…" in out
    assert len(out) < 500


def test_offline_block_emits_tags():
    ctx = "[E1] Time: a | EventID: 1 | Source: s | Description: d\n[E2] Time: b"
    assert format_evidence_block(ctx) == "[E1] [E2]"


def test_offline_block_empty_context():
    assert format_evidence_block("") == ""
