from forensics.context import extract_system_context
from forensics.session import CaseSession


def _session(df=None):
    s = CaseSession()
    s.current_audit_df = df
    return s


def test_no_evidence_loaded():
    assert extract_system_context(_session()) == "No evidence loaded."


def test_reports_total_and_host(artifact_df):
    facts = extract_system_context(_session(artifact_df))
    assert "TOTAL LOGS: 4" in facts
    assert "WORKSTATION-7" in facts


def test_sam_user_extracted(artifact_df):
    facts = extract_system_context(_session(artifact_df))
    assert "alice" in facts


def test_sam_login_count_reaches_active_users(artifact_df):
    """Regression: the regex must match 'Login Count:' as emitted by extract_sam_hive."""
    facts = extract_system_context(_session(artifact_df))
    active = [ln for ln in facts.split("\n") if ln.startswith("ACTIVE USERS:")][0]
    assert "42" in active


def test_audit_log_cleared_raises_alert(artifact_df):
    facts = extract_system_context(_session(artifact_df))
    alerts = [ln for ln in facts.split("\n") if ln.startswith("ALERTS:")][0]
    assert "Cleared" in alerts
