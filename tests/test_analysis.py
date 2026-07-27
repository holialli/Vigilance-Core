import pandas as pd

from forensics.analysis import (
    activity_peaks,
    anomaly_overview,
    build_timeline,
    format_triage_markdown,
    search_artifacts,
    triage_findings,
)


def test_search_finds_substring(artifact_df):
    hits, note = search_artifacts(artifact_df, "alice")
    assert len(hits) == 2
    assert "2 matches" in note


def test_search_is_case_insensitive(artifact_df):
    hits, _ = search_artifacts(artifact_df, "ALICE")
    assert len(hits) == 2


def test_search_no_match(artifact_df):
    hits, note = search_artifacts(artifact_df, "zzzznotfound")
    assert hits.empty
    assert "No matches" in note


def test_search_regex(artifact_df):
    hits, _ = search_artifacts(artifact_df, r"RID:\s*\d+", use_regex=True)
    assert len(hits) == 1


def test_invalid_regex_reports_error_not_crash(artifact_df):
    hits, note = search_artifacts(artifact_df, "user(", use_regex=True)
    assert hits.empty
    assert "Invalid regular expression" in note


def test_search_filters_by_artifact_type(artifact_df):
    hits, _ = search_artifacts(artifact_df, "alice", artifact_type="SAM")
    assert len(hits) == 1


def test_search_empty_case():
    hits, note = search_artifacts(None, "anything")
    assert hits.empty
    assert "No case loaded" in note


def test_timeline_buckets_by_day(artifact_df):
    tl = build_timeline(artifact_df, freq='D')
    assert not tl.empty
    assert set(tl.columns) == {'Period', 'ArtifactType', 'Count'}
    assert tl['Count'].sum() == 4


def test_timeline_handles_unparseable_dates():
    df = pd.DataFrame([{
        'Date and Time': 'N/A', 'Event ID': '1', 'Task Category': 'x',
        'LogSource': 'S', 'Keywords': 'None', 'ArtifactType': 'EVTX',
    }])
    assert build_timeline(df).empty


def test_activity_peaks_ranks_busiest_day(artifact_df):
    peaks = activity_peaks(artifact_df)
    assert not peaks.empty
    assert peaks.iloc[0]['Count'] == 4


def test_triage_detects_cleared_log(artifact_df):
    findings = triage_findings(artifact_df)
    cleared = [f for f in findings if "Audit log cleared" in f["label"]]
    assert len(cleared) == 1
    assert cleared[0]["severity"] == "critical"


def test_triage_ignores_event_id_appearing_inside_text():
    """1102 inside a DLL name or GUID must not trigger the cleared-log rule."""
    df = pd.DataFrame([{
        'Date and Time': '2024-03-01 10:00:00', 'Event ID': '7000',
        'Task Category': r'Registry [SYSTEM] services\dot3svc\DisplayName = @dot3svc.dll,-1102',
        'LogSource': 'REGISTRY', 'Keywords': 'None', 'ArtifactType': 'REGISTRY',
    }])
    assert triage_findings(df) == []


def test_triage_ranks_by_severity_not_count():
    df = pd.DataFrame(
        [{'Date and Time': '2024-03-01 10:00:00', 'Event ID': '9000',
          'Task Category': 'USB Device: Kingston', 'LogSource': 'USB_HISTORY',
          'Keywords': 'None', 'ArtifactType': 'USB'} for _ in range(50)]
        + [{'Date and Time': '2024-03-01 03:00:00', 'Event ID': '1102',
            'Task Category': 'The audit log was cleared', 'LogSource': 'SECURITY',
            'Keywords': 'Alert', 'ArtifactType': 'EVTX'}]
    )
    findings = triage_findings(df)
    assert findings[0]["severity"] == "critical"
    assert findings[0]["count"] == 1


def test_triage_respects_min_count():
    """A couple of failed logons is normal; only a run of them is a finding."""
    df = pd.DataFrame([{
        'Date and Time': '2024-03-01 10:00:00', 'Event ID': '4625',
        'Task Category': 'failed logon', 'LogSource': 'SECURITY',
        'Keywords': 'None', 'ArtifactType': 'EVTX',
    } for _ in range(3)])
    assert triage_findings(df) == []


def test_triage_ignores_security_event_id_outside_security_channel():
    """4625 in the APPLICATION channel is an unrelated event, not a brute force."""
    df = pd.DataFrame([{
        'Date and Time': '2024-03-01 10:00:00', 'Event ID': '4625',
        'Task Category': 'param1: 86400 | param2: SuppressDuplicateDuration',
        'LogSource': 'APPLICATION', 'Keywords': 'None', 'ArtifactType': 'EVTX',
    } for _ in range(30)])
    assert triage_findings(df) == []


def test_triage_empty_case():
    assert triage_findings(pd.DataFrame()) == []


def test_triage_markdown_renders(artifact_df):
    md = format_triage_markdown(triage_findings(artifact_df))
    assert "Priority findings" in md
    assert "CRITICAL" in md


def test_triage_markdown_when_clean():
    assert "No high-signal findings" in format_triage_markdown([])


def test_anomaly_overview_flags_noisy_model():
    df = pd.DataFrame({
        'AnomalyScore': [-1] * 40 + [1] * 60,
        'AnomalyLabel': ['STATISTICAL ANOMALY'] * 40 + ['VERIFIED NORMAL'] * 60,
    })
    overview = anomaly_overview(df)
    assert overview["flagged"] == 40
    assert overview["noisy"] is True
    md = format_triage_markdown([], overview)
    assert "weak signal" in md


def test_anomaly_overview_quiet_model_not_marked_noisy():
    df = pd.DataFrame({
        'AnomalyScore': [-1] * 2 + [1] * 98,
        'AnomalyLabel': ['HEURISTIC THREAT — x'] * 2 + ['VERIFIED NORMAL'] * 98,
    })
    overview = anomaly_overview(df)
    assert overview["noisy"] is False
    assert overview["heuristic"] == 2
