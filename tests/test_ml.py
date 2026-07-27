import pandas as pd

from forensics.ml import engineer_features, get_anomaly_status


def test_engineered_features_present(artifact_df):
    out = engineer_features(artifact_df)
    for col in ('HourOfDay', 'EventsPerMinute', 'EventID_Num',
                'AnomalyScore', 'AnomalyLabel'):
        assert col in out.columns


def test_hour_of_day_parsed(artifact_df):
    out = engineer_features(artifact_df)
    hours = dict(zip(out['Event ID'], out['HourOfDay']))
    assert hours['4624'] == 9
    assert hours['1102'] == 3


def test_heuristic_threat_id_flagged(artifact_df):
    out = engineer_features(artifact_df)
    cleared = out[out['Event ID'] == '1102'].iloc[0]
    assert cleared['AnomalyScore'] == -1
    assert 'Audit Log Cleared' in cleared['AnomalyLabel']


def test_blank_event_id_is_not_flagged_as_kernel_threat():
    """Missing Event IDs must not collide with heuristic threat ID 0."""
    df = pd.DataFrame([{
        'Date and Time': '2024-03-01 10:00:00', 'Event ID': '',
        'Task Category': 'File Discovery: notes.txt', 'LogSource': 'FILESYSTEM',
        'Keywords': 'None', 'ArtifactType': 'FILESYSTEM',
    }])
    out = engineer_features(df)
    assert out.iloc[0]['EventID_Num'] == -1
    assert 'Kernel Critical Event' not in out.iloc[0]['AnomalyLabel']


def test_events_per_minute_counts_burst():
    """A burst inside the 60s window should score higher than an isolated event."""
    rows = [{
        'Date and Time': f'2024-03-01 04:00:{s:02d}', 'Event ID': '4625',
        'Task Category': 'failed logon', 'LogSource': 'SECURITY',
        'Keywords': 'None', 'ArtifactType': 'EVTX',
    } for s in range(0, 30)]
    rows.append({
        'Date and Time': '2024-03-01 23:59:00', 'Event ID': '4625',
        'Task Category': 'failed logon', 'LogSource': 'SECURITY',
        'Keywords': 'None', 'ArtifactType': 'EVTX',
    })
    out = engineer_features(pd.DataFrame(rows))
    assert out['EventsPerMinute'].max() >= 30
    assert out['EventsPerMinute'].min() == 1


def test_get_anomaly_status_defaults():
    assert get_anomaly_status({}) == (1, "VERIFIED NORMAL")
