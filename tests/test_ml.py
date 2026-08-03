import pandas as pd

from forensics.ml import (FEATURE_COLUMNS, compute_features,
                          engineer_features, get_anomaly_status)


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


def _burst(n, second_stride=0):
    """n events inside one minute, optionally spread by `second_stride`."""
    return pd.DataFrame([{
        'Date and Time': (f'2024-03-01 04:00:{(i * second_stride) % 60:02d}'
                          if second_stride else '2024-03-01 04:00:00'),
        'Event ID': '4625', 'Task Category': 'failed logon',
        'LogSource': 'SECURITY', 'Keywords': 'None', 'ArtifactType': 'EVTX',
    } for i in range(n)])


def test_events_per_minute_is_not_capped_by_the_lookback():
    """The old implementation scanned back at most 100 rows, so its answer
    saturated at 101. On the real image that silently flattened 58,058 rows
    (72%) whose true rates ran from 101 to 14,474 — a feature constant across
    three quarters of the data, which is most of why the model flagged 37%."""
    out = compute_features(_burst(500))
    assert out['EventsPerMinute'].max() == 500, (
        f"capped at {out['EventsPerMinute'].max()}")


def test_events_per_minute_is_a_rolling_window_not_a_running_total():
    """Events older than 60s must drop out, or it becomes a row counter."""
    rows = pd.concat([
        _burst(10),                                    # 04:00:00
        pd.DataFrame([{
            'Date and Time': '2024-03-01 06:00:00', 'Event ID': '4625',
            'Task Category': 'failed logon', 'LogSource': 'SECURITY',
            'Keywords': 'None', 'ArtifactType': 'EVTX',
        }]),
    ], ignore_index=True)
    out = compute_features(rows)
    assert out['EventsPerMinute'].iloc[-1] == 1, (
        "counted events from two hours earlier")


def test_unparseable_timestamp_does_not_become_noon():
    """A missing hour used to default to 12, inventing a midday spike out of
    absent data and putting it in the middle of the feature's range."""
    df = pd.DataFrame([{
        'Date and Time': 'not a date', 'Event ID': '4624',
        'Task Category': 'logon', 'LogSource': 'SECURITY',
        'Keywords': 'None', 'ArtifactType': 'EVTX',
    }])
    assert compute_features(df)['HourOfDay'].iloc[0] == -1


def test_rescoring_does_not_reorder_rows():
    """Retrieval binds FAISS vector i to embed_df row i, so a reordering
    repoints every citation at a different artifact while the answer still
    reads as properly sourced. pandas sorts with quicksort by default, which
    permutes equal keys — and the real image has 80,191 rows over 5,945
    distinct timestamps, one tie group holding 13,222 of them. Sorting
    already-sorted data has to be a no-op."""
    rows = pd.DataFrame([{
        'Date and Time': '2024-03-01 04:00:00', 'Event ID': str(i),
        'Task Category': f'artifact number {i}', 'LogSource': 'SECURITY',
        'Keywords': 'None', 'ArtifactType': 'EVTX',
    } for i in range(400)])          # every row shares one timestamp

    once = compute_features(rows)
    twice = compute_features(once.copy())

    assert once['Task Category'].tolist() == twice['Task Category'].tolist(), \
        "re-scoring permuted rows inside a timestamp tie"
    assert twice['Task Category'].tolist() == rows['Task Category'].tolist(), \
        "sorting reordered rows that were already in order"


def test_stale_scores_are_recomputed_not_preserved(artifact_df):
    """A cached carve carries the labels of whatever model scored it. Evidence
    is a function of the image and safe to cache; the score is a function of the
    image *and* the model file, which changes independently — so re-scoring has
    to overwrite, or a retrained model never reaches an already-carved case."""
    stale = artifact_df.copy()
    stale["AnomalyScore"] = -1
    stale["AnomalyLabel"] = "STATISTICAL ANOMALY (Behavioral)"
    stale["EventsPerMinute"] = 101          # the old capped value

    out = engineer_features(stale)

    assert not (out["AnomalyLabel"] == "STATISTICAL ANOMALY (Behavioral)").all(), \
        "kept the stale labels instead of re-scoring"
    assert (out["EventsPerMinute"] != 101).any(), "kept the stale feature values"


def test_training_and_inference_share_one_feature_definition():
    """isolation_model.py imports this rather than reimplementing it. The last
    train/serve skew was a 50-row lookback at inference against 100 in
    training, and neither file looked wrong on its own."""
    import importlib

    mod = importlib.import_module("forensics.ml")
    assert mod.compute_features is compute_features
    assert FEATURE_COLUMNS == ["EventID_Num", "HourOfDay", "EventsPerMinute"]

    out = compute_features(_burst(5, second_stride=1))
    for col in FEATURE_COLUMNS:
        assert col in out.columns
