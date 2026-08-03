"""Behavioral anomaly scoring (Isolation Forest) and feature engineering.

`compute_features` is the single definition of the feature set, and
`isolation_model.py` imports it rather than reimplementing it. Two copies of
this arithmetic is how the last train/serve skew got in — the lookback window
was 50 rows at inference and 100 in training, and nothing detected it because
both files independently "looked right".
"""

import os

import joblib
import numpy as np
import pandas as pd

from .config import HEURISTIC_THREAT_IDS, MODEL_PATH

FEATURE_COLUMNS = ["EventID_Num", "HourOfDay", "EventsPerMinute"]

_ml_alarm = None


def get_model():
    """Lazily load the trained Isolation Forest so importing this module is side-effect free."""
    global _ml_alarm
    if _ml_alarm is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"[ERROR] ML model not found at '{MODEL_PATH}'. "
                f"Run 'python isolation_model.py' first to train it."
            )
        _ml_alarm = joblib.load(MODEL_PATH)
        print(f"  [OK] Loaded ML model: {MODEL_PATH}")
    return _ml_alarm


def compute_features(df):
    """Derive the model's three features. Used for training *and* inference.

    Returns the frame sorted by timestamp, with FEATURE_COLUMNS populated.
    """
    ts = pd.to_datetime(df['Date and Time'], errors='coerce')
    df = df.assign(_ts=ts).sort_values('_ts').reset_index(drop=True)

    # An unparseable timestamp used to become "hour 12", inventing a noon spike
    # out of missing data. -1 keeps it a distinct value the model can isolate on
    # its own terms rather than smuggling it into the middle of the range.
    df['HourOfDay'] = df['_ts'].dt.hour.fillna(-1).astype(int)

    # Events in the preceding 60 seconds. This used to be counted by scanning
    # back at most 100 rows, which made it a rate *and* a cap. Measured on the
    # 80,191-row IACIS carve: the old loop took 11.0s, returned at most 101, and
    # **58,058 rows (72%) sat at that ceiling** — their true rates ranged from
    # 101 to 14,474, every one of them reported as 101. The two agree on 28% of
    # rows. A feature that is constant across three quarters of the data cannot
    # separate anything, which is most of why the model was flagging 37%.
    # searchsorted has no such bound: 0.01s, 924x faster, 14,474 distinct values.
    valid = df['_ts'].notna()
    df['EventsPerMinute'] = 1
    if valid.any():
        t = df.loc[valid, '_ts'].to_numpy(dtype='datetime64[ns]')
        window_start = t - np.timedelta64(60, 's')
        first = np.searchsorted(t, window_start, side='left')
        df.loc[valid, 'EventsPerMinute'] = (np.arange(len(t)) - first + 1)

    df.drop(columns=['_ts'], inplace=True, errors='ignore')

    def extract_eid(eid_raw):
        val = ''.join(filter(str.isdigit, str(eid_raw)))
        return int(val) if val else -1  # 0 collides with a real heuristic threat ID

    df['EventID_Num'] = df['Event ID'].apply(extract_eid)
    return df


def engineer_features(df):
    df = compute_features(df)

    print("   Vectorizing behavioral threat predictions...")

    try:
        features = df[FEATURE_COLUMNS].values
        df['ML_Prediction'] = get_model().predict(features)
    except Exception as e:
        print(f"   Vectorized ML failed: {e}")
        df['ML_Prediction'] = 1

    def resolve_label(row):
        eid = row['EventID_Num']
        if eid in HEURISTIC_THREAT_IDS:
            return -1, f"HEURISTIC THREAT — {HEURISTIC_THREAT_IDS[eid]}"
        if row.get('ML_Prediction', 1) == -1:
            return -1, "STATISTICAL ANOMALY (Behavioral)"
        return 1, "VERIFIED NORMAL"

    statuses = df.apply(resolve_label, axis=1)
    df['AnomalyScore'] = [s[0] for s in statuses]
    df['AnomalyLabel'] = [s[1] for s in statuses]

    return df


def get_anomaly_status(row):
    score = row.get('AnomalyScore', 1)
    label = row.get('AnomalyLabel', "VERIFIED NORMAL")
    return score, label
