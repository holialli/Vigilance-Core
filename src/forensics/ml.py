"""Behavioral anomaly scoring (Isolation Forest) and feature engineering."""

import os
from datetime import timedelta

import joblib
import pandas as pd

from .config import HEURISTIC_THREAT_IDS, MODEL_PATH

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


def engineer_features(df):
    def extract_hour(dt_str):
        try:
            return pd.to_datetime(str(dt_str)).hour
        except Exception:
            return 12

    df['HourOfDay'] = df['Date and Time'].apply(extract_hour)

    df['_ts'] = pd.to_datetime(df['Date and Time'], errors='coerce')
    df = df.sort_values('_ts').reset_index(drop=True)

    epm = []
    timestamps = df['_ts'].tolist()
    for i, ts in enumerate(timestamps):
        if pd.isna(ts):
            epm.append(1)
            continue
        window_start = ts - timedelta(seconds=60)
        count = 0
        # must match isolation_model.py's training window
        for j in range(max(0, i - 100), i + 1):
            ts_j = timestamps[j]
            if pd.notna(ts_j) and window_start <= ts_j <= ts:
                count += 1
        epm.append(count)

    df['EventsPerMinute'] = epm
    df.drop(columns=['_ts'], inplace=True, errors='ignore')

    print("   Vectorizing behavioral threat predictions...")

    def extract_eid(eid_raw):
        val = ''.join(filter(str.isdigit, str(eid_raw)))
        return int(val) if val else -1  # 0 collides with a real heuristic threat ID

    df['EventID_Num'] = df['Event ID'].apply(extract_eid)

    try:
        features = df[['EventID_Num', 'HourOfDay', 'EventsPerMinute']].values
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
