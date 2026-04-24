"""
═══════════════════════════════════════════════════════════════════════
  FORENSIC IMAGE ANALYSIS ENGINE — Behavioral ML Training Script
  Version: 2.0 (3-Feature Isolation Forest)
═══════════════════════════════════════════════════════════════════════
  Features:  EventID  |  HourOfDay  |  EventsPerMinute
  Model:     Isolation Forest (n_estimators=300, contamination=0.02)
  Output:    models/forensic_alarm_v2.pkl
═══════════════════════════════════════════════════════════════════════
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import joblib
import os
import random

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────────────────────────────
# 1. LOAD TRAINING DATA
# ─────────────────────────────────────────────────────────────────────
data_dir = os.path.join(SCRIPT_DIR, "data")
frames = []

for csv_file in os.listdir(data_dir):
    if csv_file.endswith(".csv"):
        path = os.path.join(data_dir, csv_file)
        print(f"  📂 Loading: {path}")
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)

if not frames:
    print("❌ No CSV files found in data/ directory.")
    exit(1)

df = pd.concat(frames, ignore_index=True)
print(f"\n  ✅ Loaded {len(df)} total rows from {len(frames)} file(s).\n")


# ─────────────────────────────────────────────────────────────────────
# 2. FEATURE ENGINEERING
# ─────────────────────────────────────────────────────────────────────
print("  🔧 Engineering behavioral features...\n")

# Feature 1: EventID (numeric)
df['EventID'] = pd.to_numeric(
    df.get('Event ID', df.get('Source', pd.Series(dtype='str'))),
    errors='coerce'
).fillna(0).astype(int)

# Feature 2: HourOfDay (0-23)
def extract_hour(dt_str):
    try:
        dt = pd.to_datetime(str(dt_str))
        return dt.hour
    except Exception:
        return 12  # Default to noon for unparseable
    
df['HourOfDay'] = df['Date and Time'].apply(extract_hour)

# Feature 3: EventsPerMinute
# Sort by time, then count events in a rolling 60-second window
df['_timestamp'] = pd.to_datetime(df['Date and Time'], errors='coerce')
df = df.sort_values('_timestamp').reset_index(drop=True)

events_per_min = []
timestamps = df['_timestamp'].tolist()
for i, ts in enumerate(timestamps):
    if pd.isna(ts):
        events_per_min.append(1)
        continue
    window_start = ts - timedelta(seconds=60)
    count = 0
    for j in range(max(0, i - 100), i + 1):  # Look back up to 100 rows
        ts_j = timestamps[j]
        if pd.notna(ts_j) and window_start <= ts_j <= ts:
            count += 1
    events_per_min.append(count)

df['EventsPerMinute'] = events_per_min

print(f"  📊 Feature Stats:")
print(f"     EventID range:         {df['EventID'].min()} — {df['EventID'].max()}")
print(f"     HourOfDay range:       {df['HourOfDay'].min()} — {df['HourOfDay'].max()}")
print(f"     EventsPerMinute range: {min(events_per_min)} — {max(events_per_min)}")
print()


# ─────────────────────────────────────────────────────────────────────
# 3. INJECT SYNTHETIC THREAT PATTERNS
# ─────────────────────────────────────────────────────────────────────
print("  💉 Injecting synthetic threat patterns...\n")

synthetic_threats = []
threat_templates = [
    # EventID, HourOfDay (late night), EventsPerMinute (burst)
    (1102, 3, 15),   # Audit log cleared at 3 AM, high burst
    (4720, 2, 12),   # Account created at 2 AM, burst
    (4625, 4, 45),   # Brute force at 4 AM, extreme burst
    (9999, 1, 8),    # Suspicious process at 1 AM
    (0,    3, 20),   # Kernel event at 3 AM, burst
    (8000, 2, 10),   # Registry persistence at 2 AM
    (8001, 3, 5),    # Security bypass at 3 AM
]

for eid, hour, epm in threat_templates:
    for _ in range(50):  # 50 copies of each pattern
        synthetic_threats.append({
            'EventID': eid,
            'HourOfDay': hour + random.randint(-1, 1),  # Slight variation
            'EventsPerMinute': epm + random.randint(-2, 5),
        })

synthetic_df = pd.DataFrame(synthetic_threats)

# Combine real features + synthetic threats
feature_cols = ['EventID', 'HourOfDay', 'EventsPerMinute']
X_real = df[feature_cols].copy()
X = pd.concat([X_real, synthetic_df[feature_cols]], ignore_index=True)

print(f"  📈 Training set: {len(X)} rows ({len(X_real)} real + {len(synthetic_df)} synthetic)\n")


# ─────────────────────────────────────────────────────────────────────
# 4. TRAIN ISOLATION FOREST
# ─────────────────────────────────────────────────────────────────────
print("  🧠 Training Isolation Forest (v2 — Behavioral)...")

model = IsolationForest(
    n_estimators=300,
    contamination=0.02,
    max_samples='auto',
    random_state=42,
    n_jobs=-1,
)

model.fit(X.values)

# Quick self-test
predictions = model.predict(X.values)
n_anomalies = (predictions == -1).sum()
n_normal = (predictions == 1).sum()

print(f"\n  📊 Self-Test Results:")
print(f"     Normal:    {n_normal}")
print(f"     Anomalies: {n_anomalies}")
print(f"     Anomaly %: {n_anomalies / len(predictions) * 100:.1f}%")


# ─────────────────────────────────────────────────────────────────────
# 5. SAVE MODEL
# ─────────────────────────────────────────────────────────────────────
models_dir = os.path.join(SCRIPT_DIR, "models")
os.makedirs(models_dir, exist_ok=True)
model_path = os.path.join(models_dir, "forensic_alarm_v2.pkl")
joblib.dump(model, model_path)

print(f"\n{'═' * 50}")
print(f"  ✅ SUCCESS: forensic_alarm_v2.pkl saved")
print(f"  📁 Path: {model_path}")
print(f"  🔢 Features: EventID, HourOfDay, EventsPerMinute")
print(f"{'═' * 50}")