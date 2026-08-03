"""Train the behavioural anomaly model.

    cd src && python isolation_model.py

Writes models/forensic_alarm_v2.pkl, which chatbot_app.py loads at startup and
never trains.

**Trains on real carved artifacts**, taken from src/cache/<sha256>/artifacts.pkl,
and falls back to the synthetic CSVs in src/data/ only when no carve exists.
The previous version trained on the synthetic CSVs alone, and the result was a
model that flagged **37% of a real image** — every one of them a "STATISTICAL
ANOMALY (Behavioral)", including 945 copies of an ordinary
`ControlSet002\\Control` registry key. That is not a bad threshold, it is
train/serve distribution skew: to a model that has only ever seen synthetic
event logs, a real registry hive is entirely anomalous.

Features come from `forensics.ml.compute_features` — imported, not
reimplemented. Two independent copies of that arithmetic is how the last skew
got in (a 50-row lookback at inference against 100 in training), and it is not
detectable by reading either file on its own.

There is deliberately **no synthetic threat injection** any more. It used to add
50 copies each of seven "threat" patterns to the training set, intending to
teach the model to catch them. An Isolation Forest learns where the data is
*dense* and calls the sparse parts anomalous, so 50 tight copies of a pattern
teach it that the pattern is normal — the opposite of the intent. Those Event
IDs are covered deterministically by HEURISTIC_THREAT_IDS, which is the right
mechanism for "this ID is always worth surfacing".
"""

import glob
import os
import sys

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from forensics.ml import FEATURE_COLUMNS, compute_features  # noqa: E402

# Share of training rows the model is told to treat as outliers. This is the
# flag rate on data that looks like the training set, so it is the dial for
# "how much does an examiner have to read". 2% of 80k is still 1,600 rows.
CONTAMINATION = float(os.getenv("FORENSIC_CONTAMINATION", "0.02"))


def load_real_carves():
    """Every cached carve on this machine, concatenated."""
    frames = []
    pattern = os.path.join(SCRIPT_DIR, "cache", "*", "artifacts.pkl")
    for path in sorted(glob.glob(pattern)):
        try:
            df = pd.read_pickle(path)
        except Exception as e:
            print(f"  [skip] {path}: {e}")
            continue
        if "Date and Time" not in df.columns or "Event ID" not in df.columns:
            print(f"  [skip] {path}: not a carved artifact frame")
            continue
        print(f"  [carve] {os.path.basename(os.path.dirname(path))[:16]}… "
              f"{len(df):,} rows")
        frames.append(df)
    return frames


def load_synthetic_csvs():
    frames = []
    data_dir = os.path.join(SCRIPT_DIR, "data")
    for csv_file in sorted(os.listdir(data_dir)):
        if not csv_file.endswith(".csv"):
            continue
        df = pd.read_csv(os.path.join(data_dir, csv_file), low_memory=False)
        df.columns = df.columns.str.strip()
        print(f"  [csv] {csv_file}: {len(df):,} rows")
        frames.append(df)
    return frames


def main():
    print("Loading training data...")
    frames = load_real_carves()
    source = "real carved artifacts"

    if not frames:
        print("\n  [WARN] No carved images found under src/cache/.")
        print("  [WARN] Falling back to the synthetic CSVs in src/data/.")
        print("  [WARN] A model trained on these flagged 37% of a real image —")
        print("  [WARN] carve a real image first if you have one.")
        frames = load_synthetic_csvs()
        source = "synthetic CSVs (NOT representative — see the warning above)"

    if not frames:
        print("No training data found in src/cache/ or src/data/.")
        return 1

    df = pd.concat(frames, ignore_index=True)
    print(f"\n{len(df):,} rows from {len(frames)} source(s): {source}\n")

    print("Engineering features (shared with inference)...")
    df = compute_features(df)
    X = df[FEATURE_COLUMNS]

    for col in FEATURE_COLUMNS:
        s = X[col]
        print(f"  {col:<16} min {s.min():>8,.0f}  median {s.median():>8,.0f}  "
              f"max {s.max():>10,.0f}  distinct {s.nunique():>7,}")

    print(f"\nTraining Isolation Forest (contamination={CONTAMINATION})...")
    model = IsolationForest(
        n_estimators=300,
        contamination=CONTAMINATION,
        max_samples='auto',
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X.values)

    predictions = model.predict(X.values)
    n_anomalies = int((predictions == -1).sum())
    print(f"\n  flagged on its own training data: {n_anomalies:,} / "
          f"{len(predictions):,} ({n_anomalies / len(predictions) * 100:.1f}%)")
    print("  (should land near the contamination rate; far above it means the "
          "training data does not look like what the app will score)")

    models_dir = os.path.join(SCRIPT_DIR, "models")
    os.makedirs(models_dir, exist_ok=True)
    model_path = os.path.join(models_dir, "forensic_alarm_v2.pkl")
    joblib.dump(model, model_path)
    print(f"\nSaved {model_path}")
    print(f"Features: {', '.join(FEATURE_COLUMNS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
