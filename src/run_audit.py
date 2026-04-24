import joblib
import pandas as pd
from sklearn.metrics import classification_report

# Load Model and Mapping
model = joblib.load("forensic_alarm.pkl")
source_map = joblib.load("source_mapping.pkl")
inv_map = {v: k for k, v in source_map.items()}

# Load Test Data
test_df = pd.read_csv("validation_test.csv")

# Sync Source Codes
# If LogSource text is missing, assume SECURITY (usually code 0)
if 'Source_Code' not in test_df.columns:
    test_df['Source_Code'] = test_df.get('LogSource', 'SECURITY').map(inv_map).fillna(0)

# Predict
X_test = test_df[['EventID', 'Source_Code']].values
test_df['AI_Guess'] = model.predict(X_test)

# Report
print("\n--- ML PROBLEM SOLVED: FINAL AUDIT ---")
print(classification_report(test_df['Ground_Truth'], test_df['AI_Guess'], target_names=['Anomaly', 'Normal']))

caught = len(test_df[(test_df['Ground_Truth'] == -1) & (test_df['AI_Guess'] == -1)])
print(f"Final Detection: {caught}/{len(test_df[test_df['Ground_Truth']==-1])} caught.")