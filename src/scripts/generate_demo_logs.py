import pandas as pd
from datetime import datetime, timedelta
import random

# Configuration
num_logs = 100
logs = []
start_time = datetime.now()

# Normal Activities - Using 'SECURITY' to match training expectations
normal_tasks = ["User Logoff", "Network Success", "Time Sync", "Service Manager"]

for i in range(95):
    logs.append({
        "Date and Time": (start_time + timedelta(minutes=i)).strftime('%Y-%m-%d %H:%M:%S'),
        "Event ID": "4624",
        "Task Category": random.choice(normal_tasks),
        "LogSource": "SECURITY", # Fixed: Matches training data patterns
        "Keywords": "None"
    })

# The 5 'Smoking Gun' Threats
threats = [
    {"ID": "1102", "Source": "SECURITY", "Task": "The audit log was cleared."},
    {"ID": "4720", "Source": "SECURITY", "Task": "A user account 'Hacker_Admin' was created."},
    {"ID": "9999", "Source": "APPLICATION", "Task": "Process Name: C:\\Program Files\\Oracle\\VirtualBox\\VirtualBox.exe started."},
    {"ID": "4625", "Source": "SECURITY", "Task": "An account failed to log on (Brute force attempt detected)."},
    {"ID": "0000", "Source": "SYSTEM", "Task": "Kernel-Power: Critical thermal shutdown event."}
]

for t in threats:
    logs.append({
        "Date and Time": (start_time + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'),
        "Event ID": t["ID"],
        "Task Category": t["Task"],
        "LogSource": t["Source"],
        "Keywords": "Alert"
    })

df = pd.DataFrame(logs)
df.to_csv("demo_logs.csv", index=False)
print("✅ demo_logs.csv created with stabilized labels.")