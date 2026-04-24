import pandas as pd
import random
from datetime import datetime, timedelta

def generate_mock_registry():
    data = []
    start_time = datetime.now() - timedelta(days=1)
    
    # 1. Generate 990 Normal Registry Entries
    normal_keys = [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation",
        "HKCU\\Control Panel\\Desktop\\Wallpaper",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Office365"
    ]
    
    for i in range(990):
        data.append({
            "Date and Time": (start_time + timedelta(seconds=i*60)).strftime('%Y-%m-%d %H:%M:%S'),
            "Event ID": 7000, # Synthetic ID for 'Normal Registry State'
            "Task Category": f"Registry Value Read: {random.choice(normal_keys)}",
            "LogSource": "REGISTRY",
            "Keywords": "None"
        })

    # 2. Generate 10 Malicious/High-Interest Entries
    malicious_threats = [
        {"ID": 8000, "Task": "Registry Persistence: 'backdoor.exe' found in HKLM\\...\\Run"},
        {"ID": 8000, "Task": "Registry Persistence: 'powershell_hidden.bat' found in HKCU\\...\\RunOnce"},
        {"ID": 9000, "Task": "Hardware History: USB Device 'Kingston DataTraveler' Serial: 00123AB connected"},
        {"ID": 9000, "Task": "Hardware History: External Disk 'WD_Elements' detected"},
        {"ID": 8001, "Task": "Security Bypass: Windows Defender 'DisableAntiSpyware' set to 1"},
        {"ID": 8001, "Task": "Security Bypass: UAC Remote Restrictions disabled (LocalAccountTokenFilterPolicy)"}
    ]
    
    for _ in range(10):
        threat = random.choice(malicious_threats)
        data.append({
            "Date and Time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "Event ID": threat["ID"],
            "Task Category": threat["Task"],
            "LogSource": "REGISTRY",
            "Keywords": "Alert"
        })

    df = pd.DataFrame(data)
    df.to_csv("registry_samples.csv", index=False)
    print("✅ Created registry_samples.csv with 1,000 entries.")

generate_mock_registry()