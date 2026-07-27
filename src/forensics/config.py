"""Shared configuration, paths, and constants."""

import os
from dotenv import load_dotenv

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))

CACHE_DIR = os.path.join(SCRIPT_DIR, "cache")
MODELS_DIR = os.path.join(SCRIPT_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "forensic_alarm_v2.pkl")

debug_extract = True

HEURISTIC_THREAT_IDS = {
    1102: "Audit Log Cleared",
    4720: "User Account Created",
    4625: "Failed Logon (Brute Force)",
    9999: "Suspicious Process Execution",
    0:    "Kernel Critical Event",
    8000: "Registry Persistence (Run/RunOnce)",
    8001: "Security Bypass (Defender/UAC Disabled)",
}
