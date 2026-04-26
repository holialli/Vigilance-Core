"""
═══════════════════════════════════════════════════════════════════════════
  FORENSIC IMAGE ANALYSIS ENGINE v3.1  (PATCHED)
  ────────────────────────────────────
  Architecture:  pytsk3 (SleuthKit) · python-evtx · python-registry
                 Isolation Forest (Behavioral) · FAISS · Gemini RAG
  ────────────────────────────────────
  Input:   Raw disk image (.dd / .E01)
  Output:  LLM-explained forensic evidence with anomaly classification

  PATCH NOTES v3.1:
    FIX-1  get_user_roots()             — deduplicate; verify entries are dirs
    FIX-2  heuristic_discover_files()   — dotted-dir support; safe meta check
    FIX-3  extract_browser_history()    — Firefox hashed-profile descent
    FIX-4  extract_recent_documents()   — dir-type guard; loop no longer aborts
    FIX-5  extract_all_ntuser()         — dir-type guard + cross-root dedup
    FIX-6  extract_communication_artifacts() — wider depth; all roots searched
    FIX-7  extract_srum_data()          — isolated task; 7 case-variant probes
    FIX-8  extract_execution_history()  — guard against None current_audit_df
    FIX-9  carve_evidence_from_image()  — SRUM/EXECUTION tasks isolated
═══════════════════════════════════════════════════════════════════════════
"""

import gradio as gr
import pandas as pd
import joblib
import numpy as np
import faiss
import re
import os
import hashlib
import tempfile
import threading
import traceback
from datetime import datetime, timedelta, timezone
from io import BytesIO
from dotenv import load_dotenv
import concurrent.futures
import json
import sqlite3
from collections import Counter

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: GLOBAL STATE
# ═══════════════════════════════════════════════════════════════════════════

current_audit_df = None
faiss_index = None
ai_model = None
image_hash_sha256 = None
artifact_counts = {}
ml_alarm = None
cached_system_facts = None
debug_extract = True

investigator_name = "Unknown Examiner"
case_id = "CASE-2026-001"
case_notes = ""
session_log = []
db_conn = None

MODEL_PATH = os.path.join(SCRIPT_DIR, "models", "forensic_alarm_v2.pkl")
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"[ERROR] ML model not found at '{MODEL_PATH}'. "
        f"Run 'python isolation_model.py' first to train it."
    )
ml_alarm = joblib.load(MODEL_PATH)
print(f"  [OK] Loaded ML model: {MODEL_PATH}")

def init_correlation_db():
    global db_conn
    db_conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = db_conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            artifact_type TEXT,
            user_name TEXT,
            target_path TEXT,
            source_file TEXT,
            description TEXT
        )
    """)
    db_conn.commit()
    print("  [OK] Correlation database initialized.")

init_correlation_db()

HEURISTIC_THREAT_IDS = {
    1102: "Audit Log Cleared",
    4720: "User Account Created",
    4625: "Failed Logon (Brute Force)",
    9999: "Suspicious Process Execution",
    0:    "Kernel Critical Event",
    8000: "Registry Persistence (Run/RunOnce)",
    8001: "Security Bypass (Defender/UAC Disabled)",
}

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL_ID = "gemini-2.0-flash"
if not GEMINI_API_KEY:
    raise RuntimeError(
        "[ERROR] GEMINI_API_KEY not set. Create a .env file with your key."
    )
from google import genai
gemini_client = genai.Client(api_key=GEMINI_API_KEY)
print("  [OK] Gemini LLM configured (Modern SDK).")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
groq_client = None
if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("  [OK] Groq LLM configured (Fallback ready).")
    except ImportError:
        print("  [WARN] Groq key found but 'groq' package missing. Run: pip install groq")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: FORENSIC IMAGE PARSING
# ═══════════════════════════════════════════════════════════════════════════

import time

def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    for attempt in range(5):
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except PermissionError:
            if attempt < 4:
                time.sleep(1)
            else:
                return "HASH_FAILED_PERMISSION_DENIED"
        except Exception:
            return "HASH_FAILED_ERROR"


def parse_evtx_file(evtx_data):
    import Evtx.Evtx as evtx
    import xml.etree.ElementTree as ET

    records = []
    with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
        tmp.write(evtx_data)
        tmp_path = tmp.name

    try:
        with evtx.Evtx(tmp_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

                    system = root.find('ns:System', ns)
                    event_id_el = system.find('ns:EventID', ns) if system is not None else None
                    time_el = system.find('ns:TimeCreated', ns) if system is not None else None
                    channel_el = system.find('ns:Channel', ns) if system is not None else None

                    event_id = event_id_el.text if event_id_el is not None else '0'
                    time_created = time_el.get('SystemTime', 'N/A') if time_el is not None else 'N/A'
                    channel = channel_el.text if channel_el is not None else 'Unknown'

                    event_data = root.find('ns:EventData', ns)
                    task_desc = ""
                    if event_data is not None:
                        data_items = event_data.findall('ns:Data', ns)
                        task_desc = " | ".join(
                            f"{d.get('Name', '')}: {d.text or ''}" for d in data_items[:5]
                        )
                    if not task_desc:
                        task_desc = f"Event {event_id} from {channel}"

                    records.append({
                        'Date and Time': time_created[:19].replace('T', ' ') if time_created != 'N/A' else 'N/A',
                        'Event ID': str(event_id),
                        'Task Category': task_desc,
                        'LogSource': 'SECURITY',
                        'Keywords': 'None',
                        'ArtifactType': 'EVTX',
                    })
                except Exception:
                    continue
    except Exception as e:
        print(f"   EVTX parse error: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return pd.DataFrame(records)


def parse_registry_hive(reg_data, hive_name="SYSTEM"):
    from Registry import Registry as reg_lib

    records = []
    with tempfile.NamedTemporaryFile(suffix=".hive", delete=False) as tmp:
        tmp.write(reg_data)
        tmp_path = tmp.name

    FORENSIC_KEYS = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows NT\\CurrentVersion",
        "ControlSet001\\Services",
        "ControlSet001\\Control\\ComputerName",
        "ControlSet001\\Enum\\USBSTOR",
        "ControlSet001\\Enum\\USB",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        "Software\\Microsoft\\Windows Defender",
    ]

    def walk_key(key, depth=0, max_depth=6):
        if depth > max_depth:
            return
        try:
            key_path = key.path()
            timestamp = key.timestamp()
            ts_str = timestamp.strftime('%Y-%m-%d %H:%M:%S') if timestamp else 'N/A'

            is_interesting = any(fk.lower() in key_path.lower() for fk in FORENSIC_KEYS)

            if "run" in key_path.lower() and ("currentversion\\run" in key_path.lower()):
                event_id = 8000
            elif "defender" in key_path.lower() or "disableantispyware" in key_path.lower():
                event_id = 8001
            elif "usbstor" in key_path.lower() or "enum\\usb" in key_path.lower():
                event_id = 9000
            else:
                event_id = 7000

            for value in key.values():
                try:
                    val_name = value.name()
                    val_data = str(value.value())
                    display_data = val_data[:300] + ("..." if len(val_data) > 300 else "")
                    task_desc = f"Registry [{hive_name}] {key_path}\\{val_name} = {display_data}"

                    records.append({
                        'Date and Time': ts_str,
                        'Event ID': str(event_id),
                        'Task Category': task_desc,
                        'LogSource': 'REGISTRY',
                        'Keywords': 'Alert' if is_interesting else 'None',
                        'ArtifactType': 'REGISTRY',
                        '_full_val': val_data
                    })
                except Exception:
                    continue

            for subkey in key.subkeys():
                walk_key(subkey, depth + 1, max_depth)
        except Exception:
            pass

    try:
        registry = reg_lib.Registry(tmp_path)
        walk_key(registry.root())
    except Exception as e:
        print(f"   Registry parse error ({hive_name}): {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return pd.DataFrame(records)


try:
    import pytsk3
    class EWFImgInfo(pytsk3.Img_Info):
        def __init__(self, ewf_handle):
            self._ewf_handle = ewf_handle
            super(EWFImgInfo, self).__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def close(self):
            self._ewf_handle.close()

        def read(self, offset, size):
            self._ewf_handle.seek(offset)
            return self._ewf_handle.read(size)

        def get_size(self):
            return self._ewf_handle.get_media_size()
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════
# FIX-1: get_user_roots — deduplicated + directory-verified
# ═══════════════════════════════════════════════════════════════════════════

def get_user_roots(fs):
    """
    Return de-duplicated user-profile base paths that actually exist as
    directories in the mounted filesystem.
    """
    seen_lower = set()
    roots = []

    candidates = [
        "/Users", "/USERS",
        "/Documents and Settings", "/DOCUMENTS AND SETTINGS",
    ]
    for c in candidates:
        c_lower = c.lower()
        if c_lower in seen_lower:
            continue
        try:
            d = fs.open_dir(c)
            if d is not None:
                roots.append(c)
                seen_lower.add(c_lower)
        except Exception:
            pass

    # Case-insensitive sweep of root directory
    try:
        root_dir = fs.open_dir("/")
        for entry in root_dir:
            try:
                ntype = entry.info.name.type
                meta_type = entry.info.meta.type if entry.info.meta else None
                is_dir = (ntype == 2) or (meta_type == 2)
                if not is_dir:
                    continue
                name = entry.info.name.name.decode('utf-8', errors='ignore')
                if name.lower() in ('users', 'documents and settings'):
                    key = f"/{name}".lower()
                    if key not in seen_lower:
                        roots.append(f"/{name}")
                        seen_lower.add(key)
            except Exception:
                continue
    except Exception:
        pass

    return roots


# ═══════════════════════════════════════════════════════════════════════════
# FIX-2: heuristic_discover_files — dotted-dir support + safe meta check
# ═══════════════════════════════════════════════════════════════════════════

_SKIP_DIRS_LOWER = {
    'winsxs', 'servicing', 'driverstore',
    '$recycle.bin', 'recycled', 'recycler',
    'windows.old',
}


def heuristic_discover_files(fs, target_patterns, start_path="/",
                              max_depth=6, depth=0):
    """
    Recursively search for files/dirs matching target_patterns.
    Dotted directory names (e.g. Firefox hashed profiles) are now traversed.
    """
    compiled = [re.compile(p, re.IGNORECASE) for p in target_patterns]
    found = []
    _skip_names = {'.', '..', '$orphanfiles'}

    def _walk(path, d):
        if d > max_depth:
            return
        try:
            directory = fs.open_dir(path)
            if directory is None:
                return
        except Exception:
            return

        for entry in directory:
            try:
                raw_name = entry.info.name.name
                name = (raw_name.decode('utf-8', errors='ignore')
                        if isinstance(raw_name, bytes) else raw_name)
                if name.lower() in _skip_names:
                    continue

                full_path = f"{path}/{name}" if path != "/" else f"/{name}"

                if any(p.search(name) for p in compiled):
                    found.append(full_path)

                ntype     = entry.info.name.type if entry.info.name else 0
                meta_type = (entry.info.meta.type
                             if entry.info.meta is not None else 0)
                is_dir = (ntype == 2) or (meta_type == 2)

                # Fallback for entries where type field is unreliable
                if not is_dir and ntype not in (1, 2):
                    try:
                        fs.open_dir(full_path)
                        is_dir = True
                    except Exception:
                        is_dir = False

                if is_dir and name.lower() not in _SKIP_DIRS_LOWER:
                    _walk(full_path, d + 1)
            except Exception:
                continue

    _walk(start_path, depth)
    return found


def extract_all_evtx(fs):
    all_evtx_frames = []
    evtx_dir_paths = [
        "/Windows/System32/winevt/Logs",
        "/Windows/System32/winevt/logs",
    ]
    for evtx_dir_path in evtx_dir_paths:
        try:
            evtx_dir = fs.open_dir(evtx_dir_path)
        except Exception:
            continue

        if evtx_dir is None:
            continue

        for entry in evtx_dir:
            try:
                fname = entry.info.name.name.decode('utf-8', errors='ignore')
                if not fname.lower().endswith('.evtx'):
                    continue
                fpath = f"{evtx_dir_path}/{fname}"
                f_obj = fs.open(fpath)
                if f_obj.info.meta.size < 1024:
                    continue
                evtx_data = f_obj.read_random(0, f_obj.info.meta.size)
                evtx_df = parse_evtx_file(evtx_data)
                if not evtx_df.empty:
                    channel_name = fname.replace('.evtx', '').replace('%4', '/').upper()
                    evtx_df['LogSource'] = channel_name
                    all_evtx_frames.append(evtx_df)
                    print(f"   Extracted {len(evtx_df)} events from {fname}")
            except Exception:
                continue
        break

    if all_evtx_frames:
        return pd.concat(all_evtx_frames, ignore_index=True)
    return pd.DataFrame()


def extract_sam_hive(fs):
    from Registry import Registry as reg_lib

    sam_paths = [
        "/Windows/System32/config/SAM",
        "/Windows/System32/config/sam",
    ]
    records = []

    for sam_path in sam_paths:
        try:
            f_obj = fs.open(sam_path)
            sam_data = f_obj.read_random(0, f_obj.info.meta.size)
        except Exception:
            continue

        with tempfile.NamedTemporaryFile(suffix=".hive", delete=False) as tmp:
            tmp.write(sam_data)
            tmp_path = tmp.name

        try:
            registry = reg_lib.Registry(tmp_path)
            try:
                users_key = registry.open("SAM\\Domains\\Account\\Users")
                names_key = users_key.subkey("Names")
                rid_to_name = {}
                for name_subkey in names_key.subkeys():
                    try:
                        vals = [v for v in name_subkey.values()]
                        if vals:
                            rid_to_name[vals[0].value_type()] = name_subkey.name()
                    except:
                        pass

                for subkey in users_key.subkeys():
                    if subkey.name() == "Names":
                        continue
                    try:
                        rid = int(subkey.name(), 16)
                    except:
                        continue
                    username = rid_to_name.get(rid, f"Unknown_RID_{subkey.name()}")

                    ts = subkey.timestamp()
                    ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A'

                    desc = f"SAM User Account: {username} (RID: {rid})"
                    try:
                        f_val = subkey.value("F").value()
                        import struct
                        last_logon_ft = struct.unpack('<Q', f_val[8:16])[0]
                        login_count = struct.unpack('<H', f_val[64:66])[0]

                        def ft_to_str(ft):
                            if ft == 0 or ft == 0x7FFFFFFFFFFFFFFF:
                                return "Never"
                            try:
                                return (datetime(1601, 1, 1, tzinfo=timezone.utc)
                                        + timedelta(microseconds=ft // 10)).strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                return "N/A"

                        ll_str = ft_to_str(last_logon_ft)
                        desc = (f"SAM User Account: {username} (RID: {rid}) | "
                                f"Login Count: {login_count} | Last Logon: {ll_str}")
                    except Exception:
                        pass

                    records.append({
                        'Date and Time': ts_str,
                        'Event ID': '9100',
                        'Task Category': desc,
                        'LogSource': 'SAM',
                        'Keywords': 'Alert',
                        'ArtifactType': 'SAM',
                    })
                print(f"  [USER] Extracted {len(records)} user accounts from SAM hive")
            except Exception as e:
                print(f"  [WARN] Could not parse SAM user names: {e}")
        except Exception as e:
            print(f"   SAM hive parse error: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        break

    return pd.DataFrame(records)


def extract_software_hive(fs):
    from Registry import Registry as reg_lib

    sw_paths = [
        "/Windows/System32/config/SOFTWARE",
        "/Windows/System32/config/software",
    ]
    records = []

    for sw_path in sw_paths:
        try:
            f_obj = fs.open(sw_path)
            sw_data = f_obj.read_random(0, f_obj.info.meta.size)
        except Exception:
            continue

        with tempfile.NamedTemporaryFile(suffix=".hive", delete=False) as tmp:
            tmp.write(sw_data)
            tmp_path = tmp.name

        try:
            registry = reg_lib.Registry(tmp_path)

            uninstall_paths = [
                "Microsoft\\Windows\\CurrentVersion\\Uninstall",
                "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            ]
            for upath in uninstall_paths:
                try:
                    uninstall_key = registry.open(upath)
                    for subkey in uninstall_key.subkeys():
                        display_name = ""
                        display_version = ""
                        publisher = ""
                        install_date = ""
                        for val in subkey.values():
                            vn = val.name().lower()
                            if vn == "displayname":
                                display_name = str(val.value())[:200]
                            elif vn == "displayversion":
                                display_version = str(val.value())[:50]
                            elif vn == "publisher":
                                publisher = str(val.value())[:100]
                            elif vn == "installdate":
                                install_date = str(val.value())[:20]
                        if display_name:
                            ts = subkey.timestamp()
                            ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A'
                            records.append({
                                'Date and Time': ts_str,
                                'Event ID': '9200',
                                'Task Category': (
                                    f"Installed Program: {display_name} v{display_version} "
                                    f"by {publisher} (Installed: {install_date or ts_str})"
                                ),
                                'LogSource': 'SOFTWARE',
                                'Keywords': 'None',
                                'ArtifactType': 'SOFTWARE',
                            })
                except Exception:
                    pass

            try:
                nt_key = registry.open("Microsoft\\Windows NT\\CurrentVersion")
                os_info = {}
                for val in nt_key.values():
                    vn = val.name()
                    if vn in ['ProductName', 'BuildLab', 'RegisteredOwner',
                              'InstallDate', 'CurrentBuild', 'EditionID']:
                        os_info[vn] = str(val.value())[:200]
                if os_info:
                    ts = nt_key.timestamp()
                    ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A'
                    info_str = " | ".join([f"{k}: {v}" for k, v in os_info.items()])
                    records.append({
                        'Date and Time': ts_str,
                        'Event ID': '9201',
                        'Task Category': f"OS Information: {info_str}",
                        'LogSource': 'SOFTWARE',
                        'Keywords': 'Alert',
                        'ArtifactType': 'SOFTWARE',
                        '_os_facts': os_info
                    })
            except Exception:
                pass

            print(f"   Extracted {len(records)} entries from SOFTWARE hive")
        except Exception as e:
            print(f"   SOFTWARE hive parse error: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        break

    return pd.DataFrame(records)


def extract_usb_devices(fs):
    from Registry import Registry as reg_lib
    records = []

    system_paths = ["/Windows/System32/config/SYSTEM", "/Windows/System32/config/system"]
    reg_data = None
    for p in system_paths:
        try:
            f_obj = fs.open(p)
            reg_data = f_obj.read_random(0, f_obj.info.meta.size)
            break
        except:
            continue

    if not reg_data:
        return pd.DataFrame()

    with tempfile.NamedTemporaryFile(suffix=".hive", delete=False) as tmp:
        tmp.write(reg_data)
        tmp_path = tmp.name

    try:
        registry = reg_lib.Registry(tmp_path)
        try:
            usbstor_key = registry.open("ControlSet001\\Enum\\USBSTOR")
            for vendor_key in usbstor_key.subkeys():
                vendor_name = vendor_key.name()
                for serial_key in vendor_key.subkeys():
                    serial = serial_key.name()
                    ts = serial_key.timestamp()
                    ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A'

                    friendly_name = "Unknown Device"
                    try:
                        friendly_name = str(serial_key.value("FriendlyName").value())
                    except:
                        pass

                    records.append({
                        'Date and Time': ts_str,
                        'Event ID': '9000',
                        'Task Category': (
                            f"USB Device: {friendly_name} "
                            f"(Vendor: {vendor_name}, Serial: {serial})"
                        ),
                        'LogSource': 'USB_HISTORY',
                        'Keywords': 'Alert',
                        'ArtifactType': 'USB',
                    })
        except:
            pass

        try:
            usb_key = registry.open("ControlSet001\\Enum\\USB")
            for vid_key in usb_key.subkeys():
                for serial_key in vid_key.subkeys():
                    try:
                        dev_desc = "Unknown USB Device"
                        for val_name in ["DeviceDesc", "FriendlyName"]:
                            try:
                                dev_desc = str(serial_key.value(val_name).value()).split(';')[-1]
                                break
                            except:
                                pass

                        ts = serial_key.timestamp()
                        ts_str = ts.strftime('%Y-%m-%d %H:%M:%S UTC') if ts else 'N/A'

                        records.append({
                            'Date and Time': ts_str,
                            'Event ID': '9001',
                            'Task Category': (
                                f"USB Device Attached: {dev_desc} "
                                f"(ID: {vid_key.name()}\\{serial_key.name()})"
                            ),
                            'LogSource': 'USB_HISTORY',
                            'Keywords': 'None',
                            'ArtifactType': 'USB',
                        })
                    except:
                        pass
        except:
            pass

    except Exception as e:
        print(f"   USB Extraction error: {e}")
    finally:
        os.unlink(tmp_path)

    return pd.DataFrame(records)


# ═══════════════════════════════════════════════════════════════════════════
# FIX-5: extract_all_ntuser — dir-type guard + cross-root deduplication
# ═══════════════════════════════════════════════════════════════════════════

def extract_all_ntuser(fs):
    """Extract ALL NTUSER.DAT hive files from all user profiles."""
    all_ntuser_frames = []
    seen_paths = set()
    _skip_names = {'all users', 'default', 'default user', 'public', '.', '..'}

    try:
        roots = get_user_roots(fs)
        if not roots:
            return pd.DataFrame()

        for base_root in roots:
            try:
                users_dir = fs.open_dir(base_root)
            except Exception:
                continue

            for entry in users_dir:
                try:
                    raw = entry.info.name.name
                    name = (raw.decode('utf-8', errors='ignore')
                            if isinstance(raw, bytes) else raw)
                    if name.lower() in _skip_names:
                        continue

                    # FIX-5: verify it is a directory before proceeding
                    ntype = entry.info.name.type
                    meta_type = entry.info.meta.type if entry.info.meta else 0
                    is_dir = (ntype == 2) or (meta_type == 2)
                    if not is_dir:
                        try:
                            fs.open_dir(f"{base_root}/{name}")
                            is_dir = True
                        except Exception:
                            is_dir = False
                    if not is_dir:
                        continue

                    ntuser_path = f"{base_root}/{name}/NTUSER.DAT"
                    norm = ntuser_path.lower()
                    if norm in seen_paths:
                        continue
                    seen_paths.add(norm)

                    try:
                        f_obj = fs.open(ntuser_path)
                        reg_data = f_obj.read_random(0, f_obj.info.meta.size)
                        reg_df = parse_registry_hive(reg_data, f"NTUSER({name})")
                        if not reg_df.empty:
                            all_ntuser_frames.append(reg_df)
                            print(f"  [NTUSER] Parsed {len(reg_df)} entries for user '{name}'")
                    except Exception as e:
                        if debug_extract:
                            print(f"  [DEBUG] NTUSER.DAT not found for '{name}': {e}")
                        continue
                except Exception:
                    continue
    except Exception as e:
        print(f"  [DEBUG] NTUSER walk error: {e}")

    if all_ntuser_frames:
        return pd.concat(all_ntuser_frames, ignore_index=True)
    return pd.DataFrame()


def extract_user_activity(fs):
    records = []
    try:
        roots = get_user_roots(fs)
        if not roots:
            return pd.DataFrame(records)
        skip_names = {'all users', 'default', 'default user', 'public', '.', '..'}
        for base_root in roots:
            try:
                users_dir = fs.open_dir(base_root)
            except Exception:
                continue
            for entry in users_dir:
                name = entry.info.name.name.decode('utf-8', errors='ignore')
                if name.lower() in skip_names:
                    continue

                recent_path = f"{base_root}/{name}/AppData/Roaming/Microsoft/Windows/Recent"
                try:
                    recent_dir = fs.open_dir(recent_path)
                    if recent_dir is None:
                        continue
                    for lnk_entry in recent_dir:
                        try:
                            lname = lnk_entry.info.name.name.decode('utf-8', errors='ignore')
                            if not lname.lower().endswith('.lnk'):
                                continue
                            f_obj = fs.open(f"{recent_path}/{lname}")
                            data = f_obj.read_random(0, f_obj.info.meta.size)

                            target_path = "Unknown"
                            if b":\\" in data:
                                start = data.find(b":\\") - 1
                                end = data.find(b"\x00", start)
                                target_path = data[start:end].decode('utf-16le', errors='ignore')
                                if not target_path or ":" not in target_path:
                                    target_path = data[start:end].decode('utf-8', errors='ignore')

                            mtime = datetime.fromtimestamp(
                                lnk_entry.info.meta.mtime, timezone.utc
                            ).strftime('%Y-%m-%d %H:%M:%S')
                            records.append({
                                'Date and Time': mtime,
                                'Event ID': '9400',
                                'Task Category': (
                                    f"User Activity (LNK): {name} opened "
                                    f"{target_path} (LNK: {lname})"
                                ),
                                'LogSource': 'ACTIVITY',
                                'Keywords': 'None',
                                'ArtifactType': 'ACTIVITY',
                            })
                        except Exception:
                            continue
                except Exception:
                    pass

                jump_path = (f"{base_root}/{name}/AppData/Roaming/Microsoft/"
                             f"Windows/Recent/AutomaticDestinations")
                try:
                    jump_dir = fs.open_dir(jump_path)
                    if jump_dir is None:
                        continue
                    for j_entry in jump_dir:
                        try:
                            jname = j_entry.info.name.name.decode('utf-8', errors='ignore')
                            mtime = datetime.fromtimestamp(
                                j_entry.info.meta.mtime, timezone.utc
                            ).strftime('%Y-%m-%d %H:%M:%S')
                            records.append({
                                'Date and Time': mtime,
                                'Event ID': '9401',
                                'Task Category': (
                                    f"User Activity (JumpList): {name} "
                                    f"interacted with AppID {jname[:8]}..."
                                ),
                                'LogSource': 'ACTIVITY',
                                'Keywords': 'None',
                                'ArtifactType': 'ACTIVITY',
                            })
                        except Exception:
                            continue
                except Exception:
                    pass
    except Exception:
        pass
    return pd.DataFrame(records)


def extract_recycle_bin(fs):
    records = []
    print("  [CARVE] Scanning for Recycle Bin artifacts (Global Search)...")

    target_files = heuristic_discover_files(
        fs, [r'^\$I', r'^\$R', r'^INFO2$'], max_depth=10
    )
    if not target_files:
        recycle_dirs = heuristic_discover_files(
            fs, [r'^\$Recycle\.Bin$', r'^RECYCLER$', r'^RECYCLED$'], max_depth=4
        )
        for rdir in recycle_dirs:
            target_files.extend(
                heuristic_discover_files(
                    fs, [r'^\$I', r'^\$R', r'^INFO2$'],
                    start_path=rdir, max_depth=6
                )
            )
    if debug_extract:
        print(f"  [DEBUG] Recycle Bin hits: {len(target_files)}")

    for path in target_files:
        try:
            f_obj = fs.open(path)
            meta = f_obj.info.meta
            ts = datetime.fromtimestamp(meta.mtime, timezone.utc) if meta and meta.mtime else None
            ts_str = ts.strftime('%Y-%m-%d %H:%M:%S UTC') if ts else 'N/A'

            parts = path.split('/')
            context = parts[-2] if len(parts) > 2 else "Unknown"

            records.append({
                'Date and Time': ts_str,
                'Event ID': '9800',
                'Task Category': (
                    f"Recycle Bin: Found deleted artifact in "
                    f"{context} (Path: {path})"
                ),
                'LogSource': 'RECYCLE_BIN',
                'Keywords': 'Alert',
                'ArtifactType': 'RECYCLE',
            })
        except Exception as e:
            if debug_extract:
                print(f"  [DEBUG] Recycle Bin read error for {path}: {e}")
            continue
    return pd.DataFrame(records)


# ═══════════════════════════════════════════════════════════════════════════
# FIX-3: extract_browser_history — Firefox hashed-profile descent
# ═══════════════════════════════════════════════════════════════════════════

def extract_browser_history(fs):
    """
    Universal Browser Extractor.
    Firefox hashed profile directories are now explicitly descended.
    """
    records = []
    print("  [CARVE] Globally searching for Browser History & Bookmarks...")

    # 1. Generic discovery for Chrome/Edge artifacts
    generic_patterns = [r'^History$', r'^Bookmarks$', r'^Cookies$']
    found_paths = []
    roots = get_user_roots(fs)
    search_bases = roots if roots else ["/"]

    for root in search_bases:
        found_paths.extend(
            heuristic_discover_files(fs, generic_patterns,
                                     start_path=root, max_depth=14)
        )

    # 2. Firefox-specific: manually descend hashed profile dirs
    # Path: <root>/<user>/AppData/Roaming/Mozilla/Firefox/Profiles/<hash.name>/places.sqlite
    firefox_targets = []
    _skip = {'all users', 'default', 'default user', 'public', '.', '..'}

    for root in search_bases:
        try:
            users_dir = fs.open_dir(root)
            if users_dir is None:
                continue
        except Exception:
            continue

        for user_entry in users_dir:
            try:
                raw = user_entry.info.name.name
                uname = (raw.decode('utf-8', errors='ignore')
                         if isinstance(raw, bytes) else raw)
                if uname.lower() in _skip:
                    continue

                # Verify it's a directory
                ntype = user_entry.info.name.type
                meta_type = user_entry.info.meta.type if user_entry.info.meta else 0
                is_dir = (ntype == 2) or (meta_type == 2)
                if not is_dir:
                    try:
                        fs.open_dir(f"{root}/{uname}")
                        is_dir = True
                    except Exception:
                        is_dir = False
                if not is_dir:
                    continue

                # Try Vista+ and XP AppData layouts
                profiles_candidates = [
                    f"{root}/{uname}/AppData/Roaming/Mozilla/Firefox/Profiles",
                    f"{root}/{uname}/Application Data/Mozilla/Firefox/Profiles",
                ]
                for profiles_path in profiles_candidates:
                    try:
                        profiles_dir = fs.open_dir(profiles_path)
                        if profiles_dir is None:
                            continue
                    except Exception:
                        continue

                    # Each child of Profiles/ is a hashed profile dir
                    for prof_entry in profiles_dir:
                        try:
                            raw_p = prof_entry.info.name.name
                            pname = (raw_p.decode('utf-8', errors='ignore')
                                     if isinstance(raw_p, bytes) else raw_p)
                            if pname in ('.', '..'):
                                continue
                            prof_path = f"{profiles_path}/{pname}"
                            for fname in ('places.sqlite', 'cookies.sqlite'):
                                target = f"{prof_path}/{fname}"
                                try:
                                    fs.open(target)
                                    firefox_targets.append(target)
                                    print(f"  [FF] Found Firefox artifact: {target}")
                                except Exception:
                                    pass
                        except Exception:
                            continue
            except Exception:
                continue

    all_paths = list(dict.fromkeys(found_paths + firefox_targets))

    if debug_extract:
        preview = ", ".join(all_paths[:5]) if all_paths else "None"
        print(f"  [DEBUG] Browser targets found: {len(all_paths)} | Sample: {preview}")

    # 3. Parse each discovered artifact
    for path in all_paths:
        try:
            f_obj = fs.open(path)
            p_name = path.lower()

            user_context = "Unknown"
            for marker in ("/users/", "/documents and settings/"):
                if marker in path.lower():
                    idx = path.lower().index(marker) + len(marker)
                    user_context = path[idx:].split("/")[0]
                    break

            # A. SQLite History / Firefox places.sqlite
            if "history" in p_name or "places.sqlite" in p_name:
                data = f_obj.read_random(0, f_obj.info.meta.size)
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name
                try:
                    conn = sqlite3.connect(tmp_path)
                    cursor = conn.cursor()
                    if "places.sqlite" in p_name:
                        try:
                            cursor.execute(
                                "SELECT url, title, visit_date "
                                "FROM moz_places "
                                "JOIN moz_historyvisits "
                                "ON moz_places.id = moz_historyvisits.place_id "
                                "ORDER BY visit_date DESC LIMIT 200"
                            )
                            for url, title, vdate in cursor.fetchall():
                                dt = (datetime(1970, 1, 1, tzinfo=timezone.utc)
                                      + timedelta(microseconds=vdate or 0))
                                records.append({
                                    'Date and Time': dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                    'Event ID': '9600',
                                    'Task Category': f"Firefox History: {user_context} visited {url}",
                                    'LogSource': 'BROWSER',
                                    'Keywords': 'None',
                                    'ArtifactType': 'BROWSER',
                                })
                        except Exception as e:
                            print(f"  [WARN] Firefox history parse: {e}")
                        try:
                            cursor.execute(
                                "SELECT moz_places.url, moz_bookmarks.title, "
                                "moz_bookmarks.dateAdded "
                                "FROM moz_bookmarks "
                                "JOIN moz_places ON moz_bookmarks.fk = moz_places.id "
                                "WHERE moz_bookmarks.fk IS NOT NULL LIMIT 200"
                            )
                            for url, title, date_added in cursor.fetchall():
                                if date_added:
                                    dt = (datetime(1970, 1, 1, tzinfo=timezone.utc)
                                          + timedelta(microseconds=date_added))
                                    ts_str = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                                else:
                                    ts_str = 'N/A'
                                records.append({
                                    'Date and Time': ts_str,
                                    'Event ID': '9602',
                                    'Task Category': (
                                        f"Bookmark: {user_context} "
                                        f"saved '{title}' -> {url}"
                                    ),
                                    'LogSource': 'BROWSER',
                                    'Keywords': 'None',
                                    'ArtifactType': 'BROWSER',
                                })
                        except Exception as e:
                            print(f"  [WARN] Firefox bookmark parse: {e}")
                    else:
                        try:
                            cursor.execute(
                                "SELECT url, title, last_visit_time "
                                "FROM urls ORDER BY last_visit_time DESC LIMIT 200"
                            )
                            for url, title, lvt in cursor.fetchall():
                                dt = (datetime(1601, 1, 1, tzinfo=timezone.utc)
                                      + timedelta(microseconds=lvt or 0))
                                records.append({
                                    'Date and Time': dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                    'Event ID': '9600',
                                    'Task Category': (
                                        f"Browser History: {user_context} visited {url}"
                                    ),
                                    'LogSource': 'BROWSER',
                                    'Keywords': 'None',
                                    'ArtifactType': 'BROWSER',
                                })
                        except Exception as e:
                            print(f"  [WARN] Chrome/Edge history parse: {e}")
                    conn.close()
                finally:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass

            # B. JSON Bookmarks (Chrome/Edge)
            elif "bookmarks" in p_name and not p_name.endswith(".sqlite"):
                data = f_obj.read_random(0, f_obj.info.meta.size)
                try:
                    b_json = json.loads(data.decode('utf-8', errors='ignore'))

                    def walk_bm(node):
                        if isinstance(node, dict):
                            if node.get('type') == 'url':
                                records.append({
                                    'Date and Time': 'N/A',
                                    'Event ID': '9602',
                                    'Task Category': (
                                        f"Bookmark: {user_context} saved "
                                        f"'{node.get('name')}' -> {node.get('url')}"
                                    ),
                                    'LogSource': 'BROWSER',
                                    'Keywords': 'None',
                                    'ArtifactType': 'BROWSER',
                                })
                            for v in node.values():
                                walk_bm(v)
                        elif isinstance(node, list):
                            for item in node:
                                walk_bm(item)

                    walk_bm(b_json.get('roots', {}))
                except Exception as e:
                    print(f"  [WARN] Bookmarks JSON parse for {path}: {e}")

            # C. Cookies
            elif p_name.endswith("/cookies") or "cookies.sqlite" in p_name:
                data = f_obj.read_random(0, f_obj.info.meta.size)
                with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name
                try:
                    conn = sqlite3.connect(tmp_path)
                    cursor = conn.cursor()
                    if "cookies.sqlite" in p_name:
                        cursor.execute(
                            "SELECT host, name, lastAccessed "
                            "FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 200"
                        )
                        for host, name, last_access in cursor.fetchall():
                            dt = (datetime(1970, 1, 1, tzinfo=timezone.utc)
                                  + timedelta(microseconds=last_access or 0))
                            records.append({
                                'Date and Time': dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                'Event ID': '9603',
                                'Task Category': f"Cookie: {user_context} {host} -> {name}",
                                'LogSource': 'BROWSER',
                                'Keywords': 'None',
                                'ArtifactType': 'BROWSER',
                            })
                    else:
                        cursor.execute(
                            "SELECT host_key, name, last_access_utc "
                            "FROM cookies ORDER BY last_access_utc DESC LIMIT 200"
                        )
                        for host, name, last_access in cursor.fetchall():
                            dt = (datetime(1601, 1, 1, tzinfo=timezone.utc)
                                  + timedelta(microseconds=last_access or 0))
                            records.append({
                                'Date and Time': dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                'Event ID': '9603',
                                'Task Category': f"Cookie: {user_context} {host} -> {name}",
                                'LogSource': 'BROWSER',
                                'Keywords': 'None',
                                'ArtifactType': 'BROWSER',
                            })
                    conn.close()
                finally:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass

        except Exception as e:
            if debug_extract:
                print(f"  [DEBUG] Browser parse error for {path}: {e}")
            continue

    print(f"  [BROWSER] Extracted {len(records)} browser artifacts")
    return pd.DataFrame(records)


def walk_filesystem(fs, limit=150000, max_depth=14):
    records = []
    print("  [CARVE] Indexing Filesystem (Autopsy Mode)...")

    skip_dirs = {'winsxs', 'servicing', 'driverstore',
                 'system32', 'program files', 'program files (x86)'}

    def fast_walk(directory_path, depth=0):
        if len(records) >= limit or depth > max_depth:
            return
        try:
            dir_obj = fs.open_dir(directory_path)
            if dir_obj is None:
                return
            for entry in dir_obj:
                if len(records) >= limit:
                    return
                try:
                    name = entry.info.name.name.decode('utf-8', errors='ignore')
                    if name in ['.', '..']:
                        continue
                    fpath = (f"{directory_path}/{name}"
                             if directory_path != "/" else f"/{name}")

                    meta = entry.info.meta
                    ntype = entry.info.name.type
                    meta_type = meta.type if meta else None
                    is_file = (ntype == 1) or (meta_type == 1)
                    is_dir = (ntype == 2) or (meta_type == 2)
                    if not is_dir and ntype not in (1, 2):
                        try:
                            fs.open_dir(fpath)
                            is_dir = True
                        except Exception:
                            is_dir = False
                    ext = os.path.splitext(name)[1].lower() if is_file else ''
                    mtime = (datetime.fromtimestamp(meta.mtime, timezone.utc)
                             .strftime('%Y-%m-%d %H:%M:%S UTC')
                             if meta and meta.mtime else 'N/A')
                    size = meta.size if meta and meta.size else 0

                    if is_file or is_dir:
                        ftype = "Directory" if is_dir else "File"
                        records.append({
                            'Date and Time': mtime,
                            'Event ID': '9100',
                            'Task Category': (
                                f"{ftype} Discovery: {name} "
                                f"({ext.upper()}) at {fpath}"
                            ),
                            'LogSource': 'FILESYSTEM',
                            'Keywords': 'None',
                            'ArtifactType': 'FILESYSTEM',
                            '_filepath': fpath,
                            '_filename': name,
                            '_extension': ext,
                            '_size': size,
                            '_is_dir': is_dir,
                        })

                    if is_dir and depth < max_depth and name.lower() not in skip_dirs:
                        fast_walk(fpath, depth + 1)
                except Exception:
                    continue
        except Exception:
            pass

    for root in ["/Users", "/USERS",
                 "/Documents and Settings", "/DOCUMENTS AND SETTINGS"]:
        fast_walk(root)
    if len(records) < limit:
        fast_walk("/")

    print(f"  [OK] Indexed {len(records)} files/folders.")
    return pd.DataFrame(records)


# ═══════════════════════════════════════════════════════════════════════════
# FIX-6: extract_communication_artifacts — wider depth; all roots searched
# ═══════════════════════════════════════════════════════════════════════════

def extract_communication_artifacts(fs):
    """Discover email databases and communication artifacts."""
    records = []
    print("   Scanning for communication artifacts (expanded depth)...")

    email_patterns = [r'^.*\.(pst|ost|msg|eml|mbox)$']
    found_paths = []

    roots = get_user_roots(fs) or ["/"]
    for root in roots:
        found_paths.extend(
            heuristic_discover_files(
                fs, email_patterns, start_path=root, max_depth=14
            )
        )
    # Also scan root for unusual placements
    found_paths.extend(
        heuristic_discover_files(fs, email_patterns, start_path="/", max_depth=10)
    )
    # Deduplicate (normalise to lowercase key)
    seen = set()
    deduped = []
    for p in found_paths:
        k = p.lower()
        if k not in seen:
            seen.add(k)
            deduped.append(p)
    found_paths = deduped

    if debug_extract:
        preview = ", ".join(found_paths[:5]) if found_paths else "None"
        print(f"  [DEBUG] Communication targets found: {len(found_paths)} | Sample: {preview}")

    for path in found_paths:
        try:
            f_obj = fs.open(path)
            meta = f_obj.info.meta
            ext = os.path.splitext(path)[1].lower()
            mtime = (datetime.fromtimestamp(meta.mtime, timezone.utc)
                     .strftime('%Y-%m-%d %H:%M:%S')
                     if meta and meta.mtime else 'N/A')
            size = meta.size if meta and meta.size else 0
            records.append({
                'Date and Time': mtime,
                'Event ID': '9900',
                'Task Category': (
                    f"Communication File: Found {ext.upper()} archive "
                    f"at {path} (Size: {size:,} bytes)"
                ),
                'LogSource': 'COMMUNICATION',
                'Keywords': 'Alert',
                'ArtifactType': 'COMMUNICATION',
            })
        except Exception:
            continue

    print(f"  [COMM] Extracted {len(records)} communication artifacts")
    return pd.DataFrame(records)


def extract_usn_journal(fs):
    records = []
    try:
        usn_path = "/$Extend/$UsnJrnl"
        f_obj = fs.open(usn_path)
        size = f_obj.info.meta.size
        read_size = min(size, 2 * 1024 * 1024)
        data = f_obj.read_random(size - read_size, read_size)

        for match in re.finditer(br'[A-Za-z0-9._-]{5,}\.[a-zA-Z]{2,4}', data):
            try:
                fname = match.group().decode('utf-8', errors='ignore')
                records.append({
                    'Date and Time': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                    'Event ID': '9700',
                    'Task Category': (
                        f"USN Journal Activity: File modification detected for {fname}"
                    ),
                    'LogSource': 'USN',
                    'Keywords': 'None',
                    'ArtifactType': 'USN',
                })
                if len(records) > 200:
                    break
            except:
                continue
    except:
        pass
    return pd.DataFrame(records)


# ═══════════════════════════════════════════════════════════════════════════
# FIX-8: extract_execution_history — guard against None current_audit_df
# ═══════════════════════════════════════════════════════════════════════════

def extract_execution_history(fs):
    """
    ShimCache data is already captured by extract_system_artifact() under
    REGISTRY. current_audit_df is None at extraction time, so attempting
    to read it here would crash. Return empty; data is available via RAG.
    """
    print("  [EXEC] ShimCache captured via REGISTRY extraction; skipping re-extraction.")
    return pd.DataFrame()


# ═══════════════════════════════════════════════════════════════════════════
# FIX-7: extract_srum_data — isolated; 7 case-variant probes
# ═══════════════════════════════════════════════════════════════════════════

def extract_srum_data(fs):
    """SRUM database extractor with expanded case-variant path probing."""
    records = []

    srum_paths = [
        "/Windows/System32/sru/SRUDB.dat",
        "/Windows/System32/sru/srudb.dat",
        "/Windows/System32/SRU/SRUDB.DAT",
        "/Windows/System32/SRU/SRUDB.dat",
        "/WINDOWS/System32/sru/SRUDB.dat",
        "/WINDOWS/System32/SRU/SRUDB.DAT",
        "/windows/system32/sru/srudb.dat",
    ]

    for srum_path in srum_paths:
        try:
            f_obj = fs.open(srum_path)
            mtime = (datetime.fromtimestamp(f_obj.info.meta.mtime, timezone.utc)
                     .strftime('%Y-%m-%d %H:%M:%S'))
            size = f_obj.info.meta.size if f_obj.info.meta else 0
            records.append({
                'Date and Time': mtime,
                'Event ID': '9901',
                'Task Category': (
                    f"SRUM Database detected at {srum_path} "
                    f"(Size: {size:,} bytes). "
                    "Network and energy usage history available."
                ),
                'LogSource': 'SRUM',
                'Keywords': 'Alert',
                'ArtifactType': 'SRUM',
            })
            print(f"  [SRUM] Found SRUDB.dat at {srum_path}")
            return pd.DataFrame(records)
        except Exception:
            continue

    # Fallback: heuristic search
    print("  [SRUM] Probing via heuristic search...")
    found_paths = heuristic_discover_files(
        fs, [r'^SRUDB\.dat$', r'^srudb\.dat$'],
        start_path="/", max_depth=10
    )
    for path in found_paths:
        try:
            f_obj = fs.open(path)
            mtime = (datetime.fromtimestamp(f_obj.info.meta.mtime, timezone.utc)
                     .strftime('%Y-%m-%d %H:%M:%S'))
            size = f_obj.info.meta.size if f_obj.info.meta else 0
            records.append({
                'Date and Time': mtime,
                'Event ID': '9901',
                'Task Category': (
                    f"SRUM Database detected at {path} "
                    f"(Size: {size:,} bytes). "
                    "Network and energy usage history available."
                ),
                'LogSource': 'SRUM',
                'Keywords': 'Alert',
                'ArtifactType': 'SRUM',
            })
            break
        except Exception:
            continue

    if not records:
        print("  [SRUM] No SRUDB.dat found on this image.")
    return pd.DataFrame(records)


# ═══════════════════════════════════════════════════════════════════════════
# FIX-4: extract_recent_documents — dir-type guard
# ═══════════════════════════════════════════════════════════════════════════

def extract_recent_documents(fs):
    """Extract .lnk files from Recent Documents folders for all user profiles."""
    records = []
    _skip_names = {'all users', 'default', 'default user', 'public', '.', '..'}

    try:
        roots = get_user_roots(fs)
        if not roots:
            return pd.DataFrame()
        if debug_extract:
            print(f"  [DEBUG] RecentDocs base roots: {', '.join(roots)}")

        for base_root in roots:
            try:
                users_dir = fs.open_dir(base_root)
            except Exception as e:
                if debug_extract:
                    print(f"  [DEBUG] RecentDocs open root failed: {base_root} -> {e}")
                continue

            for user_entry in users_dir:
                try:
                    raw = user_entry.info.name.name
                    name = (raw.decode('utf-8', errors='ignore')
                            if isinstance(raw, bytes) else raw)
                    if name.lower() in _skip_names:
                        continue

                    # FIX-4: verify it is actually a directory
                    ntype = user_entry.info.name.type
                    meta_type = (user_entry.info.meta.type
                                 if user_entry.info.meta else 0)
                    is_dir = (ntype == 2) or (meta_type == 2)
                    if not is_dir:
                        try:
                            fs.open_dir(f"{base_root}/{name}")
                            is_dir = True
                        except Exception:
                            is_dir = False
                    if not is_dir:
                        continue

                    recent_candidates = [
                        f"{base_root}/{name}/AppData/Roaming/Microsoft/Windows/Recent",
                        f"{base_root}/{name}/Recent",
                    ]
                    for recent_path in recent_candidates:
                        try:
                            recent_dir = fs.open_dir(recent_path)
                            if recent_dir is None:
                                continue
                        except Exception:
                            continue

                        for lnk_entry in recent_dir:
                            try:
                                raw_l = lnk_entry.info.name.name
                                lnk_name = (raw_l.decode('utf-8', errors='ignore')
                                            if isinstance(raw_l, bytes) else raw_l)
                                if lnk_name in ('.', '..'):
                                    continue
                                if not lnk_name.lower().endswith('.lnk'):
                                    continue

                                meta = lnk_entry.info.meta
                                ts = (datetime.fromtimestamp(meta.mtime, timezone.utc)
                                      if meta and meta.mtime else None)
                                ts_str = ts.strftime('%Y-%m-%d %H:%M:%S UTC') if ts else 'N/A'

                                records.append({
                                    'Date and Time': ts_str,
                                    'Event ID': '9700',
                                    'Task Category': (
                                        f"Recent Document: {name} accessed '{lnk_name}'"
                                    ),
                                    'LogSource': 'RECENT',
                                    'Keywords': 'Alert',
                                    'ArtifactType': 'RECENT',
                                })
                            except Exception:
                                continue
                        break  # Found valid Recent dir; stop trying alternatives
                except Exception:
                    continue
    except Exception as e:
        if debug_extract:
            print(f"  [DEBUG] RecentDocs error: {e}")

    print(f"  [RECENT] Extracted {len(records)} recent-document entries")
    return pd.DataFrame(records)


def extract_prefetch(fs):
    records = []
    prefetch_paths = [
        "/Windows/Prefetch",
        "/Windows/prefetch",
    ]

    for pf_path in prefetch_paths:
        try:
            pf_dir = fs.open_dir(pf_path)
        except Exception:
            continue

        if pf_dir is None:
            continue

        for entry in pf_dir:
            try:
                fname = entry.info.name.name.decode('utf-8', errors='ignore')
                if fname in ['.', '..']:
                    continue
                if not fname.lower().endswith('.pf'):
                    continue
                meta = entry.info.meta
                mtime = (datetime.fromtimestamp(meta.mtime, timezone.utc)
                         .strftime('%Y-%m-%d %H:%M:%S')
                         if meta and meta.mtime and meta.mtime > 0 else 'N/A')
                crtime = (datetime.fromtimestamp(meta.crtime, timezone.utc)
                          .strftime('%Y-%m-%d %H:%M:%S')
                          if meta and meta.crtime and meta.crtime > 0 else 'N/A')
                prog_name = fname.rsplit('-', 1)[0] if '-' in fname else fname.replace('.pf', '')
                records.append({
                    'Date and Time': mtime,
                    'Event ID': '9300',
                    'Task Category': (
                        f"Prefetch: {prog_name} "
                        f"(File: {fname}, Last Run: {mtime}, Created: {crtime})"
                    ),
                    'LogSource': 'PREFETCH',
                    'Keywords': 'None',
                    'ArtifactType': 'PREFETCH',
                })
            except Exception:
                continue
        print(f"  [PREFETCH] Extracted {len(records)} prefetch entries")
        break

    return pd.DataFrame(records)


def extract_system_artifact(fs):
    system_paths = ["/Windows/System32/config/SYSTEM",
                    "/Windows/System32/config/system"]
    for sys_path in system_paths:
        try:
            f_obj = fs.open(sys_path)
            reg_data = f_obj.read_random(0, f_obj.info.meta.size)
            return parse_registry_hive(reg_data, "SYSTEM")
        except Exception:
            continue
    return pd.DataFrame()


# ═══════════════════════════════════════════════════════════════════════════
# FIX-9: carve_evidence_from_image — SRUM/EXECUTION properly isolated
# ═══════════════════════════════════════════════════════════════════════════

def carve_evidence_from_image(image_source):
    """
    Open a forensic disk image with pytsk3 and extract ALL evidence.
    image_source: Can be a single string path or a list of strings.
    """
    global artifact_counts
    all_frames = []
    artifact_counts = {
        "evtx": 0, "registry": 0, "filesystem": 0,
        "sam": 0, "software": 0, "prefetch": 0, "total": 0
    }

    import pytsk3

    filepaths = image_source if isinstance(image_source, list) else [image_source]
    primary_file = filepaths[0]

    is_e01 = primary_file.lower().endswith('.e01')
    if is_e01:
        try:
            import pyewf
            ewf_handle = pyewf.handle()
            ewf_handle.open(filepaths)

            try:
                case_num = ewf_handle.get_header_value("case_number")
                ev_num = ewf_handle.get_header_value("evidence_number")
                print(f"  [VALIDATE] E01 Set Metadata -> Case: {case_num}, Evidence: {ev_num}")
                if hasattr(ewf_handle, 'get_number_of_segment_files'):
                    actual_segments = ewf_handle.get_number_of_segment_files()
                    if actual_segments < len(filepaths):
                        print(f"  [WARN] libewf only recognized {actual_segments} "
                              f"of {len(filepaths)} files.")
            except Exception as e:
                print(f"  [WARN] Metadata validation skipped: {e}")

            img_info = EWFImgInfo(ewf_handle)
            print(f"  [OK] Opened E01 image set ({len(filepaths)} files)")
        except ImportError:
            raise RuntimeError(
                "[ERROR] libewf-python required for .E01 files. "
                "Run: pip install libewf-python"
            )
    else:
        img_info = pytsk3.Img_Info(primary_file)

    fs = None
    offsets_to_try = [0, 1048576, 65536, 32256]
    try:
        volume = pytsk3.Volume_Info(img_info)
        for part in volume:
            if part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                offset = part.start * volume.info.block_size
                if offset not in offsets_to_try:
                    offsets_to_try.insert(0, offset)
    except Exception as e:
        err_msg = str(e)
        if "missing segment file" in err_msg.lower():
            raise RuntimeError(
                f"[ERROR] Split E01 Image Detected. Ensure all segments are uploaded. "
                f"Internal Error: {err_msg}"
            )
        print(f"   Could not read volume/partition table: {e}")

    for offset in offsets_to_try:
        try:
            fs = pytsk3.FS_Info(img_info, offset=offset)
            print(f"  [OK] Filesystem found at offset {offset}")
            break
        except Exception:
            continue
    else:
        img_name = os.path.basename(primary_file)
        raise RuntimeError(
            f"[ERROR] No filesystem found in image '{img_name}'. "
            f"Tried offsets: {offsets_to_try}."
        )

    # FIX-9: SRUM and EXECUTION are independent named tasks
    print(f"  [EXEC] Starting parallel artifact extraction (Max Workers: 14)...")

    tasks = [
        ("EVTX",          extract_all_evtx,               (fs,)),
        ("SYSTEM",        extract_system_artifact,         (fs,)),
        ("SAM",           extract_sam_hive,                (fs,)),
        ("SOFTWARE",      extract_software_hive,           (fs,)),
        ("USB",           extract_usb_devices,             (fs,)),
        ("NTUSER",        extract_all_ntuser,              (fs,)),   # FIX-5
        ("PREFETCH",      extract_prefetch,                (fs,)),
        ("FILESYSTEM",    walk_filesystem,                 (fs, 150000)),
        ("ACTIVITY",      extract_user_activity,           (fs,)),
        ("RECENT",        extract_recent_documents,        (fs,)),   # FIX-4
        ("RECYCLE",       extract_recycle_bin,             (fs,)),
        ("BROWSER",       extract_browser_history,         (fs,)),   # FIX-3
        ("COMMUNICATION", extract_communication_artifacts, (fs,)),   # FIX-6
        ("USN",           extract_usn_journal,             (fs,)),
        ("EXECUTION",     extract_execution_history,       (fs,)),   # FIX-8
        ("SRUM",          extract_srum_data,               (fs,)),   # FIX-7
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=14) as executor:
        future_to_name = {
            executor.submit(fn, *args): name for name, fn, args in tasks
        }
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                df = future.result()
                if df is not None and not df.empty:
                    all_frames.append(df)
                    if name == "EVTX":         artifact_counts["evtx"]       = len(df)
                    elif name == "SAM":        artifact_counts["sam"]        = len(df)
                    elif name == "SOFTWARE":   artifact_counts["software"]   = len(df)
                    elif name == "USB":        artifact_counts["usb"]        = len(df)
                    elif name == "BROWSER":    artifact_counts["browser"]    = len(df)
                    elif name == "COMMUNICATION": artifact_counts["comm"]    = len(df)
                    elif name == "PREFETCH":   artifact_counts["prefetch"]   = len(df)
                    elif name == "FILESYSTEM": artifact_counts["filesystem"] = len(df)
                    print(f"  [OK] {name}: {len(df)} entries")
                elif debug_extract:
                    print(f"  [DEBUG] {name}: 0 entries")
            except Exception as exc:
                print(f"  [FAIL] {name} extraction failed: {exc}")
                if debug_extract:
                    traceback.print_exc()

    if not all_frames:
        raise RuntimeError(
            f"[ERROR] No artifacts extracted from '{os.path.basename(primary_file)}'."
        )

    result = pd.concat(all_frames, ignore_index=True)
    artifact_counts["total"] = len(result)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: FEATURE ENGINEERING & ML
# ═══════════════════════════════════════════════════════════════════════════

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
        for j in range(max(0, i - 50), i + 1):
            ts_j = timestamps[j]
            if pd.notna(ts_j) and window_start <= ts_j <= ts:
                count += 1
        epm.append(count)

    df['EventsPerMinute'] = epm
    df.drop(columns=['_ts'], inplace=True, errors='ignore')

    print("   Vectorizing behavioral threat predictions...")

    def extract_eid(eid_raw):
        val = ''.join(filter(str.isdigit, str(eid_raw)))
        return int(val) if val else 0

    df['EventID_Num'] = df['Event ID'].apply(extract_eid)

    if ml_alarm is not None:
        try:
            features = df[['EventID_Num', 'HourOfDay', 'EventsPerMinute']].values
            df['ML_Prediction'] = ml_alarm.predict(features)
        except Exception as e:
            print(f"   Vectorized ML failed: {e}")
            df['ML_Prediction'] = 1
    else:
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


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: RAG / LLM
# ═══════════════════════════════════════════════════════════════════════════

faiss_lock = threading.Lock()

# ── FIX-3: Normalize text before embedding to maximize cache hit rate ─────
def _normalize_for_embedding(txt: str) -> str:
    """Collapse volatile tokens so semantically identical events share one vector."""
    txt = re.sub(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}(\s?UTC)?', '<TS>', txt)
    txt = re.sub(r'\{[0-9A-Fa-f\-]{36}\}', '<GUID>', txt)
    txt = re.sub(r'\b0x[0-9A-Fa-f]{4,}\b', '<HEX>', txt)
    txt = re.sub(r'\b\d{6,}\b', '<NUM>', txt)
    txt = re.sub(r'([A-Za-z]:\\|/)[^\s|]+[\\/]', '<PATH>/', txt)
    return txt.strip()

def build_rag_context(query, top_k=8):
    global faiss_index, ai_model, image_hash_sha256

    if current_audit_df is None:
        return [], ""

    # ── REQ-1 & REQ-2: Strict filtering — Activity-Based artifacts ONLY ──────
    # FILESYSTEM (MFT) is completely excluded from FAISS embedding.
    # File count questions are answered via extract_system_context() metadata.
    EMBED_TYPES = {'EVTX', 'REGISTRY', 'SAM', 'SOFTWARE'}

    embed_mask = current_audit_df['ArtifactType'].str.upper().isin(EMBED_TYPES)
    embed_df = current_audit_df[embed_mask].copy().reset_index(drop=True)
    embed_df = embed_df.drop_duplicates(subset=['Task Category']).reset_index(drop=True)
    # ─────────────────────────────────────────────────────────────────────────

    from sentence_transformers import SentenceTransformer

    with faiss_lock:
        if ai_model is None:
            ai_model = SentenceTransformer('all-MiniLM-L6-v2')

        if faiss_index is None:
            cache_file = None
            if image_hash_sha256:
                case_dir = os.path.join(SCRIPT_DIR, "cache", image_hash_sha256)
                os.makedirs(case_dir, exist_ok=True)
                cache_file = os.path.join(case_dir, "faiss.index")

            # ── REQ-4: Validate cache against filtered embed_df, not full df ─
            if cache_file and os.path.exists(cache_file):
                print(f"  [FAISS] Loading cached index: {image_hash_sha256[:16]}...")
                loaded_index = faiss.read_index(cache_file)
                if loaded_index.ntotal == len(embed_df):
                    faiss_index = loaded_index
                    print(f"  [FAISS] Cache valid ({loaded_index.ntotal} vectors).")
                else:
                    print(
                        f"  [WARN] Cache size mismatch "
                        f"({loaded_index.ntotal} cached vs {len(embed_df)} filtered). "
                        f"Rebuilding..."
                    )
                    faiss_index = None
            # ─────────────────────────────────────────────────────────────────

            if faiss_index is None:
                print(f"  [FAISS] Vectorizing {len(embed_df)} activity artifacts "
                      f"(EVTX + REGISTRY + SAM + SOFTWARE only)...")
                t0 = time.time()

                texts_series = embed_df['Task Category'].fillna('').astype(str)
                unique_texts = texts_series.unique().tolist()

                # Normalize to collapse volatile tokens and improve cache hits
                normalized_texts = [_normalize_for_embedding(t) for t in unique_texts]

                # ── REQ: num_workers removed — not supported by this ST version ──
                unique_embeddings = ai_model.encode(
                    normalized_texts,
                    batch_size=256,
                    show_progress_bar=False,
                    convert_to_numpy=True,
                )
                # ─────────────────────────────────────────────────────────────

                # Map unique embeddings back to the full filtered series
                text_to_idx = {text: i for i, text in enumerate(unique_texts)}
                idx_map = texts_series.map(text_to_idx).values
                full_embeddings = unique_embeddings[idx_map]

                dim = full_embeddings.shape[1]

                # ── FIX-2: IVF only at large scale; Flat L2 for typical loads ─
                ivf_threshold = int(os.getenv("FAISS_IVF_THRESHOLD", "500"))
                n_unique = len(unique_embeddings)
                if n_unique > ivf_threshold:
                    nlist = min(int(n_unique ** 0.5), 256)
                    quantizer = faiss.IndexFlatL2(dim)
                    faiss_index = faiss.IndexIVFFlat(quantizer, dim, nlist)
                    faiss_index.train(
                        np.array(unique_embeddings).astype('float32')
                    )
                    faiss_index.nprobe = min(32, nlist)
                    print(f"  [FAISS] Using IVF index (nlist={nlist})")
                else:
                    faiss_index = faiss.IndexFlatL2(dim)
                    print(f"  [FAISS] Using Flat L2 index")
                # ─────────────────────────────────────────────────────────────

                faiss_index.add(np.array(full_embeddings).astype('float32'))

                if cache_file:
                    faiss.write_index(faiss_index, cache_file)

                elapsed = time.time() - t0
                print(f"  [FAISS] Index ready — {faiss_index.ntotal} vectors "
                      f"in {elapsed:.2f}s")

    # Return early if this was just an init/warmup call
    if query == "Init":
        return [], ""

    # ── REQ-5: embed_df is always defined above the lock so search is safe ───
    # Encode query — num_workers omitted for ST compatibility
    query_vec = ai_model.encode([query], convert_to_numpy=True)
    distances, result_indices = faiss_index.search(
        np.array(query_vec).astype('float32'), k=top_k
    )

    relevant_rows = []
    context_lines = []

    for rank, (dist, idx) in enumerate(zip(distances[0], result_indices[0])):
        if idx < 0 or idx >= len(embed_df):
            continue
        row = embed_df.iloc[idx]
        relevant_rows.append(row)
        context_lines.append(
            f"[Evidence {rank}] "
            f"Time: {row.get('Date and Time', 'N/A')} | "
            f"EventID: {row.get('Event ID', 'N/A')} | "
            f"Source: {row.get('LogSource', 'N/A')} | "
            f"Description: {row.get('Task Category', 'N/A')}"
        )

    return relevant_rows, "\n".join(context_lines)


def extract_system_context():
    global current_audit_df
    if current_audit_df is None or current_audit_df.empty:
        return "No evidence loaded."

    df = current_audit_df

    start_time, end_time = "N/A", "N/A"
    hostname, os_version = "Unknown", "Unknown"
    user_list = "None"

    type_groups = {k: g for k, g in df.groupby(df['ArtifactType'].astype(str).str.upper())}
    for t in ['SAM', 'REGISTRY', 'SOFTWARE', 'FILESYSTEM', 'PREFETCH', 'ACTIVITY']:
        if t not in type_groups:
            type_groups[t] = pd.DataFrame(columns=df.columns)

    users = set()
    all_categories = df['Task Category'].dropna().astype(str)
    ntuser_entries = all_categories[
        all_categories.str.contains(r"NTUSER\(", case=False, na=False)
    ]
    for desc_str in ntuser_entries.unique():
        match = re.search(r'NTUSER\((.*?)\)', desc_str, re.IGNORECASE)
        if match:
            users.add(match.group(1).strip())
    user_list = ", ".join(users) if users else "None found"

    sam_users = []
    sam_logon_stats = []
    for desc in type_groups['SAM']['Task Category'].dropna():
        d_str = str(desc)
        name_match = re.search(r'SAM User Account:\s*(.+?)\s*\(', d_str)
        logon_match = re.search(r'Logons:\s*(\d+)', d_str)
        if name_match:
            u_name = name_match.group(1).strip()
            sam_users.append(u_name)
            if logon_match:
                sam_logon_stats.append((u_name, int(logon_match.group(1))))
    sam_users_str = (f"{len(sam_users)} accounts: {', '.join(sam_users)}"
                     if sam_users else "None found")

    usb_devices, run_keys = [], []
    av_disabled = False

    reg_df = type_groups['REGISTRY']
    reg_descs = reg_df['Task Category'].dropna().astype(str)
    for desc in reg_descs:
        d_lower = desc.lower()
        if "computername\\computername" in d_lower and "=" in d_lower:
            hostname = desc.split("=")[-1].strip()
        elif "currentversion\\productname =" in d_lower:
            os_version = desc.split("=")[-1].strip()
        elif "usbstor" in d_lower or "enum\\usb" in d_lower:
            usb_devices.append(desc.split("\\")[-1])
        elif "currentversion\\run" in d_lower:
            run_keys.append(desc.split("\\")[-1])
        elif "disableantispyware" in d_lower and "= 1" in d_lower:
            av_disabled = True

    sw_descs = type_groups['SOFTWARE']['Task Category'].dropna().astype(str)
    for desc in sw_descs:
        if "OS Information:" in desc and os_version == "Unknown":
            match = re.search(r'ProductName:\s*([^|]+)', desc)
            if match:
                os_version = match.group(1).strip()

    usb_str = ", ".join(set([u for u in usb_devices if len(u) > 3][:5])) if usb_devices else "None"
    run_str = ", ".join(set([r for r in run_keys if len(r) > 3][:5])) if run_keys else "None"

    file_stats_str = "No filesystem data"
    fs_df = type_groups['FILESYSTEM']
    if not fs_df.empty and '_extension' in fs_df.columns:
        total_files = len(fs_df[fs_df['_is_dir'] == False])
        total_dirs = len(fs_df[fs_df['_is_dir'] == True])
        all_exts = fs_df[fs_df['_extension'].astype(str) != '']['_extension'].value_counts().head(20)
        categories = {
            "Images":      [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
            "Videos":      [".mp4", ".mov", ".avi", ".mkv", ".wmv"],
            "Docs":        [".pdf", ".doc", ".docx", ".txt", ".xlsx", ".csv", ".pptx", ".rtf"],
            "Executables": [".exe", ".dll", ".sys", ".bat", ".ps1", ".msi"],
            "Archives":    [".zip", ".rar", ".7z", ".tar", ".gz", ".iso"]
        }
        cat_counts = {
            cat: sum([all_exts.get(e, 0) for e in elist])
            for cat, elist in categories.items()
        }
        cat_parts = [f"{k}: {int(v)}" for k, v in cat_counts.items()]
        ext_parts = [f"{k}: {int(v)}" for k, v in all_exts.head(15).items()]
        file_stats_str = (f"Total Files: {total_files}, Total Dirs: {total_dirs}. "
                          f"CATEGORY COUNTS: {', '.join(cat_parts)}. "
                          f"DETAILED EXTENSIONS: {', '.join(ext_parts)}")

    installed = [
        re.search(r'Installed Program:\s*(.+?)(?:\s*v|\s*\()', str(d)).group(1).strip()
        for d in sw_descs
        if "Installed Program:" in str(d)
        and re.search(r'Installed Program:\s*(.+?)(\s*v|\s*\()', str(d))
    ]
    programs_str = (f"{len(installed)} programs: {', '.join(installed[:10])}"
                    if installed else "No program data")

    prefetch = [
        re.search(r'Prefetch:\s*(.+?)\s*\(', str(d)).group(1).strip()
        for d in type_groups['PREFETCH']['Task Category'].dropna()
        if "Prefetch:" in str(d)
    ]
    pf_unique = list(set(prefetch))
    prefetch_str = (f"{len(pf_unique)} unique programs: {', '.join(pf_unique[:10])}"
                    if pf_unique else "No prefetch data")

    recent_programs_str = "None"
    if not type_groups['PREFETCH'].empty:
        pf_df = type_groups['PREFETCH'].copy()
        pf_df['_ts'] = pd.to_datetime(pf_df['Date and Time'], errors='coerce')
        pf_df = pf_df.sort_values('_ts', ascending=False)
        pf_names = []
        for d in pf_df['Task Category'].dropna().astype(str):
            m = re.search(r'Prefetch:\s*(.+?)\s*\(', d)
            if m:
                pf_names.append(m.group(1).strip())
        pf_names = [n for n in pf_names if n]
        recent_programs_str = ", ".join(list(dict.fromkeys(pf_names))[:5]) if pf_names else "None"
    elif not type_groups['ACTIVITY'].empty:
        act_df = type_groups['ACTIVITY']
        act_names = []
        for d in act_df['Task Category'].dropna().astype(str):
            m = re.search(r'opened\s+(.*?)\s*\(LNK', d, re.IGNORECASE)
            if m:
                act_names.append(m.group(1).strip())
        recent_programs_str = (", ".join(list(dict.fromkeys(act_names))[:5])
                               if act_names else "None")

    try:
        times = df['Date and Time'].dropna()
        start_time, end_time = times.min(), times.max()
    except:
        start_time, end_time = "Unknown", "Unknown"

    logon_users = []
    logons_df = df[df['Event ID'].astype(str).isin(['4624', '4625', '4624.0', '4625.0'])]
    for desc in logons_df['Task Category'].dropna():
        match = re.search(r'(?:TargetUserName|SubjectUserName):\s*([^\s\|]+)', str(desc))
        if match:
            u = match.group(1).strip()
            if u not in ['-', 'SYSTEM', 'NETWORK', 'LOCAL SERVICE', 'NETWORK SERVICE'] \
                    and not u.endswith('$'):
                logon_users.append(u)

    unified_counts = {u: c for u, c in sam_logon_stats}
    for u, c in Counter(logon_users).items():
        unified_counts[u] = max(c, unified_counts.get(u, 0))
    active_users_str = ", ".join(
        [f"{u} ({c} logons)" for u, c in Counter(unified_counts).most_common(5)]
    )

    top_events = df['Event ID'].value_counts().head(5).to_dict()
    top_events_str = ", ".join([f"ID {k} ({v})" for k, v in top_events.items()])

    cleared_count = len(df[df['Event ID'].astype(str).isin(['1102', '1102.0'])])
    alerts_str = ((f"Audit Logs Cleared ({cleared_count}x), " if cleared_count else "")
                  + ("AV DISABLED" if av_disabled else "None"))

    anom_counts = (df['AnomalyScore'].value_counts().to_dict()
                   if 'AnomalyScore' in df.columns else {})
    anomaly_str = f"Normal: {anom_counts.get(1, 0)}, Threat: {anom_counts.get(-1, 0)}"

    recent_docs = [
        str(d) for d in type_groups['ACTIVITY']['Task Category'].dropna().unique()
        if any(x in str(d).lower() for x in ['opened', 'interacted'])
    ]
    recent_docs_str = "\n   - ".join(recent_docs[:10]) if recent_docs else "None"

    usb_df = type_groups.get('USB', pd.DataFrame())
    usb_count = len(usb_df)
    usb_list = "None"
    if not usb_df.empty and 'Task Category' in usb_df.columns:
        extracted = (usb_df['Task Category'].str
                     .extract(r'USB Device Attached: (.*?) \(')[0]
                     .dropna().unique().tolist())
        if not extracted:
            extracted = (usb_df['Task Category'].str
                         .extract(r'USB Device:\s*(.*?) \(')[0]
                         .dropna().unique().tolist())
        usb_list = ", ".join(extracted[:8]) if extracted else "None"

    browser_df = type_groups.get('BROWSER', pd.DataFrame())
    search_count = bookmark_count = cookie_count = 0
    if not browser_df.empty and 'Event ID' in browser_df.columns:
        search_count   = len(browser_df[browser_df['Event ID'].astype(str).isin(['9600', '9600.0'])])
        bookmark_count = len(browser_df[browser_df['Event ID'].astype(str).isin(['9602', '9602.0'])])
        cookie_count   = len(browser_df[browser_df['Event ID'].astype(str).isin(['9603', '9603.0'])])

    recent_df = type_groups.get('RECENT', pd.DataFrame())
    recent_count = len(recent_df)
    if recent_count == 0:
        activity_df = type_groups.get('ACTIVITY', pd.DataFrame())
        recent_count = (
            len(activity_df[activity_df['Task Category']
                            .astype(str).str.contains('Recent Document', na=False)])
            if not activity_df.empty else 0
        )

    recycle_df = type_groups.get('RECYCLE', pd.DataFrame())
    recycle_count = len(recycle_df)

    comm_df = type_groups.get('COMMUNICATION', pd.DataFrame())
    comm_count = len(comm_df)

    return (
        f"TOTAL LOGS: {len(df)}\nRANGE: {start_time} UTC to {end_time} UTC\n"
        f"HOST: {hostname} | OS: {os_version}\nALERTS: {alerts_str}\n"
        f"SAM USERS: {sam_users_str}\nPROFILES: {user_list}\n"
        f"ACTIVE USERS: {active_users_str}\nFILESYSTEM: {file_stats_str}\n"
        f"PROGRAMS: {programs_str}\nPREFETCH: {prefetch_str}\n"
        f"RECENT PROGRAMS: {recent_programs_str}\n"
        f"USB DEVICES ({usb_count}): {usb_list}\n"
        f"WEB ACTIVITY: {search_count} searches, {bookmark_count} bookmarks, "
        f"{cookie_count} cookies\n"
        f"RECENT DOCUMENTS: {recent_count} entries showing recently accessed files\n"
        f"RECYCLE BIN: {recycle_count} items currently in the recycle bin\n"
        f"COMMUNICATION: {comm_count} email/mail files found\n"
        f"TOP EVENTS: {top_events_str}\nRECENT ACTIVITY: {recent_docs_str}\n"
        f"ANOMALIES: {anomaly_str}"
    )


def format_evidence_block(evidence_context, max_lines=5):
    if not evidence_context:
        return ""
    lines = [line.strip() for line in evidence_context.split("\n") if line.strip()]
    lines = lines[:max_lines]
    if not lines:
        return ""
    return "\n".join([f"- {line}" for line in lines])


def build_offline_response(user_question, evidence_context):
    system_facts = extract_system_context()
    evidence_block = format_evidence_block(evidence_context)
    if evidence_block:
        evidence_block = f"\n\nEVIDENCE:\n{evidence_block}"
    return (
        "LLM unavailable. Returning deterministic summary.\n\n"
        f"SYSTEM FACTS:\n{system_facts}"
        f"{evidence_block}"
    )


def query_llm(user_question, evidence_context):
    global cached_system_facts

    if cached_system_facts is None:
        print("  [CACHE] Regenerating system facts...")
        cached_system_facts = extract_system_context()

    system_facts = cached_system_facts

    system_prompt = f"""You are a Senior Digital Forensics Examiner.
You are analyzing evidence extracted from a forensic disk image. Given the user's question, provide a clear, professional forensic analysis.

── GLOBAL SYSTEM FACTS (CRITICAL - READ FIRST) ──
{system_facts}

CRITICAL INSTRUCTIONS:
1. Use the GLOBAL SYSTEM FACTS for aggregate questions.
2. Use the RETRIEVED EVIDENCE for detailed analysis.
3. Provide a short evidence-backed answer with minimal narrative.
4. Always bold key forensic findings, account names, timestamps, and suspicious activities.
5. Include a short section "EVIDENCE" that lists 1-5 evidence lines verbatim.
6. List evidence IDs as `USED_EVIDENCE: [id1, id2]`.
7. Keep responses under 150 words."""

    prompt = f"""{system_prompt}

── RETRIEVED EVIDENCE ──
{evidence_context}

── INVESTIGATOR'S QUESTION ──
{user_question}

── YOUR FORENSIC ANALYSIS ──"""

    if groq_client:
        try:
            chat_completion = groq_client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.2,
            )
            return chat_completion.choices[0].message.content
        except Exception as e:
            print(f"  [LLM] Groq error: {e}")

    if gemini_client:
        try:
            response = gemini_client.models.generate_content(
                model=GEMINI_MODEL_ID,
                contents=prompt,
                config={"system_instruction": system_prompt, "temperature": 0.1}
            )
            return response.text
        except Exception as e:
            print(f"  [LLM] Gemini error: {e}")

    return build_offline_response(user_question, evidence_context)


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: UPLOAD HANDLER & GUI
# ═══════════════════════════════════════════════════════════════════════════

def handle_image_upload(files):
    global current_audit_df, image_hash_sha256, cached_system_facts, faiss_index

    if not files:
        return "No files uploaded."

    filepaths = [f.name if hasattr(f, 'name') else str(f) for f in files]
    primary_file = filepaths[0]
    image_hash_sha256 = compute_sha256(primary_file)

    case_dir = os.path.join(SCRIPT_DIR, "cache", image_hash_sha256)
    os.makedirs(case_dir, exist_ok=True)
    artifact_path = os.path.join(case_dir, "artifacts.pkl")

    if os.path.exists(artifact_path):
        current_audit_df = pd.read_pickle(artifact_path)
        status_msg = (
            f"Forensic Image Loaded: {len(current_audit_df)} artifacts recovered. "
            f"SHA-256: {image_hash_sha256}"
        )
    else:
        print(f"  [IMAGE] Analyzing new forensic source...")
        df = carve_evidence_from_image(filepaths)
        df = engineer_features(df)
        df.to_pickle(artifact_path)
        current_audit_df = df
        status_msg = (
            f"Forensic Image Carved: {len(df)} artifacts identified. "
            f"SHA-256: {image_hash_sha256}"
        )

    # ── REQ-6: Always reset state and trigger background index build ─────────
    # Applies to both fresh carves AND cache loads so repeated uploads work.
    cached_system_facts = None
    faiss_index = None  # Force index rebuild for new image

    def _background_index_build():
        try:
            print("  [FAISS] Background index build started...")
            build_rag_context("Init")
            print("  [FAISS] Background index build complete.")
        except Exception as e:
            print(f"  [FAISS] Background index build failed: {e}")
            if debug_extract:
                traceback.print_exc()

    threading.Thread(target=_background_index_build, daemon=True).start()
    # ─────────────────────────────────────────────────────────────────────────

    return status_msg

def build_gui():
    CSS = """
    .sidebar-box { background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; }
    #chat-history { height: 500px; overflow-y: auto; background: #0f172a; border-radius: 8px; border: 1px solid #1e293b; }
    .stat-card { background: #1e293b; border: 1px solid #334155; padding: 15px; border-radius: 8px; margin: 5px; text-align: center; }
    #raw-artifacts { height: 520px; overflow: auto; }
    """

    with gr.Blocks() as demo:
        gr.Markdown("## 🛡️ VIGILANCE FORENSIC ENGINE v3.1")

        with gr.Row():
            with gr.Column(scale=1, elem_classes="sidebar-box"):
                gr.Markdown("### 📂 Case Management")
                image_input = gr.File(label="Upload Forensic Image", file_count="multiple")
                upload_btn = gr.Button("🚀 CARVE ARTIFACTS", variant="primary")
                status_box = gr.Textbox(label="FORENSIC STATUS", value="Standby", interactive=False)

                gr.Markdown("---")
                gr.Markdown("### 💡 Forensic Inquiry Examples")
                gr.HTML("<div style='color:#94a3b8; font-size:0.85em;'>"
                        "• 'List all user accounts'<br>"
                        "• 'Show USB device history'<br>"
                        "• 'Find deleted items'</div>")

            with gr.Column(scale=3):
                with gr.Tabs():

                    with gr.Tab("AI Investigation"):
                        chatbot = gr.Chatbot(
                            label="Forensic Reasoning Logs",
                            height=500,
                            elem_id="chat-history"
                        )
                        with gr.Row():
                            msg = gr.Textbox(
                                placeholder="Enter forensic query...",
                                scale=9, container=False, show_label=False
                            )
                            submit_btn = gr.Button("Send", scale=1, variant="primary")

                    with gr.Tab("Dashboard & Summary"):
                        refresh_btn = gr.Button("🔄 REFRESH CASE SUMMARY", variant="primary")
                        summary_output = gr.HTML(
                            value="<div style='text-align:center; padding:50px; color:#94a3b8;'>"
                                  "Upload a Case Image to generate summary.</div>"
                        )

                    with gr.Tab("Raw Artifacts"):
                        artifacts_btn = gr.Button("Load Artifacts Dataframe")
                        raw_dataframe = gr.Dataframe(
                            interactive=False, wrap=True, elem_id="raw-artifacts"
                        )

        def respond(message, history):
                # ── FIX-5: Guard against querying before background build completes ──
            if faiss_index is None and current_audit_df is not None:
                not_ready_msg = (
                    "⏳ The forensic index is still being built in the background. "
                    "Please wait 15–30 seconds and try again."
                )
                history = history or []
                history.append({"role": "user", "content": message})
                history.append({"role": "assistant", "content": not_ready_msg})
                return "", history
            # ─────────────────────────────────────────────────────────────────────
            clean_history = []
            for item in history:
                if isinstance(item, (list, tuple)):
                    clean_history.append({"role": "user", "content": str(item[0])})
                    clean_history.append({"role": "assistant", "content": str(item[1])})
                else:
                    clean_history.append(item)

            relevant_rows, context_text = build_rag_context(message)
            bot_message = query_llm(message, context_text)
            evidence_block = format_evidence_block(context_text)
            if evidence_block and "EVIDENCE:" not in bot_message:
                bot_message = f"{bot_message}\n\nEVIDENCE:\n{evidence_block}"

            clean_history.append({"role": "user", "content": message})
            clean_history.append({"role": "assistant", "content": bot_message})

            return "", clean_history

        def get_styled_summary():
            if current_audit_df is None:
                return ("<div style='color:#94a3b8;text-align:center;'>"
                        "Upload a Case to begin summary analysis.</div>")
            raw = extract_system_context()

            try:
                host = raw.split("HOST: ")[1].split(" | ")[0]
                os_ver = raw.split("OS: ")[1].split("\n")[0]
                total_logs = raw.split("TOTAL LOGS: ")[1].split("\n")[0]
            except:
                host, os_ver, total_logs = "Unknown Host", "Unknown OS", "0"

            html = f"""
            <div style='display: grid; grid-template-columns: repeat(3, 1fr);
                        gap: 15px; margin-bottom: 20px;'>
                <div class='stat-card'>
                    <h4 style='color:#3b82f6;margin:0;'>HOST</h4>
                    <p style='margin:5px 0;'>{host}</p>
                </div>
                <div class='stat-card'>
                    <h4 style='color:#3b82f6;margin:0;'>OS</h4>
                    <p style='margin:5px 0;'>{os_ver}</p>
                </div>
                <div class='stat-card'>
                    <h4 style='color:#3b82f6;margin:0;'>ARTIFACTS</h4>
                    <p style='margin:5px 0;'>{total_logs}</p>
                </div>
            </div>
            <div style='background:#0f172a; padding:20px; border-radius:8px;
                        border:1px solid #1e293b; color:#cbd5e1; font-family:monospace;
                        font-size:0.9em; height:450px; overflow-y:auto;'>
                {raw.replace(chr(10), '<br>')}
            </div>
            """
            return html

        upload_btn.click(handle_image_upload, inputs=[image_input], outputs=[status_box])
        msg.submit(respond, [msg, chatbot], [msg, chatbot], show_progress="hidden")
        submit_btn.click(respond, [msg, chatbot], [msg, chatbot], show_progress="hidden")
        refresh_btn.click(get_styled_summary, outputs=summary_output)
        artifacts_btn.click(
            lambda: current_audit_df if current_audit_df is not None else pd.DataFrame(),
            outputs=raw_dataframe
        )

    return demo, CSS


if __name__ == "__main__":
    app, css = build_gui()
    app.launch(server_port=7860, show_error=True, css=css)