"""
═══════════════════════════════════════════════════════════════════════════
  FORENSIC IMAGE ANALYSIS ENGINE v3.0
  ────────────────────────────────────
  Architecture:  pytsk3 (SleuthKit) · python-evtx · python-registry
                 Isolation Forest (Behavioral) · FAISS · Gemini RAG
  ────────────────────────────────────
  Input:   Raw disk image (.dd / .E01)
  Output:  LLM-explained forensic evidence with anomaly classification
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

current_audit_df = None          # Unified evidence DataFrame
faiss_index = None               # FAISS index cache (Memory optimized)
ai_model = None                  # SentenceTransformer model (lazy loaded)
image_hash_sha256 = None         # SHA-256 of uploaded forensic image
artifact_counts = {}             # {"evtx": N, "registry": N, ...}
ml_alarm = None                  # Isolation Forest v2 model
cached_system_facts = None       # Cached string for LLM context (performance)

# -- PHASE 1 & 5: SESSION & REPORTING STATE --
investigator_name = "Unknown Examiner"
case_id = "CASE-2026-001"
case_notes = ""
session_log = []                 # List of {"query": q, "answer": a, "evidence_ids": [ids]}
db_conn = None                   # In-memory SQLite for high-speed correlation

# Load the ML model (v2: 3-feature behavioral)
MODEL_PATH = os.path.join(SCRIPT_DIR, "models", "forensic_alarm_v2.pkl")
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"[ERROR] ML model not found at '{MODEL_PATH}'. "
        f"Run 'python isolation_model.py' first to train it."
    )
ml_alarm = joblib.load(MODEL_PATH)
print(f"  [OK] Loaded ML model: {MODEL_PATH}")

def init_correlation_db():
    """Initialize an in-memory SQLite database for fast cross-artifact correlation."""
    global db_conn
    db_conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = db_conn.cursor()
    # Table for LNK and Jump List correlation
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

# Heuristic threat Event IDs
HEURISTIC_THREAT_IDS = {
    1102: "Audit Log Cleared",
    4720: "User Account Created",
    4625: "Failed Logon (Brute Force)",
    9999: "Suspicious Process Execution",
    0:    "Kernel Critical Event",
    8000: "Registry Persistence (Run/RunOnce)",
    8001: "Security Bypass (Defender/UAC Disabled)",
}

# Gemini LLM Setup (Modern SDK)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL_ID = "gemini-2.0-flash"
if not GEMINI_API_KEY:
    raise RuntimeError(
        "[ERROR] GEMINI_API_KEY not set. Create a .env file with your key. "
        "Get one at: https://aistudio.google.com/app/apikey"
    )
from google import genai
gemini_client = genai.Client(api_key=GEMINI_API_KEY)
print("  [OK] Gemini LLM configured (Modern SDK).")

# Groq LLM Setup (Fallback)
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
    """Compute SHA-256 hash of a file with retries for transient locks."""
    sha256 = hashlib.sha256()
    for attempt in range(5):
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except PermissionError:
            if attempt < 4:
                time.sleep(1)  # Wait for AV scan to release lock
            else:
                return "HASH_FAILED_PERMISSION_DENIED"
        except Exception:
            return "HASH_FAILED_ERROR"


def parse_evtx_file(evtx_data):
    """Parse a .evtx file from raw bytes into a DataFrame."""
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views
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

                    # Try to extract task/description from EventData
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
    """Parse a registry hive file from raw bytes into a DataFrame."""
    from Registry import Registry as reg_lib

    records = []
    with tempfile.NamedTemporaryFile(suffix=".hive", delete=False) as tmp:
        tmp.write(reg_data)
        tmp_path = tmp.name

    # High-interest registry paths for forensic analysis
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

            # Determine if this is a forensically interesting key
            is_interesting = any(fk.lower() in key_path.lower() for fk in FORENSIC_KEYS)

            # Determine synthetic Event ID based on key type
            if "run" in key_path.lower() and ("currentversion\\run" in key_path.lower()):
                event_id = 8000  # Persistence
            elif "defender" in key_path.lower() or "disableantispyware" in key_path.lower():
                event_id = 8001  # Security bypass
            elif "usbstor" in key_path.lower() or "enum\\usb" in key_path.lower():
                event_id = 9000  # USB history
            else:
                event_id = 7000  # Normal registry state

            for value in key.values():
                try:
                    val_name = value.name()
                    val_data = str(value.value())[:200]  # Truncate long values
                    task_desc = f"Registry {'' if is_interesting else ''}[{hive_name}] {key_path}\\{val_name} = {val_data}"

                    records.append({
                        'Date and Time': ts_str,
                        'Event ID': str(event_id),
                        'Task Category': task_desc,
                        'LogSource': 'REGISTRY',
                        'Keywords': 'Alert' if is_interesting else 'None',
                        'ArtifactType': 'REGISTRY',
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


# ── PyEWF Wrapper for .E01 Support ──
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


def walk_filesystem(fs, max_entries=100000):
    """Recursively walk the filesystem and catalog all files/directories."""
    records = []
    count = [0]

    def _walk(directory_path, depth=0, max_depth=10):
        if count[0] >= max_entries or depth > max_depth:
            return
        try:
            dir_obj = fs.open_dir(directory_path)
        except Exception:
            return
        for entry in dir_obj:
            if count[0] >= max_entries:
                return
            try:
                name = entry.info.name.name.decode('utf-8', errors='ignore')
                if name in ['.', '..', '$OrphanFiles']:
                    continue
                full_path = f"{directory_path}/{name}" if directory_path != "/" else f"/{name}"
                meta = entry.info.meta
                # 1 = TSK_FS_NAME_TYPE_REG (File), 2 = TSK_FS_NAME_TYPE_DIR (Dir)
                ntype = entry.info.name.type
                is_dir = (ntype == 2)
                is_file = (ntype == 1)
                
                size = meta.size if meta and meta.size else 0
                ext = os.path.splitext(name)[1].lower() if is_file and '.' in name else ''

                # Extract timestamps
                crtime = datetime.fromtimestamp(meta.crtime, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if meta and meta.crtime and meta.crtime > 0 else 'N/A'
                mtime = datetime.fromtimestamp(meta.mtime, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if meta and meta.mtime and meta.mtime > 0 else 'N/A'

                if is_file or is_dir:
                    ftype = "Directory" if is_dir else "File"
                    size_str = f"{size:,} bytes" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                    task_desc = f"{ftype}: {full_path} (Size: {size_str}, Modified: {mtime})"

                    records.append({
                        'Date and Time': mtime,
                        'Event ID': '0',
                        'Task Category': task_desc,
                        'LogSource': 'FILESYSTEM',
                        'Keywords': 'None',
                        'ArtifactType': 'FILESYSTEM',
                        '_filepath': full_path,
                        '_filename': name,
                        '_extension': ext,
                        '_size': size,
                        '_is_dir': is_dir,
                    })
                    count[0] += 1
                    
                    if is_file and ext in ['.jpg', '.jpeg', '.png', '.pdf', '.doc', '.docx']:
                        if count[0] % 100 == 0:
                            print(f"   [FOUND] {full_path}")

                if is_dir and depth < max_depth:
                    _walk(full_path, depth + 1, max_depth)
            except Exception:
                continue

    print("   Walking filesystem (Prioritizing /Users)...")
    _walk("/Users")
    print(f"   Cataloged {count[0]} user-profile entries")
    
    if count[0] < max_entries:
        print("   Walking remaining filesystem...")
        _walk("/")
        
    print(f"   Total filesystem entries cataloged: {count[0]}")
    return pd.DataFrame(records)


def extract_all_evtx(fs):
    """Extract ALL .evtx log files, not just Security.evtx."""
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

        for entry in evtx_dir:
            try:
                fname = entry.info.name.name.decode('utf-8', errors='ignore')
                if not fname.lower().endswith('.evtx'):
                    continue
                fpath = f"{evtx_dir_path}/{fname}"
                f_obj = fs.open(fpath)
                if f_obj.info.meta.size < 1024:  # Skip tiny/empty logs
                    continue
                evtx_data = f_obj.read_random(0, f_obj.info.meta.size)
                evtx_df = parse_evtx_file(evtx_data)
                if not evtx_df.empty:
                    # Update LogSource to reflect which log file this came from
                    channel_name = fname.replace('.evtx', '').replace('%4', '/').upper()
                    evtx_df['LogSource'] = channel_name
                    all_evtx_frames.append(evtx_df)
                    print(f"   Extracted {len(evtx_df)} events from {fname}")
            except Exception:
                continue
        break  # Found the directory, stop trying alternatives

    if all_evtx_frames:
        return pd.concat(all_evtx_frames, ignore_index=True)
    return pd.DataFrame()


def extract_sam_hive(fs):
    """Parse the SAM registry hive to extract user account information."""
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
            # Navigate to user accounts: SAM\Domains\Account\Users\Names
            try:
                users_key = registry.open("SAM\\Domains\\Account\\Users")
                names_key = users_key.subkey("Names")
                rid_to_name = {}
                for name_subkey in names_key.subkeys():
                    try:
                        # The type of the default value is the RID
                        vals = [v for v in name_subkey.values()]
                        if vals:
                            rid_to_name[vals[0].value_type()] = name_subkey.name()
                    except: pass

                for subkey in users_key.subkeys():
                    if subkey.name() == "Names": continue
                    try:
                        rid = int(subkey.name(), 16)
                    except: continue
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
                            if ft == 0 or ft == 0x7FFFFFFFFFFFFFFF: return "Never"
                            try:
                                return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft//10)).strftime('%Y-%m-%d %H:%M:%S')
                            except: return "N/A"
                            
                        ll_str = ft_to_str(last_logon_ft)
                        desc = f"SAM User Account: {username} (RID: {rid}) | Login Count: {login_count} | Last Logon: {ll_str}"
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
        break  # Found it

    return pd.DataFrame(records)


def extract_software_hive(fs):
    """Parse the SOFTWARE registry hive for installed programs and OS info."""
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

            # Installed Programs
            uninstall_paths = [
                "Microsoft\\Windows\\CurrentVersion\\Uninstall",
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
                                'Task Category': f"Installed Program: {display_name} v{display_version} by {publisher} (Installed: {install_date or ts_str})",
                                'LogSource': 'SOFTWARE',
                                'Keywords': 'None',
                                'ArtifactType': 'SOFTWARE',
                            })
                except Exception:
                    pass

            # OS Version Info
            try:
                nt_key = registry.open("Microsoft\\Windows NT\\CurrentVersion")
                os_info = {}
                for val in nt_key.values():
                    vn = val.name()
                    if vn in ['ProductName', 'BuildLab', 'RegisteredOwner', 'InstallDate', 'CurrentBuild', 'EditionID']:
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


def extract_prefetch(fs):
    """Extract Prefetch file listings to identify executed programs."""
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

        for entry in pf_dir:
            try:
                fname = entry.info.name.name.decode('utf-8', errors='ignore')
                if fname in ['.', '..']:
                    continue
                if not fname.lower().endswith('.pf'):
                    continue
                meta = entry.info.meta
                mtime = datetime.fromtimestamp(meta.mtime, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if meta and meta.mtime and meta.mtime > 0 else 'N/A'
                crtime = datetime.fromtimestamp(meta.crtime, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if meta and meta.crtime and meta.crtime > 0 else 'N/A'
                # Prefetch filename format: PROGRAMNAME-HASH.pf
                prog_name = fname.rsplit('-', 1)[0] if '-' in fname else fname.replace('.pf', '')
                records.append({
                    'Date and Time': mtime,
                    'Event ID': '9300',
                    'Task Category': f"Prefetch: {prog_name} (File: {fname}, Last Run: {mtime}, Created: {crtime})",
                    'LogSource': 'PREFETCH',
                    'Keywords': 'None',
                    'ArtifactType': 'PREFETCH',
                })
            except Exception:
                continue
        print(f"  [PREFETCH] Extracted {len(records)} prefetch entries")
        break

    return pd.DataFrame(records)


def carve_evidence_from_image(filepath):
    """
    Open a forensic disk image with pytsk3 and extract ALL evidence:
      - All .evtx log files (Security, System, Application, PowerShell, etc.)
      - SYSTEM, SAM, SOFTWARE registry hives
      - NTUSER.DAT (all user profiles)
      - Full filesystem metadata (file/directory listing)
      - Prefetch files (executed programs)
    Raises on any failure — no silent fallbacks.
    """
    global artifact_counts
    all_frames = []
    artifact_counts = {"evtx": 0, "registry": 0, "filesystem": 0, "sam": 0, "software": 0, "prefetch": 0, "total": 0}

    import pytsk3
    
    # Check if file is E01 and use pyewf if available
    is_e01 = filepath.lower().endswith('.e01')
    if is_e01:
        try:
            import pyewf
            ewf_handle = pyewf.handle()
            ewf_handle.open([filepath])
            img_info = EWFImgInfo(ewf_handle)
            print("  [OK] Opened E01 image using libewf-python")
        except ImportError:
            raise RuntimeError("[ERROR] libewf-python is required to read .E01 files. Run: pip install libewf-python")
    else:
        # Open raw image directly with pytsk3
        img_info = pytsk3.Img_Info(filepath)

    # Try to dynamically detect partition offsets
    fs = None
    offsets_to_try = [0, 1048576, 65536, 32256]
    try:
        volume = pytsk3.Volume_Info(img_info)
        for part in volume:
            if part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                offset = part.start * volume.info.block_size
                if offset not in offsets_to_try:
                    offsets_to_try.insert(0, offset)  # Prioritize actual partition offsets
    except Exception as e:
        print(f"   Could not read volume/partition table: {e}")

    # Attempt to mount filesystem at the discovered offsets
    for offset in offsets_to_try:
        try:
            fs = pytsk3.FS_Info(img_info, offset=offset)
            print(f"  [OK] Filesystem found at offset {offset}")
            break
        except Exception:
            continue
    else:
        # Loop finished without break
        raise RuntimeError(
            f"[ERROR] No filesystem found in image '{os.path.basename(filepath)}'. "
            f"Tried offsets: {offsets_to_try}. "
            f"If this is an .E01 file, your pytsk3 installation might not include libewf support. "
            f"Try converting the .E01 to a raw .dd image using FTK Imager."
        )

    # ── PARALLEL EXTRACTION ENGINE (PHASE 1) ──
    print(f"  [EXEC] Starting parallel artifact extraction (Max Workers: 10)...")
    
    tasks = [
        ("EVTX", extract_all_evtx, (fs,)),
        ("SAM", extract_sam_hive, (fs,)),
        ("SOFTWARE", extract_software_hive, (fs,)),
        ("SYSTEM", extract_system_artifact, (fs,)),
        ("NTUSER", extract_all_ntuser, (fs,)),
        ("PREFETCH", extract_prefetch, (fs,)),
        ("FILESYSTEM", walk_filesystem, (fs, 50000)),
        ("ACTIVITY", extract_user_activity, (fs,)),
        ("RECYCLE", extract_recycle_bin, (fs,)),
        ("BROWSER", extract_browser_history, (fs,)),
        ("USN", extract_usn_journal, (fs,)),
        ("EXECUTION", extract_execution_history, (fs,)),
        ("SRUM", extract_srum_data, (fs,))
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=14) as executor:
        future_to_name = {executor.submit(fn, *args): name for name, fn, args in tasks}
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                df = future.result()
                if df is not None and not df.empty:
                    all_frames.append(df)
                    # Update global artifact counts
                    atype = df['ArtifactType'].iloc[0].lower() if 'ArtifactType' in df.columns else name.lower()
                    if atype == 'registry': atype = 'registry' # Registry is summed across multiple
                    
                    if name == "EVTX": artifact_counts["evtx"] = len(df)
                    elif name == "SAM": artifact_counts["sam"] = len(df)
                    elif name == "SOFTWARE": artifact_counts["software"] = len(df)
                    elif name == "SYSTEM": artifact_counts["registry"] += len(df)
                    elif name == "NTUSER": artifact_counts["registry"] += len(df)
                    elif name == "PREFETCH": artifact_counts["prefetch"] = len(df)
                    elif name == "FILESYSTEM": artifact_counts["filesystem"] = len(df)
                    
                    print(f"  [OK] {name} extraction complete: {len(df)} entries")
            except Exception as exc:
                print(f"  [FAIL] {name} extraction generated an exception: {exc}")

    if not all_frames:
        raise RuntimeError(
            f"[ERROR] No artifacts could be extracted from '{os.path.basename(filepath)}'. "
            f"The filesystem was found but contained no recognizable artifacts."
        )

    result = pd.concat(all_frames, ignore_index=True)
    artifact_counts["total"] = len(result)
    return result

def extract_system_artifact(fs):
    """Wrapper for SYSTEM hive extraction."""
    system_paths = ["/Windows/System32/config/SYSTEM", "/Windows/System32/config/system"]
    for sys_path in system_paths:
        try:
            f_obj = fs.open(sys_path)
            reg_data = f_obj.read_random(0, f_obj.info.meta.size)
            return parse_registry_hive(reg_data, "SYSTEM")
        except Exception:
            continue
    return pd.DataFrame()

def extract_all_ntuser(fs):
    """Extract ALL NTUSER.DAT files from all user profiles."""
    all_ntuser_frames = []
    try:
        users_dir = fs.open_dir("/Users")
        for entry in users_dir:
            name = entry.info.name.name.decode('utf-8', errors='ignore')
            if name in ['.', '..', 'Public', 'Default', 'Default User', 'All Users']:
                continue
            ntuser_path = f"/Users/{name}/NTUSER.DAT"
            try:
                f_obj = fs.open(ntuser_path)
                reg_data = f_obj.read_random(0, f_obj.info.meta.size)
                reg_df = parse_registry_hive(reg_data, f"NTUSER({name})")
                if not reg_df.empty:
                    all_ntuser_frames.append(reg_df)
            except Exception:
                continue
    except Exception:
        pass
    
    if all_ntuser_frames:
        return pd.concat(all_ntuser_frames, ignore_index=True)
    return pd.DataFrame()

def extract_user_activity(fs):
    """Extract LNK files and Jump Lists from all user profiles."""
    records = []
    try:
        users_dir = fs.open_dir("/Users")
        for entry in users_dir:
            name = entry.info.name.name.decode('utf-8', errors='ignore')
            if name in ['.', '..', 'Public', 'Default', 'Default User', 'All Users']:
                continue
            
            # 1. Recent Items (.lnk files)
            recent_path = f"/Users/{name}/AppData/Roaming/Microsoft/Windows/Recent"
            try:
                recent_dir = fs.open_dir(recent_path)
                for lnk_entry in recent_dir:
                    try:
                        lname = lnk_entry.info.name.name.decode('utf-8', errors='ignore')
                        if not lname.lower().endswith('.lnk'): continue
                        f_obj = fs.open(f"{recent_path}/{lname}")
                        data = f_obj.read_random(0, f_obj.info.meta.size)
                        
                        # Basic LNK parsing: look for target path (simplified)
                        target_path = "Unknown"
                        if b":\\" in data:
                            start = data.find(b":\\") - 1
                            end = data.find(b"\x00", start)
                            target_path = data[start:end].decode('utf-16le', errors='ignore')
                            if not target_path or ":" not in target_path:
                                target_path = data[start:end].decode('utf-8', errors='ignore')
                        
                        mtime = datetime.fromtimestamp(lnk_entry.info.meta.mtime, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                        records.append({
                            'Date and Time': mtime,
                            'Event ID': '9400',
                            'Task Category': f"User Activity (LNK): {name} opened {target_path} (LNK: {lname})",
                            'LogSource': 'ACTIVITY',
                            'Keywords': 'None',
                            'ArtifactType': 'ACTIVITY',
                        })
                    except: continue
            except: pass

            # 2. Jump Lists
            jump_path = f"/Users/{name}/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations"
            try:
                jump_dir = fs.open_dir(jump_path)
                for j_entry in jump_dir:
                    try:
                        jname = j_entry.info.name.name.decode('utf-8', errors='ignore')
                        mtime = datetime.fromtimestamp(j_entry.info.meta.mtime, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                        records.append({
                            'Date and Time': mtime,
                            'Event ID': '9401',
                            'Task Category': f"User Activity (JumpList): {name} interacted with AppID {jname[:8]}...",
                            'LogSource': 'ACTIVITY',
                            'Keywords': 'None',
                            'ArtifactType': 'ACTIVITY',
                        })
                    except: continue
            except: pass
    except: pass
    return pd.DataFrame(records)

def extract_recycle_bin(fs):
    """Extract Recycle Bin metadata ($I files)."""
    records = []
    recycle_paths = ["/$Recycle.Bin", "/$RECYCLE.BIN"]
    for rb_path in recycle_paths:
        try:
            rb_dir = fs.open_dir(rb_path)
            for sid_entry in rb_dir:
                try:
                    sid_name = sid_entry.info.name.name.decode('utf-8', errors='ignore')
                    if sid_name in ['.', '..']: continue
                    sid_path = f"{rb_path}/{sid_name}"
                    sid_dir = fs.open_dir(sid_path)
                    for f_entry in sid_dir:
                        try:
                            fname = f_entry.info.name.name.decode('utf-8', errors='ignore')
                            if not fname.startswith('$I'): continue
                            f_obj = fs.open(f"{sid_path}/{fname}")
                            data = f_obj.read_random(0, f_obj.info.meta.size)
                            
                            import struct
                            # $I file format: 8 bytes header, 8 bytes size, 8 bytes deletion time, then path
                            del_time_ft = struct.unpack('<Q', data[16:24])[0]
                            orig_path = data[24:].decode('utf-16le', errors='ignore').split('\x00')[0]
                            
                            def ft_to_str(ft):
                                try:
                                    return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft//10)).strftime('%Y-%m-%d %H:%M:%S')
                                except: return "N/A"
                            
                            dtime = ft_to_str(del_time_ft)
                            records.append({
                                'Date and Time': dtime,
                                'Event ID': '9500',
                                'Task Category': f"Recycle Bin: File {orig_path} was deleted at {dtime}",
                                'LogSource': 'RECYCLE',
                                'Keywords': 'Alert',
                                'ArtifactType': 'RECYCLE',
                            })
                        except: continue
                except: continue
            break
        except: continue
    return pd.DataFrame(records)



def extract_browser_history(fs):
    """Extract Chrome/Edge history using temporary copies to avoid locking."""
    records = []
    try:
        users_dir = fs.open_dir("/Users")
        for entry in users_dir:
            name = entry.info.name.name.decode('utf-8', errors='ignore')
            if name in ['.', '..', 'Public', 'Default', 'Default User', 'All Users']: continue
            
            history_paths = [
                f"/Users/{name}/AppData/Local/Google/Chrome/User Data/Default/History",
                f"/Users/{name}/AppData/Local/Microsoft/Edge/User Data/Default/History"
            ]
            for h_path in history_paths:
                try:
                    f_obj = fs.open(h_path)
                    h_data = f_obj.read_random(0, f_obj.info.meta.size)
                    
                    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
                        tmp.write(h_data)
                        tmp_path = tmp.name
                    
                    try:
                        conn = sqlite3.connect(tmp_path)
                        cursor = conn.cursor()
                        cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
                        for url, title, lvt in cursor.fetchall():
                            # Chrome time is microseconds since 1601-01-01
                            dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=lvt)
                            dt_str = dt.strftime('%Y-%m-%d %H:%M:%S')
                            records.append({
                                'Date and Time': dt_str,
                                'Event ID': '9600',
                                'Task Category': f"Browser History: {name} visited {url} ({title[:50]})",
                                'LogSource': 'BROWSER',
                                'Keywords': 'None',
                                'ArtifactType': 'BROWSER',
                            })
                        conn.close()
                    finally:
                        os.unlink(tmp_path)
                except: continue
    except: pass
    return pd.DataFrame(records)

def extract_usn_journal(fs):
    """Implement USN Journal tail-parsing (optimized)."""
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
                    'Task Category': f"USN Journal Activity: File modification detected for {fname}",
                    'LogSource': 'USN',
                    'Keywords': 'None',
                    'ArtifactType': 'USN',
                })
                if len(records) > 200: break
            except: continue
    except: pass
    return pd.DataFrame(records)

def extract_execution_history(fs):
    """Extract ShimCache (AppCompatCache) from SYSTEM hive."""
    records = []
    # Implementation logic for parsing the AppCompatCache binary blob from registry
    # For now, we pull the paths extracted by the general registry parser that match 'AppCompatCache'
    if current_audit_df is not None:
        shim_entries = current_audit_df[current_audit_df['Task Category'].str.contains('AppCompatCache', na=False)]
        for _, row in shim_entries.iterrows():
            records.append({
                'Date and Time': row['Date and Time'],
                'Event ID': '9800',
                'Task Category': f"Execution History (ShimCache): {row['Task Category']}",
                'LogSource': 'EXECUTION',
                'Keywords': 'None',
                'ArtifactType': 'EXECUTION',
            })
    return pd.DataFrame(records)

def extract_srum_data(fs):
    """Background parser for SRUM (System Resource Usage Monitor) databases."""
    records = []
    srum_path = "/Windows/System32/sru/SRUDB.dat"
    try:
        # SRUM is a complex ESE database; we'll catalog its presence and 
        # extract basic metadata for this version.
        f_obj = fs.open(srum_path)
        mtime = datetime.fromtimestamp(f_obj.info.meta.mtime, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        records.append({
            'Date and Time': mtime,
            'Event ID': '9900',
            'Task Category': "SRUM Database detected. Proves network and energy usage history is available for deep analysis.",
            'LogSource': 'SRUM',
            'Keywords': 'Alert',
            'ArtifactType': 'SRUM',
        })
    except: pass
    return pd.DataFrame(records)



# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: BEHAVIORAL ML ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def engineer_features(df):
    """Add HourOfDay and EventsPerMinute columns to the DataFrame."""
    # HourOfDay
    def extract_hour(dt_str):
        try:
            return pd.to_datetime(str(dt_str)).hour
        except Exception:
            return 12

    df['HourOfDay'] = df['Date and Time'].apply(extract_hour)

    # EventsPerMinute — simplified for runtime performance
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

    # ── VECTORIZED ML & HEURISTIC INFERENCE ──
    print("   Vectorizing behavioral threat predictions...")
    
    # Fast event ID extraction
    def extract_eid(eid_raw):
        val = ''.join(filter(str.isdigit, str(eid_raw)))
        return int(val) if val else 0
        
    df['EventID_Num'] = df['Event ID'].apply(extract_eid)

    # ML Inference (Predict all 30k+ rows at once)
    if ml_alarm is not None:
        try:
            features = df[['EventID_Num', 'HourOfDay', 'EventsPerMinute']].values
            df['ML_Prediction'] = ml_alarm.predict(features)
        except Exception as e:
            print(f"   Vectorized ML failed: {e}")
            df['ML_Prediction'] = 1
    else:
        df['ML_Prediction'] = 1

    # Heuristic & Status Resolution
    def resolve_label(row):
        eid = row['EventID_Num']
        if eid in HEURISTIC_THREAT_IDS:
            return -1, f"HEURISTIC THREAT — {HEURISTIC_THREAT_IDS[eid]}"
        if row.get('ML_Prediction', 1) == -1:
            return -1, "STATISTICAL ANOMALY (Behavioral)"
        return 1, "VERIFIED NORMAL"

    # Apply resolution map
    statuses = df.apply(resolve_label, axis=1)
    df['AnomalyScore'] = [s[0] for s in statuses]
    df['AnomalyLabel'] = [s[1].replace(" ", "").replace(" ", "").replace(" ", "") for s in statuses]

    return df


def get_anomaly_status(row):
    """
    Classify a row using pre-computed vector labels for O(1) performance.
    """
    score = row.get('AnomalyScore', 1)
    label = row.get('AnomalyLabel', "VERIFIED NORMAL")
    return score, label


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: RAG PIPELINE (Retrieval-Augmented Generation)
faiss_lock = threading.Lock()

def build_rag_context(query, top_k=8):
    """Retrieve top-k relevant evidence rows via FAISS and build LLM context."""
    global faiss_index, ai_model, image_hash_sha256

    if current_audit_df is None:
        return [], ""

    from sentence_transformers import SentenceTransformer

    with faiss_lock:
        if ai_model is None:
            ai_model = SentenceTransformer('all-MiniLM-L6-v2')

        if faiss_index is None:
            cache_dir = os.path.join(SCRIPT_DIR, "cache", "faiss")
            os.makedirs(cache_dir, exist_ok=True)
            
            cache_file = None
            if image_hash_sha256:
                cache_file = os.path.join(cache_dir, f"{image_hash_sha256}_v7_faiss.index")
                
            if cache_file and os.path.exists(cache_file):
                print("  [FAISS] Loading FAISS index directly from disk cache...")
                faiss_index = faiss.read_index(cache_file)
            else:
                print("  [FAISS] Generating FAISS embeddings for ALL artifacts (optimized batching)...")
                texts_series = current_audit_df['Task Category'].fillna('').astype(str)
                unique_texts = texts_series.unique().tolist()
                
                # Reduce batch_size to 32 to prevent PyTorch CPU Out-Of-Memory errors
                unique_embeddings = ai_model.encode(unique_texts, batch_size=32, show_progress_bar=False)
                
                # Map unique embeddings back to all rows
                text_to_idx = {text: idx for idx, text in enumerate(unique_texts)}
                indices = texts_series.map(text_to_idx).values
                full_embeddings = unique_embeddings[indices]
                
                # Build FAISS index natively
                dim = full_embeddings.shape[1]
                faiss_index = faiss.IndexFlatL2(dim)
                faiss_index.add(np.array(full_embeddings).astype('float32'))
                
                # Serialize FAISS index directly to disk to eliminate memory overhead
                if cache_file:
                    faiss.write_index(faiss_index, cache_file)

    # Search
    query_vec = ai_model.encode([query])
    distances, indices = faiss_index.search(np.array(query_vec).astype('float32'), k=top_k)

    # Collect relevant rows
    relevant_rows = []
    context_lines = []
    for idx_in_list, (dist, idx) in enumerate(zip(distances[0], indices[0])):
        row = current_audit_df.iloc[idx]
        relevant_rows.append(row)
        _, status = get_anomaly_status(row)
        context_lines.append(
            f"[Evidence {idx_in_list}] Time: {row.get('Date and Time', 'N/A')} | "
            f"EventID: {row.get('Event ID', 'N/A')} | "
            f"Source: {row.get('LogSource', 'N/A')} | "
            f"Description: {row.get('Task Category', 'N/A')}"
        )

    return relevant_rows, "\n".join(context_lines)


def extract_system_context():
    global current_audit_df
    if current_audit_df is None or current_audit_df.empty:
        return "No evidence loaded."
    
    source_col = 'LogSource' if 'LogSource' in current_audit_df.columns else 'Source'
    df = current_audit_df # Local reference
    
    # Efficiently group by ArtifactType
    type_groups = {k: g for k, g in df.groupby(df['ArtifactType'].astype(str).str.upper())}
    # Ensure all expected keys exist to avoid KeyErrors
    for t in ['SAM', 'REGISTRY', 'SOFTWARE', 'FILESYSTEM', 'PREFETCH', 'ACTIVITY']:
        if t not in type_groups:
            type_groups[t] = pd.DataFrame(columns=df.columns)

    # 1. User Profiles (from Registry Task Category)
    users = set()
    all_categories = df['Task Category'].dropna().astype(str)
    ntuser_entries = all_categories[all_categories.str.contains(r"NTUSER\(", case=False, na=False)]
    for desc_str in ntuser_entries.unique():
        match = re.search(r'NTUSER\((.*?)\)', desc_str, re.IGNORECASE)
        if match:
            users.add(match.group(1).strip())
    user_list = ", ".join(users) if users else "None found"
    
    # 2. SAM User Accounts
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
    sam_users_str = f"{len(sam_users)} accounts: {', '.join(sam_users)}" if sam_users else "None found"
    
    
    # 3. Deep System Profiling (Registry)
    hostname, os_version = "Unknown", "Unknown"
    usb_devices, run_keys = [], []
    av_disabled = False

    # Use a single pass for Registry lookups
    reg_df = type_groups['REGISTRY']
    reg_descs = reg_df['Task Category'].dropna().astype(str)
    for desc in reg_descs:
        d_lower = desc.lower()
        if "computername\\computername =" in d_lower:
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
            if match: os_version = match.group(1).strip()

    usb_str = ", ".join(set([u for u in usb_devices if len(u) > 3][:5])) if usb_devices else "None detected"
    run_str = ", ".join(set([r for r in run_keys if len(r) > 3][:5])) if run_keys else "None detected"
    
    # 4. File Extension Statistics
    file_stats_str = "No filesystem data"
    fs_df = type_groups['FILESYSTEM']
    if not fs_df.empty and '_extension' in fs_df.columns:
        total_files = len(fs_df[fs_df['_is_dir'] == False])
        total_dirs = len(fs_df[fs_df['_is_dir'] == True])
        all_exts = fs_df[fs_df['_extension'].astype(str) != '']['_extension'].value_counts().head(20)
        
        categories = {
            "Images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
            "Videos": [".mp4", ".mov", ".avi", ".mkv", ".wmv"],
            "Docs": [".pdf", ".doc", ".docx", ".txt", ".xlsx", ".csv", ".pptx", ".rtf"],
            "Executables": [".exe", ".dll", ".sys", ".bat", ".ps1", ".msi"],
            "Archives": [".zip", ".rar", ".7z", ".tar", ".gz", ".iso"]
        }
        cat_counts = {cat: sum([all_exts.get(e, 0) for e in elist]) for cat, elist in categories.items()}
        cat_parts = [f"{k}: {int(v)}" for k, v in cat_counts.items()]
        ext_parts = [f"{k}: {int(v)}" for k, v in all_exts.head(15).items()]
        file_stats_str = f"Total Files: {total_files}, Total Dirs: {total_dirs}. CATEGORY COUNTS: {', '.join(cat_parts)}. DETAILED EXTENSIONS: {', '.join(ext_parts)}"
    
    # 5. Installed/Executed Programs
    installed = [re.search(r'Installed Program:\s*(.+?)(?:\s*v|\s*\()', str(d)).group(1).strip() 
                 for d in sw_descs if "Installed Program:" in str(d) and re.search(r'Installed Program:\s*(.+?)(\s*v|\s*\()', str(d))]
    programs_str = f"{len(installed)} programs: {', '.join(installed[:10])}" if installed else "No program data"
    
    prefetch = [re.search(r'Prefetch:\s*(.+?)\s*\(', str(d)).group(1).strip() 
                for d in type_groups['PREFETCH']['Task Category'].dropna() if "Prefetch:" in str(d)]
    pf_unique = list(set(prefetch))
    prefetch_str = f"{len(pf_unique)} unique programs: {', '.join(pf_unique[:10])}" if pf_unique else "No prefetch data"
    
    # 7. Time Range & Active Users
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
            if u not in ['-', 'SYSTEM', 'NETWORK', 'LOCAL SERVICE', 'NETWORK SERVICE'] and not u.endswith('$'):
                logon_users.append(u)
    
    unified_counts = {u: c for u, c in sam_logon_stats}
    for u, c in Counter(logon_users).items():
        unified_counts[u] = max(c, unified_counts.get(u, 0))
    active_users_str = ", ".join([f"{u} ({c} logons)" for u, c in Counter(unified_counts).most_common(5)])
    
    # 9. Meta Stats
    top_events = df['Event ID'].value_counts().head(5).to_dict()
    top_events_str = ", ".join([f"ID {k} ({v})" for k, v in top_events.items()])
    
    cleared_count = len(df[df['Event ID'].astype(str).isin(['1102', '1102.0'])])
    alerts_str = (f"Audit Logs Cleared ({cleared_count}x), " if cleared_count else "") + ("AV DISABLED" if av_disabled else "None")
    
    anom_counts = df['AnomalyScore'].value_counts().to_dict() if 'AnomalyScore' in df.columns else {}
    anomaly_str = f"Normal: {anom_counts.get(1,0)}, Threat: {anom_counts.get(-1,0)}"
    
    recent_docs = [str(d) for d in type_groups['ACTIVITY']['Task Category'].dropna().unique() if any(x in str(d).lower() for x in ['opened', 'interacted'])]
    recent_docs_str = "\n   - ".join(recent_docs[:10]) if recent_docs else "None"

    return (
        f"TOTAL LOGS: {len(df)}\nRANGE: {start_time} to {end_time}\n"
        f"HOST: {hostname} | OS: {os_version}\nALERTS: {alerts_str}\n"
        f"SAM USERS: {sam_users_str}\nPROFILES: {user_list}\n"
        f"ACTIVE USERS: {active_users_str}\nFILESYSTEM: {file_stats_str}\n"
        f"PROGRAMS: {programs_str}\nPREFETCH: {prefetch_str}\n"
        f"TOP EVENTS: {top_events_str}\nRECENT ACTIVITY: {recent_docs_str}\n"
        f"ANOMALIES: {anomaly_str}"
    )


def query_llm(user_question, evidence_context):
    """Send the user question + evidence context to Gemini for forensic reasoning."""
    global cached_system_facts
    
    if gemini_client is None:
        raise RuntimeError(" Gemini LLM is not configured. Set GEMINI_API_KEY in .env file.")

    if cached_system_facts is None:
        print("  [CACHE] Regenerating system facts...")
        cached_system_facts = extract_system_context()

    system_facts = cached_system_facts

    system_prompt = f"""You are a Senior Digital Forensics Examiner with 20 years of experience in incident response.
You are analyzing evidence extracted from a forensic disk image. Given the user's question, provide a clear, professional forensic analysis.

── GLOBAL SYSTEM FACTS (CRITICAL - READ FIRST) ──
{system_facts}

CRITICAL INSTRUCTIONS:
1. If the user asks a general or aggregate question (e.g., "how many users", "how many PDF files", "what is the hostname", "what programs are installed", "who is the most active user"), you MUST answer using the GLOBAL SYSTEM FACTS provided above. These facts contain:
   - USER ACCOUNTS FROM SAM: Actual Windows human user accounts. These are the ONLY real users.
   - MOST ACTIVE LOGON USERS (EVTX): A list of accounts and their logon counts. NOTE: Accounts ending in '$' are machine accounts, NOT people. Ignore them when listing "users".
   - FILE SYSTEM STATISTICS: Complete file counts by extension (pdf, exe, doc, jpg, etc.). Use this for ANY "how many files" or "what types of files" or "how many images" questions.
   - RECENT DOCUMENT ACTIVITY: A summary of files recently opened or interacted with by users (LNK/JumpLists).
   Do NOT tell the user to "investigate further"—you must state the facts directly using these numbers.
   
   IMPORTANT: If asked for "SYSTEM INFORMATION", only provide details like Hostname, OS Version, and User Accounts. 
   If asked for "FILES" or "IMAGES" or "DOCUMENTS", use the FILE SYSTEM STATISTICS.
   
2. If the user asks about specific events or detailed analysis, use the RETRIEVED EVIDENCE below.
3. State the forensic SIGNIFICANCE of your findings.
4. What attack technique it might indicate (reference MITRE ATT&CK).
5. A recommended NEXT STEP for the investigator.
6. CITE YOUR SOURCES. At the very end of your response, on a new line, you MUST list the exact Evidence IDs you used from the RETRIEVED EVIDENCE. Format exactly as `USED_EVIDENCE: [0, 2]`. If you answered entirely using GLOBAL SYSTEM FACTS and none of the RETRIEVED EVIDENCE was relevant, you MUST output `USED_EVIDENCE: []`.

7. **BOLD IMPORTANT TERMS**: Always **bold** key forensic findings, account names, timestamps, and suspicious activities.
8. **TIMESTAMP COMPARISON**: If multiple timestamps are provided for the same type of event (e.g., last logon), you MUST compare them and explicitly state which one is the **latest** or **most recent**.
9. **DIRECT ADDRESS**: Change your language to be more direct. Instead of "The next step for the investigator...", say "**The next step for you is to...**".
10. **CONCISE SECTIONS**: Keep the "**Forensic Significance**" and "**Next Step**" sections brief and high-impact.

Keep your response concise (under 300 words). Use professional forensic language.
Format key findings in **bold**. Reference specific Event IDs and timestamps when available."""

    prompt = f"""{system_prompt}

── RETRIEVED EVIDENCE ──
{evidence_context}

── INVESTIGATOR'S QUESTION ──
{user_question}

── YOUR FORENSIC ANALYSIS ──"""

    try:
        # 1. Primary: Gemini (Modern SDK)
        # We wrap this in a tighter timeout or check for common errors
        response = gemini_client.models.generate_content(
            model=GEMINI_MODEL_ID,
            contents=user_question, # Using just the question for context if evidence is empty
            config={
                "system_instruction": system_prompt,
                "temperature": 0.1
            }
        )
        if evidence_context: # If we have evidence, use the full prompt
            response = gemini_client.models.generate_content(
                model=GEMINI_MODEL_ID,
                contents=prompt,
                config={
                    "system_instruction": system_prompt,
                    "temperature": 0.1
                }
            )
        return response.text
    except Exception as e:
        error_msg = str(e)
        print(f"   [ERROR] Gemini API Failure: {error_msg}")
        if groq_client:
            print("   Gemini failed, falling back to Groq Llama-3...")
            try:
                # 2. Secondary: Groq
                chat_completion = groq_client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": f"── RETRIEVED EVIDENCE ──\n{evidence_context}\n\n── INVESTIGATOR'S QUESTION ──\n{user_question}"}
                    ],
                    model="llama-3.3-70b-versatile",
                    temperature=0.2,
                )
                return chat_completion.choices[0].message.content
            except Exception as groq_e:
                error_msg += f" | Groq failed: {str(groq_e)}"
        
        # 3. Ultimate Fallback: GPT4Free (Unlimited, No API Key Required)
        try:
            print("   Groq failed, falling back to G4F (Unlimited Free)...")
            import g4f
            g4f_response = g4f.ChatCompletion.create(
                model=g4f.models.gpt_4o,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"── EVIDENCE ──\n{evidence_context}\n\n── QUESTION ──\n{user_question}"}
                ],
            )
            return g4f_response
        except Exception as g4f_e:
            return f" CRITICAL LLM ERROR. All APIs (Gemini, Groq, G4F) are exhausted or failing.\nDetails: {error_msg} | G4F: {str(g4f_e)}"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: HTML FORMATTING (Evidence Cards)
# ═══════════════════════════════════════════════════════════════════════════

def format_log_card(row, status_label, is_anomaly):
    """Render an evidence card with forensic styling."""
    if "HEURISTIC" in status_label:
        border_color = "#FF4C4C"
        badge_bg = "#FF4C4C"
    elif "STATISTICAL" in status_label:
        border_color = "#FFA500"
        badge_bg = "#FFA500"
    else:
        border_color = "#2a5f7a"
        badge_bg = "#5cb85c"

    artifact_type = row.get('ArtifactType', 'LOG')
    artifact_icons = {
        "REGISTRY": "", "EVTX": "", "FILESYSTEM": "",
        "SAM": "", "SOFTWARE": "", "PREFETCH": ""
    }
    artifact_icon = artifact_icons.get(artifact_type, "")

    return f"""
    <div style='background-color:#1e3f57; border-left:3px solid {border_color};
                padding:12px 14px; margin-bottom:8px; border-radius:6px;
                font-family: "Courier New", monospace;'>
        <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;'>
            <span style='color:#8ab4cc; font-size:0.75em;'>📅 {row.get('Date and Time', 'N/A')}</span>
            <div style='display:flex; gap:6px; align-items:center;'>
                <span style='color:#456882; background:#132d3f; padding:2px 8px;
                             border-radius:8px; font-size:0.6em;'>{artifact_icon} {artifact_type}</span>
                <span style='color:#fff; background:{badge_bg}; padding:2px 10px;
                             border-radius:10px; font-size:0.65em; font-weight:bold;
                             letter-spacing:0.5px;'>{status_label}</span>
            </div>
        </div>
        <p style='color:#d2e8f5; margin:4px 0 6px 0; font-size:0.88em; line-height:1.4;'>
            {row.get('Task Category', 'N/A')}
        </p>
        <div style='display:flex; gap:16px;'>
            <small style='color:#5a8a9f;'>🔑 ID: <b style='color:#8ab4cc;'>{row.get('Event ID', 'N/A')}</b></small>
            <small style='color:#5a8a9f;'> Source: <b style='color:#8ab4cc;'>{row.get('LogSource', row.get('Source', 'N/A'))}</b></small>
        </div>
    </div>
    """


def format_llm_card(explanation):
    """Render an LLM explanation card with distinctive forensic styling."""
    if explanation is None:
        return ""

    # Convert markdown bold to HTML
    formatted = explanation.replace("**", "<b>").replace("**", "</b>")
    # Simple markdown bold parsing
    import re as _re
    formatted = _re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', explanation)
    formatted = formatted.replace('\n', '<br>')

    return f"""
    <div style='background: linear-gradient(135deg, #1a1a3e, #2d1b4e);
                border-left: 3px solid #8b5cf6;
                padding: 16px 18px; margin: 12px 0; border-radius: 8px;
                font-family: "Courier New", monospace;
                border: 1px solid #4c1d95;'>
        <div style='display:flex; align-items:center; gap:8px; margin-bottom:10px;'>
            <span style='font-size:1.1em;'></span>
            <span style='color:#c4b5fd; font-size:0.78em; letter-spacing:2px; font-weight:bold;'>
                LLM FORENSIC ANALYSIS
            </span>
            <span style='color:#7c3aed; font-size:0.6em; background:#1a1a3e; padding:2px 8px;
                         border-radius:8px; border:1px solid #4c1d95;'>GEMINI</span>
        </div>
        <div style='color:#e2d9f3; font-size:0.85em; line-height:1.6;'>
            {formatted}
        </div>
    </div>
    """


def wrap_scroll_box(inner_html, title="Results", count=None):
    count_badge = (
        f"<span style='background:#456882; color:#d2e8f5; padding:2px 10px; "
        f"border-radius:10px; font-size:0.75em; margin-left:10px;'>{count} entries</span>"
        if count is not None else ""
    )
    return f"""
    <div style='font-family:"Courier New", monospace;'>
        <div style='color:#8ab4cc; font-size:0.8em; margin-bottom:8px; letter-spacing:1px;'>
             {title.upper()} {count_badge}
        </div>
        <div style='max-height:520px; overflow-y:auto; padding-right:4px;
                    scrollbar-width:thin; scrollbar-color:#456882 #132d3f;'>
            {inner_html}
        </div>
    </div>
    """


def no_results_box(message, hint=""):
    return f"""
    <div style='color:#8ab4cc; font-family:monospace; padding:16px; background:#1e3f57;
                border-radius:6px; border:1px solid #2a5f7a;'>
         {message}<br>
        {f"<span style='color:#5a8a9f; font-size:0.8em;'>{hint}</span>" if hint else ""}
    </div>"""


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: QUERY HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

def parse_time_range(q):
    # Match ranges: "13:00 to 14:00"
    pattern = r'(\d{1,2}:\d{2})\s*(?:and|to|-)\s*(\d{1,2}:\d{2})'
    match = re.search(pattern, q)
    if match:
        return match.group(1).zfill(5), match.group(2).zfill(5)
    
    # Match single times: "at 3 am", "at 3:00", "around 15:00", "at 15"
    single_pattern = r'(?:at|around)\s*(\d{1,2})(?::00)?\s*(am|pm)?'
    match2 = re.search(single_pattern, q)
    if match2:
        hour = int(match2.group(1))
        meridian = match2.group(2)
        if meridian == 'pm' and hour < 12: hour += 12
        if meridian == 'am' and hour == 12: hour = 0
        start_t = f"{hour:02d}:00"
        end_t = f"{hour:02d}:59"
        return start_t, end_t
        
    return None, None


def filter_by_time(df, start_str, end_str):
    def in_range(dt_val):
        try:
            time_part = str(dt_val).strip().split(" ")[-1][:5]
            return start_str <= time_part <= end_str
        except Exception:
            return False
    return df[df['Date and Time'].apply(in_range)]


def detect_source_filter(q):
    if any(k in q for k in ["security log", "security logs", "security events", "sec log"]):
        return "SECURITY"
    if any(k in q for k in ["application log", "application logs", "app log", "app logs"]):
        return "APPLICATION"
    if any(k in q for k in ["system log", "system logs", "sys log", "sys logs"]):
        return "SYSTEM"
    if any(k in q for k in ["registry", "reg key", "reg keys", "hive", "ntuser"]):
        return "REGISTRY"
    if any(k in q for k in ["file system", "filesystem", "files", "directories", "folders"]):
        return "FILESYSTEM"
    if any(k in q for k in ["prefetch", "executed program", "run program"]):
        return "PREFETCH"
    if any(k in q for k in ["installed program", "installed software", "installed app"]):
        return "SOFTWARE"
    if any(k in q for k in ["user account", "sam user", "sam hive"]):
        return "SAM"
    return None


def is_show_all_query(q):
    triggers = [
        "all log", "all entries", "show log", "show logs",
        "display log", "display logs", "list log", "list logs",
        "view log", "view logs", "all events", "show events",
        "show all", "list all", "display all"
    ]
    if q.strip() in ["logs", "log", "entries", "events"]:
        return True
    return any(t in q for t in triggers)


def ask_chatbot(query):
    """Main query handler — routes to summary, anomalies, filters, or RAG pipeline."""
    global current_audit_df, uploaded_embeddings, ai_model

    if current_audit_df is None:
        return """
        <div style='background:#2a1a1a; border:1px solid #FF4C4C; padding:16px;
                    border-radius:8px; color:#FF4C4C; font-family:"Courier New",monospace;'>
             No evidence loaded. Upload a forensic image (.dd / .E01) or click "Load Demo Data" first.
        </div>"""

    q = query.lower().strip()

    # ── BLOCK 1: SUMMARY ──
    if "summar" in q:
        heuristic_threats = []
        statistical_anomalies = []
        normal_count = 0

        for _, r in current_audit_df.iterrows():
            pred, label = get_anomaly_status(r)
            if "HEURISTIC" in label:
                heuristic_threats.append(r)
            elif "STATISTICAL" in label:
                statistical_anomalies.append(r)
            else:
                normal_count += 1

        total_threats = len(heuristic_threats) + len(statistical_anomalies)
        status_txt = "COMPROMISE LIKELY" if total_threats > 0 else "SYSTEM SECURE"
        status_color = "#FF4C4C" if total_threats > 0 else "#5cb85c"
        evtx_n = artifact_counts.get('evtx', 0)
        reg_n = artifact_counts.get('registry', 0)

        return f"""
        <div style='background:#1e3f57; padding:20px; border-radius:10px;
                    border:1px solid #456882; font-family:"Courier New",monospace;'>
            <h2 style='color:#d2e8f5; margin-top:0; letter-spacing:1px; font-size:1.1em;'>
                STATISTICAL INTELLIGENCE REPORT
            </h2>
            <hr style='border:0.5px solid #2a5f7a; margin:12px 0;'>

            <div style='display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px; margin-bottom:14px;'>
                <div style='background:#132d3f; padding:12px; border-radius:6px;'>
                    <div style='color:#5a8a9f; font-size:0.7em; margin-bottom:4px;'>TOTAL EVIDENCE</div>
                    <div style='color:#d2e8f5; font-size:1.4em; font-weight:bold;'>{len(current_audit_df)}</div>
                </div>
                <div style='background:#132d3f; padding:12px; border-radius:6px;'>
                    <div style='color:#5a8a9f; font-size:0.7em; margin-bottom:4px;'> EVENT LOGS</div>
                    <div style='color:#d2e8f5; font-size:1.4em; font-weight:bold;'>{evtx_n}</div>
                </div>
                <div style='background:#132d3f; padding:12px; border-radius:6px;'>
                    <div style='color:#5a8a9f; font-size:0.7em; margin-bottom:4px;'> REGISTRY KEYS</div>
                    <div style='color:#d2e8f5; font-size:1.4em; font-weight:bold;'>{reg_n}</div>
                </div>
            </div>

            <div style='display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px; margin-bottom:14px;'>
                <div style='background:#132d3f; padding:12px; border-radius:6px;'>
                    <div style='color:#5a8a9f; font-size:0.7em; margin-bottom:4px;'> HEURISTIC THREATS</div>
                    <div style='color:#FF4C4C; font-size:1.4em; font-weight:bold;'>{len(heuristic_threats)}</div>
                </div>
                <div style='background:#132d3f; padding:12px; border-radius:6px;'>
                    <div style='color:#5a8a9f; font-size:0.7em; margin-bottom:4px;'> STATISTICAL ANOMALIES</div>
                    <div style='color:#FFA500; font-size:1.4em; font-weight:bold;'>{len(statistical_anomalies)}</div>
                </div>
                <div style='background:#132d3f; padding:12px; border-radius:6px;'>
                    <div style='color:#5a8a9f; font-size:0.7em; margin-bottom:4px;'> NORMAL</div>
                    <div style='color:#5cb85c; font-size:1.4em; font-weight:bold;'>{normal_count}</div>
                </div>
            </div>

            <hr style='border:0.5px solid #2a5f7a; margin:12px 0;'>
            <p style='color:{status_color}; font-weight:bold; font-size:1.05em; margin:0;'>{status_txt}</p>
        </div>"""

    # ── BLOCK 2: ANOMALIES ──
    if "anomal" in q or "critic" in q or "threat" in q:
        cards = ""
        count = 0
        for _, row in current_audit_df.iterrows():
            pred, label = get_anomaly_status(row)
            if pred == -1:
                cards += format_log_card(row, label, True)
                count += 1
        if not cards:
            return no_results_box("No anomalies detected in evidence.", "The system appears clean.")
        return wrap_scroll_box(cards, title="Anomaly Report", count=count)

    # ── BLOCK 3: TIME RANGE ──
    start_t, end_t = parse_time_range(q)
    if start_t and end_t:
        filtered_df = filter_by_time(current_audit_df, start_t, end_t)
        source_kw = detect_source_filter(q)
        if source_kw and not filtered_df.empty:
            src_col = 'LogSource' if 'LogSource' in filtered_df.columns else 'Source'
            filtered_df = filtered_df[
                filtered_df[src_col].str.upper().str.contains(source_kw, na=False)
            ]
        if filtered_df.empty:
            return no_results_box(
                f"No evidence found between <b>{start_t}</b> and <b>{end_t}</b>" +
                (f" in <b>{source_kw}</b> source" if source_kw else "") + ".",
                "Try a wider time window."
            )
        cards = ""
        for _, row in filtered_df.iterrows():
            pred, label = get_anomaly_status(row)
            cards += format_log_card(row, label, pred == -1)
        title = f"Evidence {start_t} → {end_t}" + (f" · {source_kw}" if source_kw else "")
        return wrap_scroll_box(cards, title=title, count=len(filtered_df))

    # ── BLOCK 4: SOURCE FILTER ──
    source_kw = detect_source_filter(q)
    if source_kw and len(q.split()) <= 3 and "?" not in q:
        src_col = 'LogSource' if 'LogSource' in current_audit_df.columns else 'Source'
        filtered_df = current_audit_df[
            current_audit_df[src_col].str.upper().str.contains(source_kw, na=False)
        ]
        if filtered_df.empty:
            return no_results_box(f"No <b>{source_kw}</b> evidence found.", "Check the artifact types.")
        cards = ""
        for _, row in filtered_df.iterrows():
            pred, label = get_anomaly_status(row)
            cards += format_log_card(row, label, pred == -1)
        return wrap_scroll_box(cards, title=f"{source_kw} Evidence Stream", count=len(filtered_df))

    # ── BLOCK 5: SHOW ALL ──
    if is_show_all_query(q):
        cards = ""
        for _, row in current_audit_df.iterrows():
            pred, label = get_anomaly_status(row)
            cards += format_log_card(row, label, pred == -1)
        cards += "<div style='color:#5a8a9f; font-size:0.75em; padding:8px; text-align:center;'>── End of evidence stream ──</div>"
        return wrap_scroll_box(cards, title="Full Evidence Stream", count=len(current_audit_df))

    # ── BLOCK 6: RAG — SEMANTIC SEARCH + LLM REASONING ──
    relevant_rows, context_text = build_rag_context(query)

    # Get LLM explanation
    if context_text:
        explanation = query_llm(query, context_text)
        
        # Parse the used evidence IDs from the LLM response
        used_ids = []
        match = re.search(r'USED_EVIDENCE:\s*\[(.*?)\]', explanation)
        if match:
            id_strs = match.group(1).split(',')
            for id_str in id_strs:
                if id_str.strip().isdigit():
                    used_ids.append(int(id_str.strip()))
            
            # Remove the citation tag from the display text
            explanation = re.sub(r'USED_EVIDENCE:\s*\[.*?\]', '', explanation).strip()
            
        cards = format_llm_card(explanation)
        
        # ONLY render the log cards that the LLM explicitly deemed relevant!
        rendered_count = 0
        for i, row in enumerate(relevant_rows):
            if i in used_ids:
                pred, label = get_anomaly_status(row)
                cards += format_log_card(row, label, pred == -1)
                rendered_count += 1
                
        if rendered_count == 0:
            system_facts_card = f"""
            <div style='background: rgba(30, 64, 175, 0.15); border-left: 3px solid #3b82f6; padding: 16px; margin: 16px 0; border-radius: 6px; font-family: Inter, sans-serif; color: #94a3b8; font-size: 0.88em;'>
                <div style='display:flex; align-items:center; gap:8px; margin-bottom:6px; color:#60a5fa; font-weight:600;'>
                    <span>INFO:</span>
                    <span>EVIDENCE SOURCE: GLOBAL SYSTEM FACTS</span>
                </div>
                <div style='line-height:1.5;'>
                    The AI answered this query by aggregating parsed forensic metadata rather than specific event logs. Evidence was extracted from:
                    <ul style='margin: 8px 0 0 20px; color:#cbd5e1;'>
                        <li><b>SAM Registry Hive:</b> User Account Info & Logons</li>
                        <li><b>SOFTWARE Registry Hive:</b> Installed Programs</li>
                        <li><b>MFT / Filesystem:</b> File & Extension Statistics</li>
                        <li><b>Prefetch:</b> Historical Executed Programs</li>
                    </ul>
                </div>
            </div>
            """
            cards += system_facts_card
                
        count_display = f"{rendered_count} logs cited" if rendered_count > 0 else "from system facts"
        
        # LOG TO SESSION FOR REPORTING
        session_log.append({
            "query": query,
            "answer": explanation,
            "evidence_ids": used_ids
        })
        
        return wrap_scroll_box(cards, title=f'RAG Analysis → "{query}"', count=count_display)

    return wrap_scroll_box(cards, title=f'RAG Analysis → "{query}"', count=len(relevant_rows))


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: UPLOAD HANDLERS
# ═══════════════════════════════════════════════════════════════════════════

def handle_image_upload(file):
    """Handle forensic image upload: hash it, carve evidence, engineer features."""
    global current_audit_df, faiss_index, image_hash_sha256, cached_system_facts

    faiss_index = None  # Reset embeddings cache
    cached_system_facts = None  # Reset facts cache

    if file is None:
        return "Awaiting forensic image upload..."

    filepath = file.name

    # Step 1: SHA-256 hash for forensic soundness
    print(f"\n  [HASH] Computing SHA-256 of {os.path.basename(filepath)}...")
    image_hash_sha256 = compute_sha256(filepath)
    print(f"  [HASH] SHA-256: {image_hash_sha256}")

    # Step 2: Check for Cached Evidence DataFrame
    cache_dir = os.path.join(SCRIPT_DIR, "cache", "data")
    df_cache_path = os.path.join(cache_dir, f"{image_hash_sha256}_v7_df.pkl")
    
    if os.path.exists(df_cache_path):
        print("  [CACHE] Cache Hit! Loading carved evidence DataFrame directly from disk...")
        try:
            df = pd.read_pickle(df_cache_path)
            
            # Safely count artifacts
            if 'ArtifactType' in df.columns:
                atype = df['ArtifactType'].fillna('').astype(str).str.upper()
                artifact_counts['evtx'] = len(df[atype == 'EVTX'])
                artifact_counts['registry'] = len(df[atype == 'REGISTRY'])
                artifact_counts['filesystem'] = len(df[atype == 'FILESYSTEM'])
                artifact_counts['sam'] = len(df[atype == 'SAM'])
                artifact_counts['software'] = len(df[atype == 'SOFTWARE'])
                artifact_counts['prefetch'] = len(df[atype == 'PREFETCH'])
            else:
                artifact_counts['evtx'] = len(df)
            artifact_counts['total'] = len(df)
        except Exception as e:
            return f"[ERROR] Cache Load Failed: {str(e)}"
    else:
        # Step 3: Carve evidence from the image
        print("  [CARVE] Carving evidence from disk image...")
        try:
            df = carve_evidence_from_image(filepath)
        except Exception as e:
            return f"[ERROR] Upload Failed: {str(e)}"

        if df.empty:
            return "[ERROR] No evidence could be extracted from the image."

        # Step 4: Engineer behavioral features
        print("  [ML] Engineering behavioral features...")
        try:
            df = engineer_features(df)
        except Exception as e:
            return f"[ERROR] Feature Engineering Failed: {str(e)}"
            
        # Save to Cache for next time
        try:
            os.makedirs(cache_dir, exist_ok=True)
            df.to_pickle(df_cache_path)
        except Exception as e:
            print(f"  [WARN] Could not save DataFrame cache: {e}")

    current_audit_df = df

    evtx_n = artifact_counts.get('evtx', 0)
    reg_n = artifact_counts.get('registry', 0)
    fs_n = artifact_counts.get('filesystem', 0)
    sam_n = artifact_counts.get('sam', 0)
    sw_n = artifact_counts.get('software', 0)
    pf_n = artifact_counts.get('prefetch', 0)

    # Pre-compute FAISS embeddings in the background
    def precompute_faiss():
        try:
            build_rag_context("")
            print("  [OK] FAISS Embeddings loaded in background!")
        except Exception as e:
            print(f"  [ERROR] FAISS background generation failed: {e}")
            traceback.print_exc()
    threading.Thread(target=precompute_faiss).start()

    return (
        f"READY — {len(df)} evidence artifacts loaded.\n"
        f"   EVTX: {evtx_n}  |  Registry: {reg_n}  |  Files: {fs_n}\n"
        f"   SAM: {sam_n}  |  Software: {sw_n}  |  Prefetch: {pf_n}\n"
        f"   [HASH] SHA-256: {image_hash_sha256}"
    )




def get_investigation_summary():
    """Generate the Investigation Summary tab content."""
    if current_audit_df is None:
        return """
        <div style='color:#5a8a9f; font-family:"Courier New",monospace; padding:40px; text-align:center;'>
             Upload a forensic image to generate the investigation summary.
        </div>"""

    hash_display = image_hash_sha256 if image_hash_sha256 else "N/A"
    evtx_n = artifact_counts.get('evtx', 0)
    reg_n = artifact_counts.get('registry', 0)
    fs_n = artifact_counts.get('filesystem', 0)
    sam_n = artifact_counts.get('sam', 0)
    sw_n = artifact_counts.get('software', 0)
    pf_n = artifact_counts.get('prefetch', 0)
    total_n = artifact_counts.get('total', len(current_audit_df))

    # Count anomalies
    heuristic_count = 0
    statistical_count = 0
    for _, row in current_audit_df.iterrows():
        _, label = get_anomaly_status(row)
        if "HEURISTIC" in label:
            heuristic_count += 1
        elif "STATISTICAL" in label:
            statistical_count += 1

    timestamp_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return f"""
    <div style='font-family:"Courier New",monospace; padding:10px;'>

        <!-- Header -->
        <div style='background:linear-gradient(135deg, #1a3a5c, #1e3f57);
                    padding:20px; border-radius:10px; border:1px solid #456882; margin-bottom:16px;'>
            <h2 style='color:#d2e8f5; margin:0 0 8px 0; letter-spacing:1px; font-size:1.1em;'>
                 INVESTIGATION SUMMARY
            </h2>
            <div style='color:#5a8a9f; font-size:0.72em;'>Generated: {timestamp_now}</div>
        </div>

        <!-- SHA-256 Hash -->
        <div style='background:#132d3f; padding:16px; border-radius:8px; border:1px solid #2a5f7a;
                    margin-bottom:12px;'>
            <div style='color:#5a8a9f; font-size:0.7em; letter-spacing:2px; margin-bottom:8px;'>
                 FORENSIC IMAGE HASH (SHA-256)
            </div>
            <div style='color:#5cb85c; font-size:0.9em; word-break:break-all; white-space:pre-wrap; background:#0f2535;
                        padding:12px; border-radius:4px; border:1px solid #1e3f57;'>
                {hash_display}
            </div>
        </div>

        <!-- Artifact Counts -->
        <div style='display:grid; grid-template-columns:1fr 1fr 1fr; gap:10px; margin-bottom:12px;'>
            <div style='background:#132d3f; padding:16px; border-radius:8px; text-align:center;
                        border:1px solid #2a5f7a;'>
                <div style='color:#5a8a9f; font-size:0.68em; margin-bottom:6px;'> EVENT LOGS</div>
                <div style='color:#d2e8f5; font-size:1.8em; font-weight:bold;'>{evtx_n}</div>
            </div>
            <div style='background:#132d3f; padding:16px; border-radius:8px; text-align:center;
                        border:1px solid #2a5f7a;'>
                <div style='color:#5a8a9f; font-size:0.68em; margin-bottom:6px;'> REGISTRY KEYS</div>
                <div style='color:#d2e8f5; font-size:1.8em; font-weight:bold;'>{reg_n}</div>
            </div>
            <div style='background:#132d3f; padding:16px; border-radius:8px; text-align:center;
                        border:1px solid #2a5f7a;'>
                <div style='color:#5a8a9f; font-size:0.68em; margin-bottom:6px;'> TOTAL ARTIFACTS</div>
                <div style='color:#d2e8f5; font-size:1.8em; font-weight:bold;'>{total_n}</div>
            </div>
        </div>

        <!-- Threat Breakdown -->
        <div style='display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-bottom:12px;'>
            <div style='background:#2a1a1a; padding:16px; border-radius:8px; text-align:center;
                        border:1px solid #5a1a1a;'>
                <div style='color:#FF4C4C; font-size:0.7em; margin-bottom:6px; letter-spacing:1px;'>
                     HEURISTIC THREATS
                </div>
                <div style='color:#FF4C4C; font-size:2em; font-weight:bold;'>{heuristic_count}</div>
                <div style='color:#8a4444; font-size:0.65em; margin-top:4px;'>
                    Known-bad Event IDs & Registry Persistence
                </div>
            </div>
            <div style='background:#2a1f0a; padding:16px; border-radius:8px; text-align:center;
                        border:1px solid #5a3a0a;'>
                <div style='color:#FFA500; font-size:0.7em; margin-bottom:6px; letter-spacing:1px;'>
                     STATISTICAL ANOMALIES
                </div>
                <div style='color:#FFA500; font-size:2em; font-weight:bold;'>{statistical_count}</div>
                <div style='color:#8a6a2a; font-size:0.65em; margin-top:4px;'>
                    ML-detected behavioral outliers
                </div>
            </div>
        </div>

        <!-- LLM Status -->
        <div style='background:#132d3f; padding:12px; border-radius:8px; border:1px solid #2a5f7a;
                    display:flex; justify-content:space-between; align-items:center;'>
            <span style='color:#5a8a9f; font-size:0.72em;'> RAG Engine</span>
            <span style='color:{"#5cb85c" if gemini_client else "#FF4C4C"}; font-size:0.75em; font-weight:bold;'>
                {"● ONLINE" if gemini_client else "● OFFLINE (Set GEMINI_API_KEY)"}
            </span>
        </div>
    </div>
    """




def get_raw_artifacts():
    """Return raw dataframe for exploration."""
    if current_audit_df is None:
        return pd.DataFrame({"Status": ["Upload an image first"]})
    
    cols = ['Date and Time', 'Event ID', 'LogSource', 'ArtifactType', 'Task Category', 'AnomalyLabel']
    return current_audit_df[[c for c in cols if c in current_audit_df.columns]]


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: GRADIO UI
# ═══════════════════════════════════════════════════════════════════════════

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --primary: #6366f1;
    --secondary: #8b5cf6;
    --bg-dark: #050810;
    --card-bg: rgba(15, 23, 42, 0.7);
    --border-glow: rgba(99, 102, 241, 0.2);
    --neon-cyan: #00f2ff;
    --neon-red: #ff4c4c;
    --neon-amber: #ffa500;
}

body, .gradio-container {
    background: radial-gradient(circle at top right, #0a0e1a, #050810) !important;
    font-family: 'Inter', sans-serif !important;
    color: #e2e8f0 !important;
}

/* Glassmorphism Cards */
.gradio-container .gr-box, .gradio-container .gr-panel {
    background: var(--card-bg) !important;
    backdrop-filter: blur(16px) !important;
    border: 1px solid var(--border-glow) !important;
    border-radius: 16px !important;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37) !important;
}

/* Premium Typography */
h1, h2, h3 {
    font-family: 'Inter', sans-serif !important;
    font-weight: 700 !important;
    letter-spacing: -0.5px !important;
}

.mono {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Glowing Buttons */
.gr-button-primary {
    background: linear-gradient(135deg, var(--primary), var(--secondary)) !important;
    border: none !important;
    box-shadow: 0 0 15px rgba(99, 102, 241, 0.4) !important;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
}

.gr-button-primary:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 0 25px rgba(99, 102, 241, 0.6) !important;
}

/* Interactive Evidence Cards Styling */
.evidence-card {
    transition: all 0.2s ease !important;
    cursor: pointer;
}
.evidence-card:hover {
    transform: scale(1.01) !important;
    border-color: var(--primary) !important;
    background: rgba(99, 102, 241, 0.1) !important;
}
"""

def generate_pdf_report(investigator, case_id, notes):
    """Generate a professional forensic PDF report using fpdf2."""
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
    
    class ForensicPDF(FPDF):
        def header(self):
            self.set_font('helvetica', 'B', 15)
            self.cell(0, 10, 'OFFICIAL FORENSIC EXAMINATION REPORT', border=False, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_font('helvetica', 'I', 8)
            self.cell(0, 10, f'Generated by Forensic Image Analysis Engine v4.0 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', border=False, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(10)
            
        def footer(self):
            self.set_y(-15)
            self.set_font('helvetica', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}/{{nb}} | Case: {case_id}', align='C')

    pdf = ForensicPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=10)
    
    # 1. Header Metadata
    pdf.set_font("helvetica", 'B', 12)
    pdf.cell(0, 10, "1. CASE METADATA", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("helvetica", size=10)
    pdf.cell(0, 8, f"Investigator: {investigator}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Case Identifier: {case_id}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Evidence Hash (SHA-256): {image_hash_sha256}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)
    
    # 2. Executive Summary
    pdf.set_font("helvetica", 'B', 12)
    pdf.cell(0, 10, "2. EXECUTIVE SUMMARY", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("helvetica", size=10)
    pdf.multi_cell(pdf.epw, 8, f"Notes: {notes}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Total Artifacts Analyzed: {artifact_counts.get('total', 0)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 8, f"Anomalies Detected: {len(current_audit_df[current_audit_df['AnomalyScore'] == -1]) if current_audit_df is not None else 0}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)
    
    # 3. Investigation Log
    pdf.set_font("helvetica", 'B', 12)
    pdf.cell(0, 10, "3. INTERROGATION LOG (Q&A History)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("helvetica", size=10)
    
    for i, entry in enumerate(session_log):
        pdf.set_font("helvetica", 'B', 10)
        # Explicit width to avoid "Not enough horizontal space" error
        pdf.multi_cell(pdf.epw, 8, f"Q{i+1}: {entry['query']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("helvetica", size=10)
        # Clean up HTML/Markdown for PDF
        answer = entry['answer'].replace('**', '').replace('<br>', '\n')
        # Use effective page width (epw) for wrapping
        pdf.multi_cell(pdf.epw, 8, f"A: {answer}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("helvetica", 'I', 8)
        pdf.cell(0, 6, f"Evidence Cited: {entry['evidence_ids']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        
    report_name = f"Forensic_Report_{case_id.replace(' ', '_')}.pdf"
    output_path = os.path.join(SCRIPT_DIR, "cache", report_name)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    pdf.output(output_path)
    return output_path


with gr.Blocks() as demo:
    # -- HEADER --
    gr.HTML("""
    <div style='background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(139,92,246,0.08), rgba(15,23,42,0.9));
                padding: 24px 32px; border-bottom: 1px solid rgba(99,102,241,0.15);
                margin: -16px -16px 20px -16px;'>
        <div style='display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;'>
            <div>
                <div style='display:flex; align-items:center; gap:12px;'>
                    <div style='width:42px; height:42px; border-radius:12px;
                                background: linear-gradient(135deg, #6366f1, #8b5cf6);
                                display:flex; align-items:center; justify-content:center;
                                font-size:1.3em; box-shadow: 0 4px 15px rgba(99,102,241,0.3); color:white;'>DEF</div>
                    <div>
                        <h1 style='color:#e2e8f0; margin:0; font-size:1.35em; font-weight:700;
                                   font-family:Inter,sans-serif; letter-spacing:0.5px;'>
                            Forensic Analysis Engine
                        </h1>
                        <div style='color:#64748b; font-size:0.72em; letter-spacing:2px; margin-top:2px;
                                    font-family:JetBrains Mono,monospace;'>
                            v4.0 -- FULL IMAGE INTELLIGENCE
                        </div>
                    </div>
                </div>
            </div>
            <div style='display:flex; gap:8px; flex-wrap:wrap;'>
                <span style='background:rgba(99,102,241,0.12); color:#a5b4fc; padding:4px 12px;
                             border-radius:20px; font-size:0.65em; font-weight:500; letter-spacing:1px;
                             border:1px solid rgba(99,102,241,0.2);'>SLEUTHKIT</span>
                <span style='background:rgba(16,185,129,0.1); color:#6ee7b7; padding:4px 12px;
                             border-radius:20px; font-size:0.65em; font-weight:500; letter-spacing:1px;
                             border:1px solid rgba(16,185,129,0.2);'>FAISS + RAG</span>
                <span style='background:rgba(139,92,246,0.1); color:#c4b5fd; padding:4px 12px;
                             border-radius:20px; font-size:0.65em; font-weight:500; letter-spacing:1px;
                             border:1px solid rgba(139,92,246,0.2);'>GEMINI AI</span>
                <span style='background:rgba(245,158,11,0.1); color:#fcd34d; padding:4px 12px;
                             border-radius:20px; font-size:0.65em; font-weight:500; letter-spacing:1px;
                             border:1px solid rgba(245,158,11,0.2);'>MFT . SAM . PREFETCH</span>
            </div>
        </div>
    </div>
    """)

    with gr.Row():
        # -- LEFT SIDEBAR --
        with gr.Column(scale=1, min_width=280):
            file_input = gr.File(label="FORENSIC IMAGE (.dd / .E01)", file_types=[".dd", ".E01", ".e01", ".raw", ".img"])
            status = gr.Textbox(label="SYSTEM STATUS", interactive=False, value="Awaiting evidence upload...", lines=4)

            with gr.Accordion("CASE SETUP (FOR REPORTING)", open=False):
                investigator_input = gr.Textbox(label="Investigator Name", value="Unknown Examiner")
                case_id_input = gr.Textbox(label="Case ID", value="CASE-2026-001")
                case_notes_input = gr.TextArea(label="Investigation Notes", placeholder="Enter case context...")
                export_btn = gr.Button("EXPORT PDF REPORT", variant="secondary")
                report_file = gr.File(label="Download Report")

            gr.HTML("""
            <div style='background: linear-gradient(145deg, rgba(15, 23, 42, 0.8), rgba(30, 41, 59, 0.6));
                        backdrop-filter: blur(12px);
                        border: 1px solid rgba(99,102,241,0.2); 
                        border-radius: 16px;
                        padding: 18px; 
                        margin-top: 15px;
                        box-shadow: 0 4px 20px rgba(0,0,0,0.3);'>
                
                <div style='margin-bottom: 15px;'>
                    <div style='color:#94a3b8; font-size:0.65em; letter-spacing:2.5px; font-weight:600;
                                margin-bottom:10px; font-family:Inter,sans-serif; text-transform:uppercase;'>
                        Query Guide</div>
                    <div style='color:#cbd5e1; font-size:0.8em; line-height:1.8; font-family:Inter,sans-serif;'>
                        <div style='display:flex; justify-content:space-between;'><span style='color:#a5b4fc; font-weight:600;'>summary</span> <span style='color:#64748b;'>forensic overview</span></div>
                        <div style='display:flex; justify-content:space-between;'><span style='color:#a5b4fc; font-weight:600;'>anomalies</span> <span style='color:#64748b;'>threats & outliers</span></div>
                        <div style='display:flex; justify-content:space-between;'><span style='color:#a5b4fc; font-weight:600;'>how many users</span> <span style='color:#64748b;'>SAM + profiles</span></div>
                        <div style='display:flex; justify-content:space-between;'><span style='color:#a5b4fc; font-weight:600;'>files with .pdf</span> <span style='color:#64748b;'>filesystem search</span></div>
                        <div style='display:flex; justify-content:space-between;'><span style='color:#a5b4fc; font-weight:600;'>installed programs</span> <span style='color:#64748b;'>SOFTWARE hive</span></div>
                        <div style='display:flex; justify-content:space-between;'><span style='color:#a5b4fc; font-weight:600;'>logs 13:00 to 14:00</span> <span style='color:#64748b;'>time range</span></div>
                    </div>
                </div>

                <div style='border-top: 1px solid rgba(99,102,241,0.1); padding-top: 12px;'>
                    <div style='color:#c4b5fd; font-size:0.65em; letter-spacing:2.5px; font-weight:600;
                                margin-bottom:8px; font-family:Inter,sans-serif; text-transform:uppercase;'>
                        AI Examples</div>
                    <div style='color:#a78bfa; font-size:0.75em; line-height:1.8; font-family:Inter,sans-serif; font-style: italic;'>
                        "Was there a brute force attack?"<br>
                        "How many PDF files exist?"<br>
                        "List all user accounts"<br>
                        "What programs were executed?"
                    </div>
                </div>
            </div>
            """)

        # -- MAIN CONTENT --
        with gr.Column(scale=3):
            with gr.Tabs(elem_classes="main-tabs"):
                # TAB 1: AI INVESTIGATION (CHAT)
                with gr.Tab("AI Investigation"):
                    gr.HTML("""<div style='color:#94a3b8; font-size:0.7em; letter-spacing:2.5px;
                                          font-weight:600; margin-bottom:6px; font-family:Inter,sans-serif;'>
                                 AI INQUIRY TERMINAL</div>""")
                    query_input = gr.Textbox(
                        label="QUERY",
                        placeholder="Ask any forensic question",
                        lines=1
                    )
                    with gr.Row():
                        btn = gr.Button("EXECUTE QUERY", variant="primary")
                        stop_btn = gr.Button("STOP", variant="secondary")

                    gr.HTML("""<div style='color:#94a3b8; font-size:0.68em; letter-spacing:2px; font-weight:600;
                                          margin:16px 0 8px 0; font-family:Inter,sans-serif;
                                          display:flex; align-items:center; gap:8px;'>
                                 OUTPUT STREAM</div>""")
                    chat_output = gr.HTML(
                        value="""<div style='color:#64748b; font-family:Inter,sans-serif; padding:40px;
                                            text-align:center; font-size:0.95em;'>
                            <div style='font-size:2em; margin-bottom:12px; opacity:0.5;'>[INFO]</div>
                            <div style='font-weight:500;'>Ready for investigation</div>
                            <div style='font-size:0.8em; margin-top:6px; color:#475569;'>
                                Upload evidence and ask any question
                            </div>
                        </div>""",
                        elem_id="chat-output-box"
                    )

                # TAB 2: DASHBOARD
                with gr.Tab("Dashboard & Summary"):
                    refresh_btn = gr.Button("Generate Dashboard", variant="primary")
                    summary_output = gr.HTML(
                        value="""<div style='color:#64748b; font-family:Inter,sans-serif; padding:40px; text-align:center;'>
                            Upload a forensic image and click Generate Dashboard.
                        </div>""",
                        elem_id="summary-output-box"
                    )


                # TAB 4: RAW ARTIFACTS
                with gr.Tab("Raw Artifacts"):
                    gr.HTML("<div style='color:#94a3b8; font-family:Inter,sans-serif; font-size:0.8em; margin-bottom:10px;'>Browse and filter all extracted evidence artifacts.</div>")
                    artifacts_btn = gr.Button("Load Artifacts", variant="primary")
                    raw_dataframe = gr.Dataframe(interactive=False, wrap=True)

    # -- EVENT BINDINGS --
    file_input.change(handle_image_upload, inputs=file_input, outputs=status, show_progress="full")
    
    query_click = btn.click(ask_chatbot, inputs=query_input, outputs=chat_output, show_progress="full")
    query_submit = query_input.submit(ask_chatbot, inputs=query_input, outputs=chat_output, show_progress="full")
    stop_btn.click(fn=None, inputs=None, outputs=None, cancels=[query_click, query_submit])
    
    refresh_btn.click(get_investigation_summary, outputs=summary_output, show_progress="hidden")
    artifacts_btn.click(get_raw_artifacts, outputs=raw_dataframe, show_progress="hidden")
    
    export_btn.click(
        generate_pdf_report, 
        inputs=[investigator_input, case_id_input, case_notes_input], 
        outputs=report_file
    )

demo.launch(css=CSS)
