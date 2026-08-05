"""Low-level artifact format parsers (EVTX, registry hives, hashing, E01)."""

import hashlib
import os
import tempfile
import time
from datetime import datetime

import pandas as pd

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


PYTSK3_MISSING = (
    "pytsk3 is not installed, so disk images cannot be opened.\n"
    "It is a native extension and needs SleuthKit present before it will "
    "build:\n"
    "  Windows : pip install pytsk3   (needs Visual C++ Build Tools)\n"
    "  Debian  : sudo apt install libtsk-dev && pip install pytsk3\n"
    "  macOS   : brew install sleuthkit && pip install pytsk3\n"
    "Everything except image carving works without it."
)

try:
    import pytsk3
except ImportError:              # native build failed or SleuthKit is absent
    pytsk3 = None

if pytsk3 is not None:
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
else:
    class EWFImgInfo:
        """Stand-in so this module still imports when pytsk3 is missing.

        The class used to be defined *inside* a `try: import pytsk3` whose
        `except ImportError` merely passed — which left the name undefined, and
        `extractors.py` imports it at module level. Every user whose pytsk3
        build failed therefore hit

            ImportError: cannot import name 'EWFImgInfo' from 'forensics.parsers'

        at startup: fatal, and silent about the actual cause. pytsk3 is a native
        extension that fails to build often enough that this was the most likely
        first-run failure there is. Now the import succeeds and the complaint
        arrives when someone actually opens an image, saying what to install.
        """

        def __init__(self, *args, **kwargs):
            raise RuntimeError(PYTSK3_MISSING)
