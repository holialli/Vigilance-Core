"""Filesystem walking and per-artifact-type extractors."""

import concurrent.futures
import json
import os
import re
import sqlite3
import tempfile
import time
import traceback
from datetime import datetime, timedelta, timezone

import pandas as pd

from .config import HASHSET_BAD_PATH, HASHSET_GOOD_PATH, debug_extract
from .hashsets import (hash_image_files, hash_summary, load_hashset,
                       match_hashsets)
from .parsers import EWFImgInfo, parse_evtx_file, parse_registry_hive
from .recyclebin import describe as describe_recycle
from .recyclebin import parse_i_file, parse_info2
from .shimcache import parse_appcompatcache


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

# Only these are worth skipping when the walk is shared. They are enormous and
# no extractor looks inside them. The recycle-bin directories are deliberately
# absent: extract_recycle_bin searches for the $I/$R files that live inside
# them, and skipping them forced it down a second-pass fallback.
_INDEX_SKIP_DIRS_LOWER = {'winsxs', 'servicing', 'driverstore', 'windows.old'}

_WALK_SKIP_NAMES = {'.', '..', '$orphanfiles'}


def _meta_addr(entry):
    """Inode for a directory entry, from the name record when meta is absent."""
    try:
        meta = entry.info.meta
        if meta is not None and meta.addr:
            return int(meta.addr)
    except Exception:
        pass
    try:
        name = entry.info.name
        if name is not None and name.meta_addr:
            return int(name.meta_addr)
    except Exception:
        pass
    return None


def _open_dir_by_inode(fs, meta_addr):
    """Open a directory by inode, or None if it is not a directory.

    Never resolve a child by path string. TSK resolves a path by scanning each
    parent directory's entries in turn, so the cost is the size of the parents,
    not the depth — and a probe that *fails* (the common case, since the caller
    is asking "is this a directory?" about a file) scans the parent to the end
    first. In /WINDOWS/system32, 1,794 entries, that is ~200ms per probe; a
    quarter of all entries need one. That single line was 4,146s of a 5,215s
    carve on the reference image. By inode it is one lookup, ~0ms.
    """
    if not meta_addr:
        return None
    try:
        return fs.open_dir(inode=meta_addr)
    except Exception:
        return None


def build_path_index(fs, start_path="/", max_depth=14):
    """Walk the image once and record every path found.

    heuristic_discover_files traverses the whole filesystem per call, and four
    extractors call it (recycle bin, browser, communication, SRUM) — six or more
    complete walks of the same image per carve. That was cheap only while the
    walk was truncating early; once it descended properly it dominated carve
    time. Build the listing once here and let every caller filter it.

    Returns a list of (full_path, name, is_dir, depth).
    """
    index = []

    def _walk(path, depth, directory):
        if depth > max_depth or directory is None:
            return

        entries = []
        for entry in directory:
            try:
                raw_name = entry.info.name.name
                name = (raw_name.decode('utf-8', errors='ignore')
                        if isinstance(raw_name, bytes) else raw_name)
                if name.lower() in _WALK_SKIP_NAMES:
                    continue
                ntype = entry.info.name.type if entry.info.name else 0
                meta_type = (entry.info.meta.type
                             if entry.info.meta is not None else 0)
                entries.append((name, ntype, meta_type, _meta_addr(entry),
                                entry))
            except Exception:
                continue

        # Dedup on (name, type, type) exactly as before — the inode is carried
        # along, not part of the key, so a deleted and a live entry sharing a
        # name still collapse to one the way they always did.
        #
        # But take the inode from whichever copy actually has one. A name can be
        # listed twice with an identical key, once with meta_addr 0: on the
        # reference image 'wizdata.dat' and '~DF99EB.tmp' both list first with 0
        # and again with a real inode, and only the second can be opened. Keeping
        # the first blindly classified both as files and lost 67 paths beneath
        # them, including an ARJ toolset in the suspect's temp directory.
        # A name can also list twice under *different* keys (differing
        # meta_type), so both survive dedup and the stale copy has no inode of
        # its own. Let it borrow the inode its live twin resolved with,
        # otherwise the same path is reported as a directory and then as a file.
        name_addr = {}
        for name, _nt, _mt, addr, _e in entries:
            if addr and name not in name_addr:
                name_addr[name] = addr

        unique, pos = [], {}
        for name, ntype, meta_type, addr, entry in entries:
            key = (name, ntype, meta_type)
            if key in pos:
                i = pos[key]
                if not unique[i][3] and addr:
                    unique[i] = (name, ntype, meta_type, addr, entry)
                continue
            pos[key] = len(unique)
            unique.append((name, ntype, meta_type, addr, entry))

        for name, ntype, meta_type, addr, entry in unique:
            try:
                full_path = f"{path}/{name}" if path != "/" else f"/{name}"
                is_dir = (ntype == 2) or (meta_type == 2)

                child = _open_dir_by_inode(fs, addr)
                if child is None and ntype not in (1, 2):
                    # No inode to ask about. as_directory() answers from the
                    # entry we already hold, with no lookup of any kind — the
                    # path probe here cost 297s of a 302s walk.
                    try:
                        child = entry.as_directory()
                    except Exception:
                        child = None
                    if child is None and not addr:
                        child = _open_dir_by_inode(fs, name_addr.get(name))
                if not is_dir and ntype not in (1, 2):
                    is_dir = child is not None
                if is_dir and child is None:
                    # Known directory that yielded no handle. Never reached on a
                    # real image (every live directory has an inode), but the
                    # path lookup is the only route an fs without inodes has.
                    try:
                        child = entry.as_directory()
                    except Exception:
                        child = None
                    if child is None:
                        try:
                            child = fs.open_dir(full_path)
                        except Exception:
                            child = None

                index.append((full_path, name, is_dir, depth + 1))

                # No visited-inode guard: five PCHEALTH help-center directories
                # are legitimately reachable by more than one name, and skipping
                # the repeat visit silently dropped ~100 paths. max_depth is the
                # termination bound, as it was before.
                if (is_dir and child is not None
                        and name.lower() not in _INDEX_SKIP_DIRS_LOWER):
                    _walk(full_path, depth + 1, child)
            except Exception:
                continue

    try:
        root = fs.open_dir(start_path)
    except Exception:
        root = None
    _walk(start_path, 0, root)
    print(f"  [INDEX] Indexed {len(index)} paths in a single traversal.")
    return index


def match_path_index(index, target_patterns, start_path="/", max_depth=6):
    """Select paths from a prebuilt index, mirroring a heuristic walk."""
    compiled = [re.compile(p, re.IGNORECASE) for p in target_patterns]
    if start_path == "/":
        prefix, base_depth = "/", 0
    else:
        prefix = start_path.rstrip("/") + "/"
        base_depth = start_path.rstrip("/").count("/")

    found = []
    for full_path, name, _is_dir, depth in index:
        if start_path != "/" and not full_path.lower().startswith(prefix.lower()):
            continue
        # The recursive walk enters a directory at depth d and matches its
        # children there, so it reaches relative depth max_depth + 1. Matching
        # that exactly matters: being one level shallow here would quietly
        # shrink discovery, which is the failure mode this refactor exists to
        # remove.
        if depth - base_depth > max_depth + 1:
            continue
        if any(p.search(name) for p in compiled):
            found.append(full_path)
    return found


def heuristic_discover_files(fs, target_patterns, start_path="/",
                              max_depth=6, depth=0, index=None):
    """
    Recursively search for files/dirs matching target_patterns.
    Dotted directory names (e.g. Firefox hashed profiles) are now traversed.

    When `index` is supplied the shared traversal is filtered instead of the
    filesystem being walked again.
    """
    if index is not None:
        return match_path_index(index, target_patterns, start_path, max_depth)

    compiled = [re.compile(p, re.IGNORECASE) for p in target_patterns]
    found = []
    _skip_names = _WALK_SKIP_NAMES

    def _walk(path, d):
        if d > max_depth:
            return
        try:
            directory = fs.open_dir(path)
            if directory is None:
                return
        except Exception:
            return

        # Drain the listing before touching the filesystem again. Recursing (or
        # probing with open_dir) while this directory is mid-iteration truncates
        # it, so entries past the first subdirectory were never even examined.
        entries = []
        for entry in directory:
            try:
                raw_name = entry.info.name.name
                name = (raw_name.decode('utf-8', errors='ignore')
                        if isinstance(raw_name, bytes) else raw_name)
                if name.lower() in _skip_names:
                    continue
                ntype = entry.info.name.type if entry.info.name else 0
                meta_type = (entry.info.meta.type
                             if entry.info.meta is not None else 0)
                entries.append((name, ntype, meta_type))
            except Exception:
                continue

        for name, ntype, meta_type in list(dict.fromkeys(entries)):
            try:
                full_path = f"{path}/{name}" if path != "/" else f"/{name}"

                if any(p.search(name) for p in compiled):
                    found.append(full_path)

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

        # Names are collected before any file is read. Reading a file through
        # the same handle that is mid-iteration can cut the directory listing
        # short, which silently drops whole channels (System.evtx and
        # Application.evtx went missing this way — the largest logs on the image).
        names = []
        for entry in evtx_dir:
            try:
                fname = entry.info.name.name.decode('utf-8', errors='ignore')
            except Exception:
                continue
            if fname.lower().endswith('.evtx'):
                names.append(fname)
        # A directory can list the same name twice (an unallocated entry
        # alongside the live one); opening it twice just duplicates every event.
        names = list(dict.fromkeys(names))
        print(f"   Found {len(names)} .evtx files in {evtx_dir_path}")

        skipped = []
        for fname in names:
            fpath = f"{evtx_dir_path}/{fname}"
            try:
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
            except Exception as exc:
                # Never swallow silently: an unreadable channel is a gap in the
                # evidence and the examiner has to know which one.
                skipped.append(f"{fname} ({type(exc).__name__}: {exc})")

        if skipped:
            print(f"   [WARN] {len(skipped)} EVTX file(s) could not be read:")
            for item in skipped:
                print(f"      - {item}")
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

            # Collect profile names before opening any hive. Reading a file
            # through the handle that is iterating this directory truncates the
            # listing, so every profile after the first one silently disappeared.
            profile_names = []
            for entry in users_dir:
                try:
                    raw = entry.info.name.name
                    name = (raw.decode('utf-8', errors='ignore')
                            if isinstance(raw, bytes) else raw)
                except Exception:
                    continue
                if name.lower() in _skip_names:
                    continue
                ntype = entry.info.name.type
                meta_type = entry.info.meta.type if entry.info.meta else 0
                profile_names.append((name, (ntype == 2) or (meta_type == 2)))
            profile_names = list(dict.fromkeys(profile_names))

            for name, typed_as_dir in profile_names:
                try:
                    # FIX-5: verify it is a directory before proceeding. The
                    # open_dir probe happens here rather than during iteration
                    # above, for the same reason the hive read does.
                    if not typed_as_dir:
                        try:
                            fs.open_dir(f"{base_root}/{name}")
                        except Exception:
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
            # Names first, reads second — see extract_all_evtx: reading through
            # a handle mid-iteration cuts the listing short.
            profile_names = []
            for entry in users_dir:
                try:
                    name = entry.info.name.name.decode('utf-8', errors='ignore')
                except Exception:
                    continue
                if name.lower() not in skip_names:
                    profile_names.append(name)

            for name in list(dict.fromkeys(profile_names)):
                recent_path = f"{base_root}/{name}/AppData/Roaming/Microsoft/Windows/Recent"
                try:
                    recent_dir = fs.open_dir(recent_path)
                    if recent_dir is None:
                        continue
                    lnk_names = []
                    for lnk_entry in recent_dir:
                        try:
                            lname = lnk_entry.info.name.name.decode('utf-8', errors='ignore')
                        except Exception:
                            continue
                        if lname.lower().endswith('.lnk'):
                            lnk_names.append((lname, lnk_entry.info.meta.mtime
                                              if lnk_entry.info.meta else 0))

                    for lname, lnk_mtime in list(dict.fromkeys(lnk_names)):
                        try:
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
                                lnk_mtime, timezone.utc
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


_RECYCLE_DIR_RE = re.compile(r'(\$recycle\.bin|recycler|recycled)', re.I)


def extract_recycle_bin(fs, index=None):
    records = []
    print("  [CARVE] Scanning for Recycle Bin artifacts (Global Search)...")

    target_files = heuristic_discover_files(
        fs, [r'^\$I', r'^\$R', r'^INFO2$'], max_depth=10, index=index
    )
    if not target_files:
        recycle_dirs = heuristic_discover_files(
            fs, [r'^\$Recycle\.Bin$', r'^RECYCLER$', r'^RECYCLED$'],
            max_depth=4, index=index
        )
        for rdir in recycle_dirs:
            target_files.extend(
                heuristic_discover_files(
                    fs, [r'^\$I', r'^\$R', r'^INFO2$'],
                    start_path=rdir, max_depth=6, index=index
                )
            )

    # '^\$R' also matches NTFS metafiles — $Reparse, $RmMetadata and $Repair all
    # live under /$Extend and are not deleted user data. Deleted-item records
    # only ever live inside a recycle-bin directory, so require that.
    filtered = [p for p in target_files if _RECYCLE_DIR_RE.search(p)]
    discarded = len(target_files) - len(filtered)
    target_files = filtered
    if discarded and debug_extract:
        print(f"  [DEBUG] Ignored {discarded} NTFS metafile(s) matching $I/$R "
              f"outside any recycle-bin directory.")

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
            leaf = parts[-1]

            # Read the record so the entry says what was deleted. Reporting only
            # that a recycle-bin file exists tells an examiner nothing: the
            # original path, size and deletion time all live inside INFO2/$I.
            parsed = []
            try:
                size = meta.size if meta and meta.size else 0
                if size and size < (8 << 20):
                    data = f_obj.read_random(0, size)
                    if leaf.upper() == 'INFO2':
                        parsed = parse_info2(data)
                    elif leaf.upper().startswith('$I'):
                        one = parse_i_file(data)
                        parsed = [one] if one else []
            except Exception as exc:
                if debug_extract:
                    print(f"  [DEBUG] Recycle record parse failed for {path}: {exc}")

            if parsed:
                for record in parsed:
                    deleted_at = record.get('deleted_time')
                    records.append({
                        'Date and Time': (deleted_at.strftime('%Y-%m-%d %H:%M:%S UTC')
                                          if deleted_at else ts_str),
                        'Event ID': '9800',
                        'Task Category': describe_recycle(record, path),
                        'LogSource': 'RECYCLE_BIN',
                        'Keywords': 'Alert',
                        'ArtifactType': 'RECYCLE',
                    })
                continue

            # $R files hold the deleted content itself and carry no metadata;
            # the paired $I record above is what names them.
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

def extract_browser_history(fs, index=None):
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
                                     start_path=root, max_depth=14, index=index)
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


def _is_deleted(entry):
    """True when TSK marks the name or metadata record as unallocated."""
    try:
        import pytsk3
        name_flags = entry.info.name.flags if entry.info.name else 0
        meta_flags = entry.info.meta.flags if entry.info.meta else 0
        return bool(
            (name_flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
            or (meta_flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
        )
    except Exception:
        return False


def walk_filesystem(fs, limit=150000, max_depth=14):
    records = []
    print("  [CARVE] Indexing Filesystem (Autopsy Mode)...")

    skip_dirs = {'winsxs', 'servicing', 'driverstore',
                 'system32', 'program files', 'program files (x86)'}

    # The roots below overlap: TSK resolves '/Users' and '/USERS' to the same
    # directory, '/' reaches both, and '/' also reaches '$OrphanFiles' before it
    # is walked explicitly. Without these guards every such file is recorded
    # two to four times — the artifact counts were inflated 2.8x (FILESYSTEM)
    # and 2.0x (DELETED) on the reference image, so "1,334 deleted files" was
    # really 663.
    visited_dirs = set()
    seen_paths = set()

    def fast_walk(directory_path, depth=0, dir_obj=None):
        if len(records) >= limit or depth > max_depth:
            return
        dir_key = directory_path.lower().rstrip('/') or '/'
        if dir_key in visited_dirs:
            return
        visited_dirs.add(dir_key)
        try:
            # Only the entry roots are resolved by path; children arrive as an
            # already-open directory object. See _open_dir_by_inode.
            if dir_obj is None:
                dir_obj = fs.open_dir(directory_path)
            if dir_obj is None:
                return

            # Snapshot the listing before recursing. Descending into a
            # subdirectory while this one is still being iterated truncates it,
            # so siblings after the first subdirectory were never indexed.
            listing = []
            for entry in dir_obj:
                try:
                    name = entry.info.name.name.decode('utf-8', errors='ignore')
                    if name in ['.', '..']:
                        continue
                    meta = entry.info.meta
                    listing.append((
                        name,
                        entry.info.name.type,
                        meta.type if meta else None,
                        meta.mtime if meta else None,
                        meta.size if meta and meta.size else 0,
                        _is_deleted(entry),
                        _meta_addr(entry),
                        entry,
                    ))
                except Exception:
                    continue

            # Inode per name, taken from whichever listing of it actually has
            # one, so a copy listed with meta_addr 0 can borrow it. Same two
            # failure modes build_path_index documents.
            name_addr = {}
            for _n, _nt, _mt, _mtime, _sz, _del, _addr, _e in listing:
                if _addr and _n not in name_addr:
                    name_addr[_n] = _addr

            for name, ntype, meta_type, m_time, size, deleted, addr, entry in listing:
                if len(records) >= limit:
                    return
                try:
                    fpath = (f"{directory_path}/{name}"
                             if directory_path != "/" else f"/{name}")
                    path_key = fpath.lower()
                    if path_key in seen_paths:
                        continue
                    seen_paths.add(path_key)

                    is_file = (ntype == 1) or (meta_type == 1)
                    is_dir = (ntype == 2) or (meta_type == 2)
                    child = _open_dir_by_inode(fs, addr)
                    # seen_paths keeps the first listing of a name, which may be
                    # the meta_addr-0 copy; without this the directory is filed
                    # as a plain file and its contents never walked.
                    if child is None and not addr and ntype not in (1, 2):
                        # Ask the entry we already hold, then the inode a live
                        # twin of the same name resolved with — the two routes
                        # build_path_index uses here, and deliberately the only
                        # two. It never resolves an UNDEF entry by path, because
                        # TSK answers a path by scanning every parent in turn:
                        # 34 such probes were 17.4s of a 27.1s walk on the Win7
                        # image, every one of them a deleted Content.IE5 cache
                        # file with no inode and no live twin, and every one
                        # returning nothing. A probe that cannot succeed is pure
                        # cost, so the walk now concludes 'not a directory' from
                        # the entry itself, exactly as the shared index does.
                        try:
                            child = entry.as_directory()
                        except Exception:
                            child = None
                        if child is None:
                            child = _open_dir_by_inode(fs, name_addr.get(name))
                    if not is_dir and ntype not in (1, 2):
                        is_dir = child is not None
                    ext = os.path.splitext(name)[1].lower() if is_file else ''
                    mtime = (datetime.fromtimestamp(m_time, timezone.utc)
                             .strftime('%Y-%m-%d %H:%M:%S UTC')
                             if m_time else 'N/A')

                    if is_file or is_dir:
                        ftype = "Directory" if is_dir else "File"
                        prefix = "Deleted " if deleted else ""
                        records.append({
                            'Date and Time': mtime,
                            'Event ID': '9101' if deleted else '9100',
                            'Task Category': (
                                f"{prefix}{ftype} Discovery: {name} "
                                f"({ext.upper()}) at {fpath}"
                            ),
                            'LogSource': 'FILESYSTEM',
                            'Keywords': 'Alert' if deleted else 'None',
                            'ArtifactType': 'DELETED' if deleted else 'FILESYSTEM',
                            '_filepath': fpath,
                            '_filename': name,
                            '_extension': ext,
                            '_size': size,
                            '_is_dir': is_dir,
                            '_deleted': deleted,
                        })

                    if is_dir and depth < max_depth and name.lower() not in skip_dirs:
                        fast_walk(fpath, depth + 1, child)
                except Exception:
                    continue
        except Exception:
            pass

    for root in ["/Users", "/USERS",
                 "/Documents and Settings", "/DOCUMENTS AND SETTINGS"]:
        fast_walk(root)
    if len(records) < limit:
        fast_walk("/")
    # Orphaned MFT entries: files whose parent directory is gone. TSK exposes
    # them under a synthetic $OrphanFiles node that a normal walk never reaches.
    fast_walk("/$OrphanFiles")

    deleted_count = sum(1 for r in records if r['_deleted'])
    print(f"  [OK] Indexed {len(records)} files/folders "
          f"({deleted_count} deleted/orphaned).")
    return pd.DataFrame(records)


# ═══════════════════════════════════════════════════════════════════════════
# FIX-6: extract_communication_artifacts — wider depth; all roots searched
# ═══════════════════════════════════════════════════════════════════════════

def extract_communication_artifacts(fs, index=None):
    """Discover email databases and communication artifacts."""
    records = []
    print("   Scanning for communication artifacts (expanded depth)...")

    email_patterns = [r'^.*\.(pst|ost|msg|eml|mbox)$']
    found_paths = []

    roots = get_user_roots(fs) or ["/"]
    for root in roots:
        found_paths.extend(
            heuristic_discover_files(
                fs, email_patterns, start_path=root, max_depth=14, index=index
            )
        )
    # Also scan root for unusual placements
    found_paths.extend(
        heuristic_discover_files(fs, email_patterns, start_path="/",
                                 max_depth=10, index=index)
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
    """Parse AppCompatCache (ShimCache) from the SYSTEM hive.

    Evidence of program presence/execution that survives deletion of the binary.
    """
    from Registry import Registry as reg_lib

    reg_data = None
    for path in ("/Windows/System32/config/SYSTEM", "/Windows/System32/config/system"):
        try:
            f_obj = fs.open(path)
            reg_data = f_obj.read_random(0, f_obj.info.meta.size)
            break
        except Exception:
            continue

    if not reg_data:
        return pd.DataFrame()

    with tempfile.NamedTemporaryFile(suffix=".hive", delete=False) as tmp:
        tmp.write(reg_data)
        tmp_path = tmp.name

    records = []
    try:
        registry = reg_lib.Registry(tmp_path)
        for control_set in ("ControlSet001", "ControlSet002"):
            for key_path in (
                f"{control_set}\\Control\\Session Manager\\AppCompatCache",
                f"{control_set}\\Control\\Session Manager\\AppCompatibility",
            ):
                try:
                    key = registry.open(key_path)
                    raw = key.value("AppCompatCache").value()
                except Exception:
                    continue

                entries = parse_appcompatcache(raw)
                if entries:
                    print(f"  [EXEC] {len(entries)} ShimCache entries from {key_path}")
                for entry in entries:
                    records.append({
                        'Date and Time': entry["last_modified"],
                        'Event ID': '9500',
                        'Task Category': (
                            f"Program Execution Evidence: {entry['path']} "
                            f"({entry['source']}, last modified: {entry['last_modified']})"
                        ),
                        'LogSource': 'SHIMCACHE',
                        'Keywords': 'Alert',
                        'ArtifactType': 'EXECUTION',
                    })
                if records:
                    break
            if records:
                break
    except Exception as e:
        print(f"  [EXEC] ShimCache parse error: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return pd.DataFrame(records)


# ═══════════════════════════════════════════════════════════════════════════
# FIX-7: extract_srum_data — isolated; 7 case-variant probes
# ═══════════════════════════════════════════════════════════════════════════

def extract_srum_data(fs, index=None):
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

    # Every one of those probes is a full path resolution, and on an image with
    # no SRUM all seven fail — each scanning its parent directories to the end
    # before concluding, ~800ms apiece on the XP image. The shared index already
    # lists every path, and each candidate above sits at depth 4 in a directory
    # the index never skips, so if it holds no SRUDB.dat the probes cannot find
    # one either. The heuristic search below still runs, so nothing is lost.
    if index is not None and not match_path_index(
            index, [r'^SRUDB\.dat$'], start_path="/", max_depth=14):
        srum_paths = []

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
        start_path="/", max_depth=10, index=index
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
    Returns (dataframe, artifact_counts).
    """
    all_frames = []
    artifact_counts = {
        "evtx": 0, "registry": 0, "filesystem": 0,
        "sam": 0, "software": 0, "prefetch": 0, "total": 0
    }

    try:
        import pytsk3
    except ImportError:
        # Reached only if the install is incomplete. Say which package and how
        # to get it, rather than surfacing a bare ModuleNotFoundError from six
        # frames down in a background carve thread.
        from .parsers import PYTSK3_MISSING
        raise RuntimeError(PYTSK3_MISSING)

    filepaths = image_source if isinstance(image_source, list) else [image_source]
    primary_file = filepaths[0]

    is_e01 = primary_file.lower().endswith('.e01')
    if is_e01:
        try:
            import pyewf

            # A multi-segment E01 set must be opened with every segment. Only
            # the first was ever passed — the UI hands over a single path — so
            # any split image failed at the first segment boundary and was
            # reported as "segments missing" even with the .E02 sitting right
            # beside it. glob() discovers the siblings by naming convention.
            if not isinstance(image_source, list):
                try:
                    globbed = list(pyewf.glob(primary_file))
                    if globbed:
                        filepaths = globbed
                        if len(globbed) > 1:
                            print(f"  [E01] Multi-segment set: "
                                  f"{len(globbed)} segments located.")
                except Exception as exc:
                    print(f"  [WARN] E01 segment glob failed ({exc}); "
                          f"opening the given file only.")

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

    fs_offset = None
    for offset in offsets_to_try:
        try:
            fs = pytsk3.FS_Info(img_info, offset=offset)
            fs_offset = offset
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

    def open_fs():
        """Open an independent filesystem handle.

        A TSK filesystem handle is not safe to share across threads: concurrent
        directory walks corrupt each other's state, which showed up as random
        '$IDX_ROOT not found' failures and silently empty extractors. Each task
        therefore gets its own handle over its own image handle.
        """
        if is_e01:
            import pyewf
            handle = pyewf.handle()
            handle.open(filepaths)
            own_img = EWFImgInfo(handle)
        else:
            own_img = pytsk3.Img_Info(primary_file)
        return pytsk3.FS_Info(own_img, offset=fs_offset)

    def isolated(fn, *extra):
        """Run an extractor against its own filesystem handle."""
        def runner():
            return fn(open_fs(), *extra)
        return runner

    # Serial by default, because concurrency here costs evidence and buys
    # nothing. Per-task handles removed the worst of the corruption but not all
    # of it: libtsk keeps process-global state, so concurrent path resolution
    # still intermittently fails with '$IDX_ROOT not found' and drops whole
    # channels. Measured on the Win7 reference image, 14 workers vs serial:
    #
    #     wall 112.8s vs 106.5s      -- threading is *slower*
    #     EVTX 17,001 vs 17,336      -- 6 channels lost to $IDX_ROOT
    #     rows 79,853 vs 80,191      -- also 2 ACTIVITY, 1 COMMUNICATION
    #
    # It loses because the phase is 83% EVTX parsing, which is pure Python under
    # the GIL (python-evtx builds and re-parses XML per record), so threads
    # cannot overlap it with anything except libtsk's C calls -- while still
    # paying 16 extra image handles and the contention that corrupts libtsk.
    # Raise this only with evidence that it has stopped losing rows; the way to
    # actually parallelise the carve is a process pool over the EVTX files.
    max_workers = int(os.getenv("CARVE_MAX_WORKERS", "1"))

    # One traversal, shared by every discovery-based extractor. Built before the
    # pool starts so it is also the only walk that has to be thread-safe.
    print("  [INDEX] Building shared path index...")
    t_index = time.time()
    path_index = build_path_index(open_fs())
    print(f"  [INDEX] Done in {time.time() - t_index:.1f}s")

    # FIX-9: SRUM and EXECUTION are independent named tasks
    print(f"  [EXEC] Starting parallel artifact extraction "
          f"(Max Workers: {max_workers})...")

    tasks = [
        ("EVTX",          isolated(extract_all_evtx)),
        ("SYSTEM",        isolated(extract_system_artifact)),
        ("SAM",           isolated(extract_sam_hive)),
        ("SOFTWARE",      isolated(extract_software_hive)),
        ("USB",           isolated(extract_usb_devices)),
        ("NTUSER",        isolated(extract_all_ntuser)),             # FIX-5
        ("PREFETCH",      isolated(extract_prefetch)),
        ("FILESYSTEM",    isolated(walk_filesystem, 150000)),
        ("ACTIVITY",      isolated(extract_user_activity)),
        ("RECENT",        isolated(extract_recent_documents)),       # FIX-4
        ("RECYCLE",       isolated(extract_recycle_bin, path_index)),
        ("BROWSER",       isolated(extract_browser_history, path_index)),  # FIX-3
        ("COMMUNICATION", isolated(extract_communication_artifacts, path_index)),  # FIX-6
        ("USN",           isolated(extract_usn_journal)),
        ("EXECUTION",     isolated(extract_execution_history)),      # FIX-8
        ("SRUM",          isolated(extract_srum_data, path_index)),  # FIX-7
    ]

    filesystem_df = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_name = {
            executor.submit(fn): name for name, fn in tasks
        }
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                df = future.result()
                if df is not None and not df.empty:
                    all_frames.append(df)
                    if name == "FILESYSTEM":
                        filesystem_df = df
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

    # Hashing runs after the parallel phase because it consumes the file list
    # produced by walk_filesystem.
    if filesystem_df is not None and not filesystem_df.empty:
        try:
            hash_df = _hash_and_match(fs, filesystem_df)
            if hash_df is not None and not hash_df.empty:
                all_frames.append(hash_df)
                artifact_counts["hashmatch"] = len(hash_df)
        except Exception as exc:
            print(f"  [FAIL] Hashing pass failed: {exc}")
            if debug_extract:
                traceback.print_exc()

    if not all_frames:
        raise RuntimeError(
            f"[ERROR] No artifacts extracted from '{os.path.basename(primary_file)}'."
        )

    result = pd.concat(all_frames, ignore_index=True)
    artifact_counts["total"] = len(result)
    return result, artifact_counts


def _hash_and_match(fs, filesystem_df):
    """Hash notable files and compare them against configured hash sets.

    Skipped entirely when no hash sets exist: hashing reads every candidate file
    out of the image and dominates carve time, which is wasted with nothing to
    match against.
    """
    known_bad = load_hashset(HASHSET_BAD_PATH)
    known_good = load_hashset(HASHSET_GOOD_PATH)
    if not known_bad and not known_good:
        print("  [HASH] No hash sets configured — skipping hashing pass. "
              f"Add hashes to {HASHSET_BAD_PATH} to enable.")
        return pd.DataFrame()

    rows = filesystem_df.to_dict('records')
    print(f"  [HASH] Hashing notable files from {len(rows)} filesystem entries...")
    hashed = hash_image_files(fs, rows)

    summary = hash_summary(hashed)
    print(f"  [HASH] {summary['hashed']} hashed | "
          f"{summary['known_bad']} known-bad | {summary['known_good']} known-good")

    if not known_bad and not known_good:
        print("  [HASH] No hash sets configured — hashes computed but unmatched.")

    return match_hashsets(hashed, known_bad, known_good)
