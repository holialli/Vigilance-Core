"""Aggregate system-level facts from carved artifacts."""

import re
from collections import Counter

import pandas as pd

def extract_system_context(session):
    if session.current_audit_df is None or session.current_audit_df.empty:
        return "No evidence loaded."

    df = session.current_audit_df

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
        logon_match = re.search(r'Login Count:\s*(\d+)', d_str)
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
