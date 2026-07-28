"""Cross-artifact correlation: pivot on entities that appear in several places.

A USB serial in the registry, a filename in the recycle bin, and a username in
the event log are separate rows to the extractor but the same lead to an
examiner. This module extracts entities from artifact descriptions and finds
where they co-occur across artifact types and in time.
"""

import re
import sqlite3
from datetime import timedelta

import pandas as pd

_ENTITY_PATTERNS = {
    "user": [
        re.compile(r'TargetUserName:\s*([^\s|]+)', re.I),
        re.compile(r'SAM User Account:\s*(.+?)\s*\(', re.I),
        re.compile(r'NTUSER\((.*?)\)', re.I),
        re.compile(r'/Users/([^/]+)/', re.I),
    ],
    "usb_serial": [
        # Registry USBSTOR form: "... Serial: I145291811100&0)"
        re.compile(r'Serial:\s*([A-Za-z0-9&_\-]+)', re.I),
        # Device-attach form: "... (ID: VID_05DC&PID_0080\\I145291811100)".
        # Requiring VID_/PID_ keeps hubs (ROOT_HUB\...) out.
        re.compile(r'ID:\s*VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\([A-Za-z0-9&_\-]+)', re.I),
    ],
    "executable": [
        re.compile(r'([A-Za-z0-9_\-.]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs))', re.I),
    ],
    "domain": [
        re.compile(r'https?://([A-Za-z0-9.\-]+)', re.I),
        re.compile(r'Cookie:[^|]*?\s([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*->', re.I),
    ],
}

_NOISE = {
    'system', 'localsystem', 'network service', 'local service', '-', 'n/a',
    'unknown', 'public', 'default', 'all users', 'administrator',
}


def init_correlation_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity TEXT,
            entity_type TEXT,
            timestamp TEXT,
            artifact_type TEXT,
            log_source TEXT,
            description TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_entity ON correlations(entity)")
    conn.commit()
    return conn


_USB_INSTANCE_SUFFIX = re.compile(r'&\d+$')


def _normalize_entity(entity_type, value):
    """Reduce the different spellings of one entity to a single key.

    Windows records the same USB serial two ways — USBSTOR appends an instance
    suffix ("I145291811100&0") that the device-attach record omits. Left
    unnormalized the two never join, so a device seen in both places looks like
    two single-source entities and is filtered out as an uncorroborated lead.
    """
    if entity_type == "usb_serial":
        return _USB_INSTANCE_SUFFIX.sub('', value)
    return value


def extract_entities(description):
    """Pull identifiable entities out of one artifact description."""
    found = set()
    for entity_type, patterns in _ENTITY_PATTERNS.items():
        for pattern in patterns:
            for match in pattern.findall(description or ""):
                value = _normalize_entity(entity_type, match.strip().strip('\\/'))
                if not value or len(value) < 3 or value.lower() in _NOISE:
                    continue
                if value.endswith('$'):  # machine accounts
                    continue
                found.add((entity_type, value))
    return found


def build_correlations(df, conn=None, max_rows=None):
    """Index entities from artifacts into a queryable correlation table.

    Indexes every row by default. A head() cap is not safe here: artifacts are
    concatenated one extractor at a time, so truncating drops whole artifact
    types rather than thinning the corpus evenly — on the reference image a
    60k cap silently excluded all FILESYSTEM, DELETED, ACTIVITY and RECENT
    rows, and most USB rows, from correlation.
    """
    conn = conn or init_correlation_db()
    if df is None or df.empty:
        return conn

    working = df if max_rows is None else df.head(max_rows)
    if max_rows is not None and len(df) > max_rows:
        print(f"  [CORRELATE] WARNING: capped at {max_rows} of {len(df)} rows — "
              f"later artifact types are excluded.")
    rows = []
    for record in working.to_dict('records'):
        description = str(record.get('Task Category', ''))
        for entity_type, value in extract_entities(description):
            rows.append((
                value.lower(), entity_type,
                str(record.get('Date and Time', 'N/A')),
                str(record.get('ArtifactType', 'N/A')),
                str(record.get('LogSource', 'N/A')),
                description[:500],
            ))

    conn.executemany(
        "INSERT INTO correlations "
        "(entity, entity_type, timestamp, artifact_type, log_source, description) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    print(f"  [CORRELATE] Indexed {len(rows)} entity references.")
    return conn


def top_entities(conn, entity_type=None, min_types=None, limit=25):
    """Ranked leads for the Leads tab.

    Unfiltered, a lead is only interesting if it is corroborated by more than
    one artifact type, so the default is min_types=2. But some entity kinds
    legitimately live in a single artifact type — a USB serial only ever
    appears in USB rows — and requiring two sources made those categories
    return nothing at all. When the caller names an entity_type they have
    asked to see that category, so the corroboration requirement drops to 1.
    """
    if min_types is None:
        min_types = 1 if entity_type else 2

    sql = """
        SELECT entity, entity_type,
               COUNT(*) AS refs,
               COUNT(DISTINCT artifact_type) AS type_count,
               GROUP_CONCAT(DISTINCT artifact_type) AS types
        FROM correlations
    """
    params = []
    if entity_type:
        sql += " WHERE entity_type = ?"
        params.append(entity_type)
    sql += """
        GROUP BY entity, entity_type
        HAVING type_count >= ?
        ORDER BY type_count DESC, refs DESC
        LIMIT ?
    """
    params += [min_types, limit]

    rows = conn.execute(sql, params).fetchall()
    return pd.DataFrame(rows, columns=['Entity', 'Type', 'References',
                                       'TypeCount', 'ArtifactTypes'])


def pivot_entity(conn, entity, limit=200):
    """Every artifact mentioning one entity, for pivoting during an investigation.

    Identical descriptions are collapsed: a single registry key rewritten on
    every boot produced 200 byte-identical rows, which filled the pane without
    telling the examiner anything. Occurrences are counted instead, with the
    first and last time each was seen.
    """
    rows = conn.execute(
        "SELECT MIN(timestamp), MAX(timestamp), artifact_type, log_source, "
        "       MIN(description), COUNT(*) "
        "FROM correlations WHERE entity = ? "
        # Case-insensitive: the same path is recorded as both /Users/... and
        # /USERS/..., which a case-sensitive GROUP BY keeps as separate rows.
        "GROUP BY artifact_type, log_source, LOWER(description) "
        "ORDER BY MIN(timestamp) LIMIT ?",
        (entity.lower().strip(), limit),
    ).fetchall()
    return pd.DataFrame(
        rows, columns=['First Seen', 'Last Seen', 'ArtifactType',
                       'LogSource', 'Description', 'Occurrences']
    )


def find_temporal_cluster(df, anchor_time, window_minutes=10, limit=100):
    """Artifacts occurring near a point in time — 'what else happened then'."""
    if df is None or df.empty:
        return pd.DataFrame()

    timestamps = pd.to_datetime(
        df['Date and Time'], errors='coerce', format='mixed', utc=True
    )
    anchor = pd.to_datetime(anchor_time, errors='coerce', utc=True)
    if pd.isna(anchor):
        return pd.DataFrame()

    delta = timedelta(minutes=window_minutes)
    mask = timestamps.notna() & (timestamps >= anchor - delta) & (timestamps <= anchor + delta)
    columns = [c for c in ('Date and Time', 'ArtifactType', 'LogSource',
                           'Event ID', 'Task Category') if c in df.columns]
    return df.loc[mask, columns].head(limit)
