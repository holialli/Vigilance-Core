"""Investigator-facing analysis: keyword search, timeline aggregation, triage."""

import re

import pandas as pd

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Event IDs are matched against the Event ID column, never as a substring of the
# description: "1102" also appears inside strings like "dot3svc.dll,-1102" and
# GUIDs such as {3061954e-edaa-4625-...}, which produced false positives.
_TRIAGE_RULES = [
    {"label": "Audit log cleared (anti-forensics)", "severity": "critical",
     "event_ids": {"1102"}, "sources": {"SECURITY"}},
    {"label": "Security tooling disabled", "severity": "critical",
     "pattern": r'disable(?:antispyware|antivirus|realtimemonitoring)\s*=\s*1'},
    {"label": "User account created", "severity": "high",
     "event_ids": {"4720"}, "sources": {"SECURITY"}},
    {"label": "Repeated failed logons", "severity": "high",
     "event_ids": {"4625"}, "sources": {"SECURITY"}, "min_count": 5},
    {"label": "Registry persistence (Run/RunOnce)", "severity": "high",
     "pattern": r'currentversion\\run(?:once)?\\', "types": {"REGISTRY"}},
    {"label": "Removable media attached", "severity": "medium",
     "types": {"USB"}},
    {"label": "Items in Recycle Bin", "severity": "low",
     "types": {"RECYCLE"}},
    {"label": "Email/communication archives present", "severity": "low",
     "types": {"COMMUNICATION"}},
]


def search_artifacts(df, query, use_regex=False, artifact_type=None, limit=500):
    """Free-text or regex search across artifact descriptions.

    Returns a display-ready frame. Invalid regex is reported rather than raised
    so a typo in the UI cannot take the app down.
    """
    if df is None or df.empty:
        return pd.DataFrame(), "No case loaded."

    working = df
    if artifact_type and artifact_type != "All":
        working = working[
            working['ArtifactType'].astype(str).str.upper() == artifact_type.upper()
        ]

    query = (query or "").strip()
    if not query:
        return pd.DataFrame(), "Enter a search term."

    descriptions = working['Task Category'].fillna('').astype(str)
    try:
        mask = descriptions.str.contains(query, case=False, regex=use_regex, na=False)
    except re.error as exc:
        return pd.DataFrame(), f"Invalid regular expression: {exc}"

    hits = working[mask]
    total = len(hits)
    if total == 0:
        return pd.DataFrame(), f"No matches for '{query}'."

    columns = [c for c in ('Date and Time', 'ArtifactType', 'LogSource',
                           'Event ID', 'Task Category', 'AnomalyLabel')
               if c in hits.columns]
    shown = hits[columns].head(limit)
    note = f"{total} match{'es' if total != 1 else ''} for '{query}'"
    if total > limit:
        note += f" (showing first {limit})"
    return shown, note


def build_timeline(df, freq='D', artifact_type=None):
    """Aggregate artifacts into time buckets for plotting.

    freq follows pandas offset aliases ('h' hourly, 'D' daily, 'W' weekly).
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=['Period', 'ArtifactType', 'Count'])

    working = df
    if artifact_type and artifact_type != "All":
        working = working[
            working['ArtifactType'].astype(str).str.upper() == artifact_type.upper()
        ]
    if working.empty:
        return pd.DataFrame(columns=['Period', 'ArtifactType', 'Count'])

    # utc=True: extractors emit a mix of naive and 'UTC'-suffixed timestamps,
    # which otherwise raises on mixed timezones. Dropped back to naive UTC so
    # period bucketing does not warn about discarding tz info.
    timestamps = pd.to_datetime(
        working['Date and Time'], errors='coerce', format='mixed', utc=True
    ).dt.tz_localize(None)
    valid = timestamps.notna()
    if not valid.any():
        return pd.DataFrame(columns=['Period', 'ArtifactType', 'Count'])

    grouped = pd.DataFrame({
        'Period': timestamps[valid].dt.to_period(freq).dt.to_timestamp(),
        'ArtifactType': working.loc[valid, 'ArtifactType'].astype(str),
    })
    out = grouped.groupby(['Period', 'ArtifactType']).size().reset_index(name='Count')
    return out.sort_values('Period').reset_index(drop=True)


def activity_peaks(df, top_n=5):
    """Busiest days — where an examiner should look first."""
    timeline = build_timeline(df, freq='D')
    if timeline.empty:
        return pd.DataFrame(columns=['Period', 'Count'])
    daily = timeline.groupby('Period')['Count'].sum().reset_index()
    return daily.nlargest(top_n, 'Count').reset_index(drop=True)


def triage_findings(df, max_examples=3):
    """Rule-driven findings ranked by severity.

    Runs on upload so the examiner starts from leads rather than a blank prompt.
    Ranked by severity rather than raw count: 1,000 registry rows mentioning USB
    matter far less than one cleared audit log.
    """
    if df is None or df.empty:
        return []

    descriptions = df['Task Category'].fillna('').astype(str)
    types_upper = df['ArtifactType'].fillna('').astype(str).str.upper()
    event_ids = df['Event ID'].astype(str).str.strip() if 'Event ID' in df.columns else None
    sources = (df['LogSource'].fillna('').astype(str).str.upper()
               if 'LogSource' in df.columns else None)

    findings = []
    for rule in _TRIAGE_RULES:
        mask = pd.Series(True, index=df.index)
        if "types" in rule:
            mask &= types_upper.isin(rule["types"])
        if "event_ids" in rule and event_ids is not None:
            mask &= event_ids.isin(rule["event_ids"])
        # Windows security event IDs only carry their documented meaning in the
        # Security channel; 4625 in APPLICATION is an unrelated event.
        if "sources" in rule and sources is not None:
            mask &= sources.isin(rule["sources"])
        if "pattern" in rule:
            mask &= descriptions.str.contains(
                rule["pattern"], case=False, regex=True, na=False
            )

        count = int(mask.sum())
        if count < rule.get("min_count", 1):
            continue

        findings.append({
            "label": rule["label"],
            "severity": rule["severity"],
            "count": count,
            "examples": descriptions[mask].head(max_examples).tolist(),
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["count"]))
    return findings


def anomaly_overview(df):
    """Summarise ML anomaly scoring, including how much of the case it flags.

    The flag rate is reported so an examiner can see when the model is firing on
    a large share of the case and therefore carries little signal on its own.
    """
    if df is None or df.empty or 'AnomalyScore' not in df.columns:
        return None

    flagged = int((df['AnomalyScore'] == -1).sum())
    total = int(len(df))
    rate = flagged / total if total else 0.0

    heuristic = 0
    if 'AnomalyLabel' in df.columns:
        heuristic = int(df['AnomalyLabel'].astype(str)
                        .str.contains("HEURISTIC", case=False, na=False).sum())

    return {
        "flagged": flagged,
        "total": total,
        "rate": rate,
        "heuristic": heuristic,
        "statistical": max(flagged - heuristic, 0),
        "noisy": rate > 0.10,
    }


def format_triage_markdown(findings, anomalies=None):
    lines = []
    if not findings:
        lines.append("No high-signal findings were detected by the triage rules.")
    else:
        lines += ["### Priority findings", ""]
        for f in findings:
            lines.append(
                f"**[{f['severity'].upper()}] {f['label']}** — {f['count']} artifact(s)"
            )
            for ex in f["examples"]:
                snippet = ex if len(ex) <= 160 else ex[:160] + "…"
                lines.append(f"  - {snippet}")
            lines.append("")

    if anomalies:
        lines += ["### Anomaly scoring", ""]
        lines.append(
            f"{anomalies['heuristic']} heuristic threat match(es); "
            f"{anomalies['statistical']} statistical outlier(s) "
            f"({anomalies['rate']:.0%} of {anomalies['total']} artifacts)."
        )
        if anomalies["noisy"]:
            lines.append(
                "*The statistical model is flagging a large share of this case, "
                "so treat those scores as weak signal and prioritise the "
                "rule-based findings above.*"
            )
    return "\n".join(lines)
