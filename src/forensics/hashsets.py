"""File hashing and hash-set (known-good / known-bad) matching.

Hashing every file on an image is prohibitively slow, so hashing targets the
files an examiner actually triages: executables, archives, documents, and
anything recovered as deleted.
"""

import hashlib
import os
import re

import pandas as pd

NOTABLE_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1', '.vbs',
    '.js', '.jar', '.msi', '.zip', '.rar', '.7z', '.iso',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
}

_HASH_LINE = re.compile(r'\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b')


def load_hashset(path):
    """Load hashes from a text/CSV file (NSRL exports work).

    Any 32/40/64-hex token on a line is treated as a hash, so plain hash lists
    and CSV rows with extra columns both load without a format flag.
    """
    hashes = set()
    if not path or not os.path.exists(path):
        return hashes
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            if line.startswith('#'):
                continue
            for match in _HASH_LINE.findall(line):
                hashes.add(match.lower())
    return hashes


def hash_stream(read_chunk, chunk_size=65536):
    """Compute MD5 and SHA-256 in a single pass over a chunk iterator."""
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    for chunk in read_chunk:
        md5.update(chunk)
        sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def hash_image_files(fs, file_rows, max_files=2000, max_size=64 * 1024 * 1024):
    """Hash notable files referenced by filesystem rows.

    file_rows: iterable of dicts with _filepath/_extension/_size/_is_dir keys.
    Bounded by max_files and max_size so a carve cannot run unbounded.
    """
    results = []
    hashed = 0

    for row in file_rows:
        if hashed >= max_files:
            break
        if row.get('_is_dir'):
            continue
        size = row.get('_size') or 0
        if size <= 0 or size > max_size:
            continue
        ext = (row.get('_extension') or '').lower()
        if ext not in NOTABLE_EXTENSIONS and not row.get('_deleted'):
            continue

        path = row.get('_filepath')
        try:
            f_obj = fs.open(path)

            def chunks(handle=f_obj, total=size):
                offset = 0
                while offset < total:
                    n = min(65536, total - offset)
                    data = handle.read_random(offset, n)
                    if not data:
                        break
                    offset += len(data)
                    yield data

            md5, sha256 = hash_stream(chunks())
        except Exception:
            continue

        results.append({**row, '_md5': md5, '_sha256': sha256})
        hashed += 1

    return results


def match_hashsets(rows, known_bad=None, known_good=None):
    """Tag hashed rows against known-bad / known-good sets.

    Returns artifact records for known-bad hits only; known-good membership is
    recorded on the row so the caller can suppress OS noise from review.
    """
    known_bad = known_bad or set()
    known_good = known_good or set()
    records = []

    for row in rows:
        md5 = (row.get('_md5') or '').lower()
        sha256 = (row.get('_sha256') or '').lower()
        row['_known_good'] = bool(
            (md5 and md5 in known_good) or (sha256 and sha256 in known_good)
        )
        hit = (md5 and md5 in known_bad) or (sha256 and sha256 in known_bad)
        row['_known_bad'] = bool(hit)
        if hit:
            records.append({
                'Date and Time': row.get('Date and Time', 'N/A'),
                'Event ID': '9950',
                'Task Category': (
                    f"HASH SET HIT (known-bad): {row.get('_filepath')} "
                    f"(MD5: {md5 or 'n/a'}, SHA-256: {sha256 or 'n/a'})"
                ),
                'LogSource': 'HASHSET',
                'Keywords': 'Alert',
                'ArtifactType': 'HASHMATCH',
            })

    return pd.DataFrame(records)


def hash_summary(rows):
    """Counts for the dashboard/report."""
    total = len(rows)
    return {
        "hashed": total,
        "known_bad": sum(1 for r in rows if r.get('_known_bad')),
        "known_good": sum(1 for r in rows if r.get('_known_good')),
        "unknown": sum(1 for r in rows
                       if not r.get('_known_bad') and not r.get('_known_good')),
    }
