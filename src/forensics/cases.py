"""Case persistence: save, list and reopen investigations.

A case is a directory under cache/ keyed by the image SHA-256, holding the
carved artifacts plus a manifest of examiner metadata. Reopening a case restores
the artifacts without re-carving the image.
"""

import json
import os
from datetime import datetime, timezone

import pandas as pd

from .config import CACHE_DIR

MANIFEST_NAME = "case.json"
ARTIFACTS_NAME = "artifacts.pkl"


def case_dir(image_hash):
    return os.path.join(CACHE_DIR, image_hash)


def save_case(image_hash, artifacts, case_name=None, examiner=None, notes=None,
              source_image=None, artifact_counts=None):
    """Persist artifacts plus examiner metadata for later reopening."""
    if not image_hash:
        raise ValueError("image_hash is required to save a case")

    directory = case_dir(image_hash)
    os.makedirs(directory, exist_ok=True)

    if artifacts is not None:
        artifacts.to_pickle(os.path.join(directory, ARTIFACTS_NAME))

    manifest = load_manifest(image_hash) or {}
    manifest.update({
        "image_hash": image_hash,
        "case_name": case_name or manifest.get("case_name") or f"Case {image_hash[:12]}",
        "examiner": examiner or manifest.get("examiner", ""),
        "notes": notes if notes is not None else manifest.get("notes", ""),
        "source_image": source_image or manifest.get("source_image", ""),
        "artifact_count": int(len(artifacts)) if artifacts is not None
        else manifest.get("artifact_count", 0),
        "artifact_counts": artifact_counts or manifest.get("artifact_counts", {}),
        "updated": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
    })
    manifest.setdefault("created", manifest["updated"])

    with open(os.path.join(directory, MANIFEST_NAME), 'w', encoding='utf-8') as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


def load_manifest(image_hash):
    path = os.path.join(case_dir(image_hash), MANIFEST_NAME)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def load_case(image_hash):
    """Return (artifacts, manifest) for a saved case, or (None, None)."""
    artifacts_path = os.path.join(case_dir(image_hash), ARTIFACTS_NAME)
    if not os.path.exists(artifacts_path):
        return None, None
    try:
        artifacts = pd.read_pickle(artifacts_path)
    except Exception:
        return None, None
    return artifacts, load_manifest(image_hash)


def list_cases():
    """All saved cases, most recently updated first."""
    if not os.path.isdir(CACHE_DIR):
        return pd.DataFrame(columns=['Case', 'Examiner', 'Artifacts',
                                     'Updated', 'Image SHA-256'])

    rows = []
    for entry in os.listdir(CACHE_DIR):
        directory = os.path.join(CACHE_DIR, entry)
        if not os.path.isdir(directory):
            continue
        if not os.path.exists(os.path.join(directory, ARTIFACTS_NAME)):
            continue
        manifest = load_manifest(entry) or {}
        rows.append({
            'Case': manifest.get('case_name', f"Case {entry[:12]}"),
            'Examiner': manifest.get('examiner', ''),
            'Artifacts': manifest.get('artifact_count', 0),
            'Updated': manifest.get('updated', ''),
            'Image SHA-256': entry,
        })

    frame = pd.DataFrame(rows)
    if frame.empty:
        return pd.DataFrame(columns=['Case', 'Examiner', 'Artifacts',
                                     'Updated', 'Image SHA-256'])
    return frame.sort_values('Updated', ascending=False).reset_index(drop=True)
