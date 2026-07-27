"""Per-browser-session case state."""

import threading


class CaseSession:
    """Per-browser-session case state (one per Gradio gr.State instance)."""
    def __init__(self):
        self.current_audit_df = None
        self.faiss_index = None
        self.image_hash_sha256 = None
        self.artifact_counts = {}
        self.cached_system_facts = None
        self.session_log = []
        self.correlation_db = None
        self.faiss_lock = threading.Lock()
