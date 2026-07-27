"""In-memory correlation database for cross-artifact pivoting."""

import sqlite3

def init_correlation_db():
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
