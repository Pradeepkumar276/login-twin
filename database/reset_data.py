import sqlite3
import os
import sys
import json
import hashlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import Config

def reset_to_clean_state(db_path=None):
    if db_path is None:
        db_path = Config.DATABASE_PATH
    
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = OFF")
    cur = conn.cursor()

    tables_to_clear = [
        "security_events",
        "alerts",
        "alert_events",
        "correlations",
        "correlation_members",
        "incidents",
        "incident_alerts",
        "incident_history",
        "url_scans",
        "url_findings",
        "simulation_events",
        "audit_logs"
    ]

    for tbl in tables_to_clear:
        cur.execute(f"DELETE FROM {tbl}")
        try:
            cur.execute(f"DELETE FROM sqlite_sequence WHERE name = '{tbl}'")
        except Exception:
            pass

    # Genesis audit record for SHA-256 hash chaining
    now_utc = datetime.now(timezone.utc).isoformat()
    genesis_prev = "0" * 64
    genesis_canonical = f"1|{genesis_prev}|SYSTEM_INIT|SYSTEM|1|{json.dumps({'message': 'Login Twin system initialized with clean operational state'})}|{now_utc}"
    genesis_hash = hashlib.sha256(genesis_canonical.encode("utf-8")).hexdigest()

    cur.execute(
        """INSERT INTO audit_logs (id, actor_id, action, entity_type, entity_id, details_json, previous_hash, entry_hash, created_at)
           VALUES (1, NULL, 'SYSTEM_INIT', 'SYSTEM', '1', ?, ?, ?, ?)""",
        (json.dumps({"message": "Login Twin system initialized with clean operational state"}), genesis_prev, genesis_hash, now_utc)
    )

    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()
    conn.close()
    print("Database successfully reset: All pre-data cleared! 0 events, 0 alerts, 0 incidents.")

if __name__ == "__main__":
    reset_to_clean_state()
