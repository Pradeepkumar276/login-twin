import sqlite3
import os
import json
from config import Config

def get_db_connection(db_path=None):
    if db_path is None:
        db_path = Config.DATABASE_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db(db_path=None):
    conn = get_db_connection(db_path)
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    
    # Seed default detection rules if none exist
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM detection_rules")
    if cur.fetchone()[0] == 0:
        rules_data = [
            (
                "DET-001",
                "Brute Force Detection",
                "Detects repeated failed login attempts against a single target account within a 5-minute sliding window.",
                json.dumps({"window_seconds": Config.BRUTE_FORCE_WINDOW_SECONDS, "threshold": Config.BRUTE_FORCE_THRESHOLD}),
                "High",
                1
            ),
            (
                "DET-002",
                "Password Spraying Detection",
                "Detects a single source IP attempting failed logins across multiple distinct user accounts within a 10-minute window.",
                json.dumps({"window_seconds": Config.SPRAY_WINDOW_SECONDS, "threshold": Config.SPRAY_DISTINCT_ACCOUNT_THRESHOLD}),
                "High",
                1
            ),
            (
                "DET-003",
                "Suspicious IP Activity",
                "Monitors an unusually high aggregate rate of failed, denied, or invalid security events from one source IP within 5 minutes.",
                json.dumps({"window_seconds": Config.IP_ACTIVITY_WINDOW_SECONDS, "threshold": Config.IP_ACTIVITY_THRESHOLD}),
                "Medium",
                1
            ),
            (
                "DET-004",
                "Repeated Unauthorized Access",
                "Flags repeated access_denied authorization failures from a source IP or account within 5 minutes.",
                json.dumps({"window_seconds": Config.DENIED_ACCESS_WINDOW_SECONDS, "threshold": Config.DENIED_ACCESS_THRESHOLD}),
                "Medium",
                1
            ),
            (
                "DET-005",
                "Abnormal Request Activity",
                "Identifies bursts of malformed or invalid client requests from a single source IP within 2 minutes.",
                json.dumps({"window_seconds": Config.INVALID_REQUEST_WINDOW_SECONDS, "threshold": Config.INVALID_REQUEST_THRESHOLD}),
                "Medium",
                1
            )
        ]
        cur.executemany(
            "INSERT INTO detection_rules (rule_code, name, description, threshold_json, severity, enabled) VALUES (?, ?, ?, ?, ?, ?)",
            rules_data
        )

    # Seed default phishing simulation scenarios if none exist
    cur.execute("SELECT COUNT(*) FROM simulation_scenarios")
    if cur.fetchone()[0] == 0:
        from modules.phishing_lab.scenarios import DEFAULT_SCENARIOS
        for sc in DEFAULT_SCENARIOS:
            cur.execute(
                "INSERT INTO simulation_scenarios (code, title, content_json, is_active) VALUES (?, ?, ?, 1)",
                (sc["code"], sc["title"], json.dumps(sc))
            )
    
    # Check if audit_logs has a genesis hash block
    cur.execute("SELECT COUNT(*) FROM audit_logs")
    if cur.fetchone()[0] == 0:
        import hashlib
        from datetime import datetime, timezone
        now_utc = datetime.now(timezone.utc).isoformat()
        genesis_prev = "0" * 64
        genesis_canonical = f"1|{genesis_prev}|SYSTEM_INIT|SYSTEM|1|{json.dumps({'message': 'Login Twin system initialized'})}|{now_utc}"
        genesis_hash = hashlib.sha256(genesis_canonical.encode("utf-8")).hexdigest()
        cur.execute(
            """INSERT INTO audit_logs (id, actor_id, action, entity_type, entity_id, details_json, previous_hash, entry_hash, created_at)
               VALUES (1, NULL, 'SYSTEM_INIT', 'SYSTEM', '1', ?, ?, ?, ?)""",
            (json.dumps({'message': 'Login Twin system initialized'}), genesis_prev, genesis_hash, now_utc)
        )

    conn.commit()
    conn.close()
