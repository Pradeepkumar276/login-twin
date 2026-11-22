import unittest
import os
import sys
import sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import Config
from database.db import init_db, get_db_connection
from database.repositories import (
    get_incident_by_id,
    add_audit_log,
    verify_audit_chain
)
from modules.incident_management.incidents import (
    create_new_incident,
    transition_incident,
    append_investigation_note
)
from modules.soc_monitor.log_ingestion import ingest_json_events
from modules.url_analyzer.analyzer import analyze_url

class TestIncidentsAndSecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_incidents.db")
        Config.DATABASE_PATH = cls.test_db
        init_db(cls.test_db)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    def test_inc_t01_lifecycle_transitions(self):
        """INC-T01: Analyst changes New -> Investigating -> Resolved -> Closed. Each transition appears in history."""
        inc_id = create_new_incident(
            title="Test Incident Lifecycle",
            severity="High",
            summary="Testing state machine"
        )
        self.assertIsNotNone(inc_id)

        # 1. New -> Investigating
        success = transition_incident(inc_id, "Investigating", note="Analyst triaging alert telemetry.")
        self.assertTrue(success)

        # 2. Investigating -> Resolved (requires note)
        success = transition_incident(inc_id, "Resolved", note="Identified false positive from internal security audit.")
        self.assertTrue(success)

        # 3. Resolved -> Closed
        success = transition_incident(inc_id, "Closed", note="Case documentation complete. Closed.")
        self.assertTrue(success)

        # Check full history
        details = get_incident_by_id(inc_id)
        self.assertEqual(details["status"], "Closed")
        self.assertTrue(len(details["history"]) >= 4) # initial + 3 transitions

    def test_sec_t01_sql_injection_resilience(self):
        """SEC-T01: Submit SQL injection payload in event and URL fields -> Handled safely as data."""
        sql_payload = "admin' OR '1'='1'; DROP TABLE users; --"
        # In URL Analyzer
        res = analyze_url(f"https://example.invalid/{sql_payload}", save_to_db=True)
        self.assertIsNotNone(res["scan_id"])

        # In Security Events
        event = [{
            "event_time": "2026-11-20T12:00:00Z",
            "source": "sql_test",
            "event_type": "login",
            "outcome": "failure",
            "source_ip": "192.0.2.1",
            "account_id": sql_payload,
            "resource": "/login"
        }]
        ingest_res = ingest_json_events(event, source="sql_test", auto_detect=False)
        self.assertEqual(ingest_res["status"], "success")

        # Verify tables still exist
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        self.assertIsNotNone(cur.fetchone())
        conn.close()

    def test_aud_t01_tamper_detection(self):
        """AUD-T01: Modify one audit row in database -> Hash-chain verification reports mismatch."""
        # Add legitimate audit log
        add_audit_log(action="INTEGRITY_CHECK_1", entity_type="TEST", entity_id=99)
        add_audit_log(action="INTEGRITY_CHECK_2", entity_type="TEST", entity_id=100)

        # Confirm valid chain before tampering
        is_valid, count, _, _ = verify_audit_chain()
        self.assertTrue(is_valid)

        # Tamper with an audit row directly in SQLite
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM audit_logs WHERE action = 'INTEGRITY_CHECK_1'")
        row = cur.fetchone()
        target_id = row["id"]
        # Maliciously modify the details_json
        cur.execute("UPDATE audit_logs SET action = 'MALICIOUS_ACTION_REWRITE' WHERE id = ?", (target_id,))
        conn.commit()
        conn.close()

        # Run verification -> MUST DETECT TAMPERING!
        is_valid, count, msg, mismatch = verify_audit_chain()
        self.assertFalse(is_valid)
        self.assertIn("tampering detected", msg.lower())

if __name__ == "__main__":
    unittest.main()
