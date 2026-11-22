import unittest
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import Config
from database.db import init_db
from database.repositories import get_alerts
from modules.soc_monitor.log_ingestion import ingest_json_events
from modules.soc_monitor.detection_engine import run_all_detection_rules

class TestDetectionEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_detection.db")
        Config.DATABASE_PATH = cls.test_db
        init_db(cls.test_db)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    def test_det_t01_brute_force_5_failures(self):
        """DET-T01: 5 failed logins for one account in 5 minutes -> DET-001 alert created with evidence IDs."""
        now = datetime.now(timezone.utc)
        events = []
        for i in range(5):
            events.append({
                "event_time": (now + timedelta(seconds=i * 20)).isoformat(),
                "source": "det_test",
                "event_type": "login",
                "outcome": "failure",
                "source_ip": "192.0.2.10",
                "account_id": "victim_account_01",
                "resource": "/login"
            })
        ingest_json_events(events, source="det_test", auto_detect=False)
        alerts = run_all_detection_rules()
        det_001_alerts = [a for a in alerts if a["rule_code"] == "DET-001"]
        self.assertTrue(len(det_001_alerts) >= 1)
        self.assertGreaterEqual(det_001_alerts[0]["event_count"], 5)

    def test_det_t02_brute_force_below_threshold(self):
        """DET-T02: 4 failed logins for one account -> No DET-001 alert under threshold of 5."""
        now = datetime.now(timezone.utc) + timedelta(hours=1)
        events = []
        for i in range(4):
            events.append({
                "event_time": (now + timedelta(seconds=i * 20)).isoformat(),
                "source": "det_test",
                "event_type": "login",
                "outcome": "failure",
                "source_ip": "192.0.2.11",
                "account_id": "safe_account_below_threshold",
                "resource": "/login"
            })
        ingest_json_events(events, source="det_test", auto_detect=False)
        alerts = run_all_detection_rules()
        below_thresh = [a for a in alerts if "safe_account_below_threshold" in a.get("title", "")]
        self.assertEqual(len(below_thresh), 0)

    def test_det_t03_password_spraying_5_accounts(self):
        """DET-T03: One source fails against 5 distinct accounts in 10 minutes -> DET-002 alert created."""
        now = datetime.now(timezone.utc) + timedelta(hours=2)
        events = []
        accounts = ["user_a", "user_b", "user_c", "user_d", "user_e"]
        for idx, acc in enumerate(accounts):
            events.append({
                "event_time": (now + timedelta(seconds=idx * 30)).isoformat(),
                "source": "spray_test",
                "event_type": "login",
                "outcome": "failure",
                "source_ip": "198.51.100.99",
                "account_id": acc,
                "resource": "/login"
            })
        ingest_json_events(events, source="spray_test", auto_detect=False)
        alerts = run_all_detection_rules()
        det_002_alerts = [a for a in alerts if a["rule_code"] == "DET-002"]
        self.assertTrue(len(det_002_alerts) >= 1)

    def test_det_t04_repeated_access_denied(self):
        """DET-T04: Repeated access_denied events -> DET-004 alert created at configured threshold (5)."""
        now = datetime.now(timezone.utc) + timedelta(hours=3)
        events = []
        for i in range(5):
            events.append({
                "event_time": (now + timedelta(seconds=i * 20)).isoformat(),
                "source": "denied_test",
                "event_type": "access_denied",
                "outcome": "denied",
                "source_ip": "203.0.113.88",
                "account_id": "intruder_01",
                "resource": "/admin/keys"
            })
        ingest_json_events(events, source="denied_test", auto_detect=False)
        alerts = run_all_detection_rules()
        det_004_alerts = [a for a in alerts if a["rule_code"] == "DET-004"]
        self.assertTrue(len(det_004_alerts) >= 1)

if __name__ == "__main__":
    unittest.main()
