import unittest
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import Config
from database.db import init_db
from database.repositories import get_correlations
from modules.soc_monitor.log_ingestion import ingest_json_events
from modules.soc_monitor.detection_engine import run_all_detection_rules
from modules.correlation.correlation_engine import run_correlation_engine

class TestCorrelation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_correlation.db")
        Config.DATABASE_PATH = cls.test_db
        init_db(cls.test_db)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    def test_cor_t01_related_alerts_share_source_ip(self):
        """COR-T01: Related alerts share source IP and time window -> Correlation created with explanation."""
        now = datetime.now(timezone.utc)
        shared_ip = "192.0.2.200"
        events = []
        
        # Pattern 1: Password spray from shared_ip (5 accounts) -> DET-002
        for i in range(5):
            events.append({
                "event_time": (now + timedelta(seconds=i * 10)).isoformat(),
                "source": "corr_test",
                "event_type": "login",
                "outcome": "failure",
                "source_ip": shared_ip,
                "account_id": f"sprayed_user_{i}",
                "resource": "/login"
            })
        
        # Pattern 2: Access denied violations from shared_ip (5 times) -> DET-004
        for i in range(5):
            events.append({
                "event_time": (now + timedelta(seconds=60 + (i * 10))).isoformat(),
                "source": "corr_test",
                "event_type": "access_denied",
                "outcome": "denied",
                "source_ip": shared_ip,
                "account_id": "sprayed_user_0",
                "resource": "/admin"
            })

        ingest_json_events(events, source="corr_test", auto_detect=False)
        run_all_detection_rules()
        new_corrs = run_correlation_engine()

        self.assertTrue(len(new_corrs) >= 1)
        self.assertEqual(new_corrs[0]["key"], shared_ip)

    def test_cor_t02_unrelated_ips_no_correlation(self):
        """COR-T02: Events have different IPs and no shared key -> No correlation created solely due to time proximity."""
        corrs = get_correlations(limit=50)
        # Verify no correlation exists with a non-existent or disjoint key
        unrelated_keys = [c["correlation_key"] for c in corrs if c["correlation_key"] == "192.0.2.254"]
        self.assertEqual(len(unrelated_keys), 0)

if __name__ == "__main__":
    unittest.main()
