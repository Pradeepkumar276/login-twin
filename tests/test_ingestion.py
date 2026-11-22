import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import Config
from database.db import init_db
from database.repositories import get_security_events
from modules.soc_monitor.log_ingestion import ingest_json_events, IngestionError

class TestLogIngestion(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_ingestion.db")
        Config.DATABASE_PATH = cls.test_db
        init_db(cls.test_db)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    def test_soc_t01_valid_json_ingestion(self):
        """SOC-T01: Import valid JSON events -> Events normalized and stored."""
        valid_json = [
            {
                "event_time": "2026-11-20T10:00:00Z",
                "source": "unit_test",
                "event_type": "login",
                "outcome": "success",
                "source_ip": "192.0.2.1",
                "account_id": "test_account_01",
                "resource": "/dashboard",
                "details": {"method": "password"}
            }
        ]
        result = ingest_json_events(valid_json, source="unit_test", auto_detect=False)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["ingested_count"], 1)

        events = get_security_events(limit=5, filters={"source": "unit_test"})
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0]["account_id"], "test_account_01")
        self.assertEqual(events[0]["source_ip"], "192.0.2.1")

    def test_soc_t02_malformed_json_rejected(self):
        """SOC-T02: Import malformed JSON -> Clear error; no partial/corrupt batch stored."""
        malformed_raw = '{"broken_json": [1, 2, '
        with self.assertRaises(IngestionError):
            ingest_json_events(malformed_raw, source="unit_test")

if __name__ == "__main__":
    unittest.main()
