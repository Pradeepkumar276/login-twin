import json
import os
import tempfile
import unittest
from unittest.mock import patch

from app import app
from config import Config
from database.db import init_db
from database.repositories import create_url_scan, insert_security_events_batch
from modules.phishing_lab.awareness import evaluate_phishing_submission


class TestDashboardMetrics(unittest.TestCase):
    def test_saved_entries_are_included_in_dashboard_stats(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            test_db = os.path.join(temp_dir, "dashboard.db")
            with patch.object(Config, "DATABASE_PATH", test_db):
                init_db(test_db)
                insert_security_events_batch(
                    [{
                        "event_time": "2026-11-22T10:00:00+00:00",
                        "event_type": "login",
                        "outcome": "success",
                        "source_ip": "192.0.2.45",
                        "account_id": "dashboard_test_user",
                        "resource": "/login",
                    }],
                    source="dashboard_test",
                )
                create_url_scan(
                    submitted_url="https://example.invalid/login",
                    normalized_host="example.invalid",
                    score=10,
                    risk_level="Low",
                    findings=[],
                )
                evaluate_phishing_submission(
                    scenario_code="PH-001",
                    selected_indicator_ids=[],
                    selected_action_id="report",
                )

                with app.test_client() as client:
                    response = client.get("/api/dashboard/stats")
                    download = client.get("/dashboard/export")

            self.assertEqual(response.status_code, 200)
            metrics = response.get_json()
            self.assertEqual(metrics["total_events"], 1)
            self.assertEqual(metrics["total_url_scans"], 1)
            self.assertEqual(metrics["completed_quizzes"], 1)

            self.assertEqual(download.status_code, 200)
            self.assertIn("attachment; filename=login_twin_security_report_", download.headers["Content-Disposition"])
            report = json.loads(download.data)
            self.assertEqual(len(report["security_events"]), 1)
            self.assertEqual(len(report["url_scans"]), 1)
            self.assertEqual(len(report["phishing_quiz_results"]), 1)


if __name__ == "__main__":
    unittest.main()
