import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import Config
from database.db import init_db
from database.repositories import get_scenario_by_code
from modules.phishing_lab.awareness import evaluate_phishing_submission

class TestPhishingLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Use an isolated test database
        cls.test_db = os.path.join(os.path.dirname(__file__), "test_login_twin.db")
        Config.DATABASE_PATH = cls.test_db
        init_db(cls.test_db)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    def test_ph_t01_complete_scenario_all_correct(self):
        """PH-T01: Complete a scenario and choose all correct clues -> Score 100% and training event saved."""
        scenario = get_scenario_by_code("PH-001")
        self.assertIsNotNone(scenario)

        result = evaluate_phishing_submission(
            scenario_code="PH-001",
            selected_indicator_ids=scenario["correct_indicator_ids"],
            selected_action_id=scenario["correct_action_id"]
        )
        self.assertEqual(result["total_score"], 100)
        self.assertTrue(result["action_correct"])
        self.assertIsNotNone(result["event_id"])

    def test_ph_t02_no_password_stored_or_accepted(self):
        """PH-T02: Verify simulation never requests or stores passwords."""
        scenario = get_scenario_by_code("PH-001")
        # Ensure scenario data has no credential input requirement
        scenario_json_str = str(scenario).lower()
        self.assertNotIn("enter password", scenario_json_str)
        self.assertNotIn("password_hash", scenario_json_str)

if __name__ == "__main__":
    unittest.main()
