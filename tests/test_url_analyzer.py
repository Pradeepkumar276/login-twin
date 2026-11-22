import unittest
import os
import sys

# Ensure login_twin directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.url_analyzer.analyzer import analyze_url, URLAnalysisError

class TestURLAnalyzer(unittest.TestCase):

    def test_url_t01_simple_https_url(self):
        """URL-T01: A simple HTTPS URL with ordinary host/path -> Low score, no network request."""
        res = analyze_url("https://subdomain.example.invalid/home/index.html", save_to_db=False)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertLessEqual(res["score"], 19)
        self.assertEqual(res["risk_wording"], "No strong indicators found by these checks")

    def test_url_t02_http_url(self):
        """URL-T02: HTTP URL -> HTTP indicator appears and adds configured points (+5)."""
        res = analyze_url("http://example.invalid/page", save_to_db=False)
        rule_ids = [f["rule_id"] for f in res["findings"]]
        self.assertIn("URL-001", rule_ids)
        http_finding = next(f for f in res["findings"] if f["rule_id"] == "URL-001")
        self.assertEqual(http_finding["points"], 5)

    def test_url_t03_ipv4_host(self):
        """URL-T03: URL with IPv4 host -> IP-literal finding appears (+20 points)."""
        res = analyze_url("http://192.0.2.1/login", save_to_db=False)
        rule_ids = [f["rule_id"] for f in res["findings"]]
        self.assertIn("URL-002", rule_ids)
        ip_finding = next(f for f in res["findings"] if f["rule_id"] == "URL-002")
        self.assertEqual(ip_finding["points"], 20)

    def test_url_t04_long_url_with_suspicious_terms(self):
        """URL-T04: Long URL with suspicious terms -> Relevant findings appear; score capped at 100."""
        long_url = (
            "http://192.0.2.55/portal/login/verify/update/account/security/password/"
            "banking/auth/token?session=982348729384729384729384729384729384729384729384729"
        )
        res = analyze_url(long_url, save_to_db=False)
        rule_ids = [f["rule_id"] for f in res["findings"]]
        self.assertIn("URL-003", rule_ids)
        self.assertIn("URL-004", rule_ids)
        self.assertLessEqual(res["score"], 100)
        self.assertIn(res["risk_level"], ["HIGH", "CRITICAL"])

    def test_url_t05_malformed_url(self):
        """URL-T05: Malformed URL text -> Validation message; no crash."""
        with self.assertRaises(URLAnalysisError):
            analyze_url("   ", save_to_db=False)
        with self.assertRaises(URLAnalysisError):
            analyze_url("a", save_to_db=False)

if __name__ == "__main__":
    unittest.main()
