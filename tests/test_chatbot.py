import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.chatbot.explainer import answer_query

class TestChatbot(unittest.TestCase):

    def test_chatbot_url_query(self):
        res = answer_query("Explain URL analyzer rules")
        self.assertIn("URL", res["title"])
        self.assertIn("URL-001", res["answer"])
        self.assertTrue(len(res["suggestions"]) >= 1)

    def test_chatbot_detection_query(self):
        res = answer_query("What is brute force vs password spraying?")
        self.assertIn("Brute Force", res["answer"])
        self.assertIn("DET-001", res["answer"])

    def test_chatbot_hash_chain_query(self):
        res = answer_query("How does the SHA-256 hash chain work?")
        self.assertIn("Hash", res["title"])
        self.assertIn("SHA-256", res["answer"])

    def test_chatbot_viva_query(self):
        res = answer_query("viva exam questions")
        self.assertIn("Viva", res["title"])
        self.assertIn("Why SQLite", res["answer"])

    def test_chatbot_empty_fallback(self):
        res = answer_query("")
        self.assertIn("Login Twin", res["title"])

if __name__ == "__main__":
    unittest.main()
