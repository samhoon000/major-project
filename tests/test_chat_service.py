import unittest

from backend.chat_service import inspect_message, state, behavior_risk, behavior_analyzer


class ChatSecurityTests(unittest.TestCase):
    def setUp(self):
        state.sent.clear()
        behavior_analyzer.users.clear()

    def test_ordinary_message_has_no_url_risk(self):
        result = inspect_message("See you tomorrow")
        self.assertFalse(result["suspicious_url"])
        self.assertEqual(result["url_risk"], 0.0)

    def test_suspicious_url_is_flagged_without_visiting_it(self):
        result = inspect_message("URGENT verify account http://192.168.1.8/login")
        self.assertTrue(result["suspicious_url"])
        self.assertGreaterEqual(result["url_risk"], 0.6)
        self.assertGreaterEqual(len(result["urls"][0]["indicators"]), 2)

    def test_repetition_and_recipient_spread_raise_behavior_risk(self):
        score = 0.0
        for i in range(10):
            score, details = behavior_risk("alice", f"recipient{i % 2}", "same text")
        self.assertGreater(score, 0.0)
        self.assertEqual(details["repeated_messages"], 10)
        self.assertEqual(details["unique_recipients_last_minute"], 2)


if __name__ == "__main__":
    unittest.main()
