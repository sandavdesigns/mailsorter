import os
import unittest

os.environ.setdefault("APP_SECRET", "test-secret-with-at-least-24-characters")

from app.exchange import clean_html, rule_matches
from app.security import decrypt, encrypt, hash_password, verify_password


class SecurityTests(unittest.TestCase):
    def test_password_hash(self):
        value = hash_password("a sufficiently long password")
        self.assertTrue(verify_password("a sufficiently long password", value))
        self.assertFalse(verify_password("wrong", value))

    def test_encryption_roundtrip(self):
        encrypted = encrypt("exchange-password")
        self.assertNotIn("exchange-password", encrypted)
        self.assertEqual(decrypt(encrypted), "exchange-password")

    def test_html_sanitization(self):
        result = clean_html('<p>Hallo</p><script>alert(1)</script><img src="https://tracker/x">')
        self.assertIn("Hallo", result)
        self.assertNotIn("script", result)
        self.assertNotIn("src=", result)


class RuleTests(unittest.TestCase):
    message = {"sender": "Rechnung <billing@example.org>", "subject": "Rechnung 4711", "recipients": "inbox@example.org", "text_body": "Betrag 25 EUR"}

    def test_contains_case_insensitive(self):
        self.assertTrue(rule_matches({"field": "subject", "operator": "contains", "value": "RECHNUNG"}, self.message))

    def test_regex(self):
        self.assertTrue(rule_matches({"field": "body", "operator": "regex", "value": r"\d+ EUR"}, self.message))
        self.assertFalse(rule_matches({"field": "body", "operator": "regex", "value": "["}, self.message))


if __name__ == "__main__":
    unittest.main()
