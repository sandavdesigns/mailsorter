import os
import unittest
from unittest import mock

os.environ.setdefault("APP_SECRET", "test-secret-with-at-least-24-characters")

from app import exchange
from app.exchange import apply_rules, clean_html, forward_message, move_message, rule_matches, test_mailbox_connection, test_mode_enabled
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

    def test_test_mode_is_fail_safe_and_blocks_external_actions(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(test_mode_enabled())
            with self.assertRaisesRegex(RuntimeError, "Testmodus aktiv"):
                forward_message(999, "target@example.org", "test")
            with self.assertRaisesRegex(RuntimeError, "Testmodus aktiv"):
                move_message(999, "INBOX/Archiv", "test")

    def test_test_mode_requires_explicit_false(self):
        with mock.patch.dict(os.environ, {"TEST_MODE": "false"}, clear=False):
            self.assertFalse(test_mode_enabled())
        with mock.patch.dict(os.environ, {"TEST_MODE": "unexpected"}, clear=False):
            self.assertTrue(test_mode_enabled())

    def test_automatic_rule_only_logs_in_test_mode(self):
        message = {"id": 7, "mailbox_id": 2, "sender": "billing@example.org", "recipients": "inbox@example.org", "subject": "Rechnung", "text_body": "Test"}
        rule = {"id": 3, "mailbox_id": None, "field": "subject", "operator": "contains", "value": "Rechnung", "action": "forward", "target_email": "team@example.org", "user_email": None, "target_folder": None, "stop_processing": 1}
        with mock.patch.dict(os.environ, {"TEST_MODE": "true"}, clear=False), \
             mock.patch.object(exchange.db, "row", return_value=message), \
             mock.patch.object(exchange.db, "rows", return_value=[rule]), \
             mock.patch.object(exchange.db, "audit") as audit, \
             mock.patch.object(exchange, "forward_message") as forward, \
             mock.patch.object(exchange, "move_message") as move:
            apply_rules(7)
            forward.assert_not_called()
            move.assert_not_called()
            audit.assert_called_once()
            self.assertEqual(audit.call_args.args[0], "rule_test_match")

    def test_mailbox_connection_test_does_not_send_mail(self):
        settings = {"imap_host": "exchange.example.org", "imap_port": 993, "imap_ssl": True, "smtp_host": "exchange.example.org", "smtp_port": 587, "smtp_mode": "starttls", "username": "svc", "folder": "INBOX"}
        with mock.patch.object(exchange.imaplib, "IMAP4_SSL") as imap_class, \
             mock.patch.object(exchange.smtplib, "SMTP") as smtp_class:
            imap_class.return_value.select.return_value = ("OK", [])
            result = test_mailbox_connection(settings, "secret")
            self.assertTrue(result["ok"])
            imap_class.return_value.login.assert_called_once_with("svc", "secret")
            smtp_class.return_value.login.assert_called_once_with("svc", "secret")
            self.assertFalse(smtp_class.return_value.send_message.called)


class RuleTests(unittest.TestCase):
    message = {"sender": "Rechnung <billing@example.org>", "subject": "Rechnung 4711", "recipients": "inbox@example.org", "text_body": "Betrag 25 EUR"}

    def test_contains_case_insensitive(self):
        self.assertTrue(rule_matches({"field": "subject", "operator": "contains", "value": "RECHNUNG"}, self.message))

    def test_regex(self):
        self.assertTrue(rule_matches({"field": "body", "operator": "regex", "value": r"\d+ EUR"}, self.message))
        self.assertFalse(rule_matches({"field": "body", "operator": "regex", "value": "["}, self.message))


if __name__ == "__main__":
    unittest.main()
