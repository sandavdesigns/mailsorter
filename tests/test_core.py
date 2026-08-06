import email
import os
import unittest
from unittest import mock

os.environ.setdefault("APP_SECRET", "test-secret-with-at-least-24-characters")

from app import exchange
from app.exchange import apply_rules, authenticate_imap_ntlm, clean_html, connect_imap_with_password, connection_error, decoded, forward_message, imap_tls_channel_bindings, message_bodies, move_message, rule_matches, test_mailbox_connection, test_mode_enabled
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
        result = clean_html('<p style="color:#123;position:fixed">Hallo</p><script>alert(1)</script><a href="data:text/html,bad">bad</a><img src="https://tracker/x">')
        self.assertIn("Hallo", result)
        self.assertNotIn("script", result)
        self.assertNotIn("position", result)
        self.assertIn('style="color:#123;"', result)
        self.assertIn('data-external-src="https://tracker/x"', result)
        self.assertNotIn('<img src=', result)
        self.assertNotIn('href="data:', result)

    def test_message_charset_falls_back_to_windows_1252(self):
        msg = email.message_from_bytes(
            b"Content-Type: text/plain\r\nContent-Transfer-Encoding: 8bit\r\n\r\nGr\xfc\xdfe aus K\xf6ln"
        )
        text, html = message_bodies(msg)
        self.assertEqual(text, "Grüße aus Köln")
        self.assertIn("Grüße aus Köln", html)
        self.assertEqual(decoded("=?windows-1252?Q?Gr=FC=DFe_aus_K=F6ln?="), "Grüße aus Köln")

    def test_inline_cid_images_are_embedded_and_remote_images_are_opt_in(self):
        msg = email.message.EmailMessage()
        msg.set_content("Grüße")
        msg.add_alternative('<p style="font-family:Arial">Grüße</p><img src="cid:logo"><img src="https://example.org/tracker.png">', subtype="html")
        msg.get_payload()[1].add_related(b"png-data", maintype="image", subtype="png", cid="<logo>")
        text, html = message_bodies(msg)
        self.assertEqual(text.strip(), "Grüße")
        self.assertIn("Grüße", html)
        self.assertIn("src=\"data:image/png;base64,", html)
        self.assertIn('data-external-src="https://example.org/tracker.png"', html)
        self.assertNotIn('<img src="https://example.org', html)

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
        settings = {"imap_host": "exchange.example.org", "imap_port": 993, "imap_ssl": True, "smtp_host": "exchange.example.org", "smtp_port": 587, "smtp_mode": "starttls", "username": "legacy", "imap_username": "imap-svc", "smtp_username": "smtp-svc", "folder": "INBOX"}
        with mock.patch.object(exchange.imaplib, "IMAP4_SSL") as imap_class, \
             mock.patch.object(exchange.smtplib, "SMTP") as smtp_class:
            imap_class.return_value.select.return_value = ("OK", [])
            result = test_mailbox_connection(settings, "secret")
            self.assertTrue(result["ok"])
            imap_class.return_value.login.assert_called_once_with("imap-svc", "secret")
            smtp_class.return_value.login.assert_called_once_with("smtp-svc", "secret")
            self.assertFalse(smtp_class.return_value.send_message.called)

    def test_exchange_errors_include_actionable_hints(self):
        smtp_hint = connection_error(Exception("[SSL: WRONG_VERSION_NUMBER] wrong version number"), "smtp", {"smtp_port": 587})
        self.assertIn("STARTTLS", smtp_hint)
        imap_hint = connection_error(Exception("b'LOGIN failed.'"), "imap", {})
        self.assertIn("UPN", imap_hint)
        self.assertIn("primäre SMTP-Adresse", imap_hint)
        ntlm_hint = connection_error(Exception("NTLM AUTHENTICATE failed (mit TLS-Kanalbindung)"), "imap", {})
        self.assertIn("DOMAIN\\dienstkonto/postfachalias", ntlm_hint)
        self.assertIn("Full-Access", ntlm_hint)

    def test_ntlm_uses_tls_server_endpoint_channel_binding(self):
        client = mock.MagicMock()
        binding = mock.sentinel.channel_binding
        context = mock.MagicMock()
        settings = {"imap_host": "exchange.example.org", "imap_username": "DOMAIN\\svc"}
        with mock.patch.object(exchange, "imap_tls_channel_bindings", return_value=binding), \
             mock.patch.object(exchange.spnego, "client", return_value=context) as spnego_client:
            authenticate_imap_ntlm(client, settings, "secret")
        self.assertIs(spnego_client.call_args.kwargs["channel_bindings"], binding)
        self.assertEqual(spnego_client.call_args.kwargs["protocol"], "ntlm")
        client.authenticate.assert_called_once()

    def test_tls_channel_binding_uses_sha256_for_sha1_certificate(self):
        client = mock.MagicMock()
        client.sock.getpeercert.return_value = b"certificate"
        certificate = mock.MagicMock()
        certificate.signature_hash_algorithm.name = "sha1"
        with mock.patch.object(exchange.x509, "load_der_x509_certificate", return_value=certificate):
            binding = imap_tls_channel_bindings(client)
        self.assertEqual(binding.application_data, b"tls-server-end-point:" + exchange.hashlib.sha256(b"certificate").digest())

    def test_imap_auto_falls_back_to_ntlm(self):
        settings = {"imap_host": "exchange.example.org", "imap_port": 993, "imap_ssl": True, "imap_username": "DOMAIN\\svc", "username": "DOMAIN\\svc", "imap_auth_mode": "auto"}
        login_client, ntlm_client = mock.MagicMock(), mock.MagicMock()
        login_client.login.side_effect = exchange.imaplib.IMAP4.error("LOGIN failed")
        login_client.capabilities = (b"IMAP4REV1", b"AUTH=NTLM")
        with mock.patch.object(exchange, "open_imap", side_effect=[login_client, ntlm_client]), \
             mock.patch.object(exchange, "authenticate_imap_ntlm") as ntlm_auth:
            connected = connect_imap_with_password(settings, "secret")
            self.assertIs(connected, ntlm_client)
            ntlm_auth.assert_called_once_with(ntlm_client, settings, "secret")

    def test_ntlm_mode_skips_plain_login(self):
        settings = {"imap_host": "exchange.example.org", "imap_port": 993, "imap_ssl": True, "imap_username": "DOMAIN\\svc", "username": "DOMAIN\\svc", "imap_auth_mode": "ntlm"}
        client = mock.MagicMock()
        with mock.patch.object(exchange, "open_imap", return_value=client), \
             mock.patch.object(exchange, "authenticate_imap_ntlm") as ntlm_auth:
            connect_imap_with_password(settings, "secret")
            client.login.assert_not_called()
            ntlm_auth.assert_called_once()


class RuleTests(unittest.TestCase):
    message = {"sender": "Rechnung <billing@example.org>", "subject": "Rechnung 4711", "recipients": "inbox@example.org", "text_body": "Betrag 25 EUR"}

    def test_contains_case_insensitive(self):
        self.assertTrue(rule_matches({"field": "subject", "operator": "contains", "value": "RECHNUNG"}, self.message))

    def test_regex(self):
        self.assertTrue(rule_matches({"field": "body", "operator": "regex", "value": r"\d+ EUR"}, self.message))
        self.assertFalse(rule_matches({"field": "body", "operator": "regex", "value": "["}, self.message))


if __name__ == "__main__":
    unittest.main()
