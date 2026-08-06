import email
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("APP_SECRET", "test-secret-with-at-least-24-characters")

from app import db, exchange, main
from app.exchange import apply_rules, authenticate_imap_ntlm, clean_html, connect_imap_with_password, connection_error, create_folder, decoded, forward_message, imap_mailbox_arg, imap_tls_channel_bindings, imap_utf7_decode, imap_utf7_encode, message_attachments, message_bodies, move_message, rule_matches, test_mailbox_connection, test_mode_enabled, test_mode_value
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

    def test_regular_attachments_are_listed_but_inline_images_are_not(self):
        msg = email.message.EmailMessage()
        msg.set_content("Text")
        msg.add_alternative('<img src="cid:logo">', subtype="html")
        msg.get_payload()[-1].add_related(b"png-data", maintype="image", subtype="png", cid="<logo>", filename="logo.png", disposition="inline")
        msg.add_attachment(b"pdf-data", maintype="application", subtype="pdf", filename="../Prüfung.pdf")
        attachments = message_attachments(msg)
        self.assertEqual(len(attachments), 1)
        self.assertEqual(attachments[0]["filename"], "Prüfung.pdf")
        self.assertEqual(attachments[0]["content_type"], "application/pdf")
        self.assertEqual(attachments[0]["content"], b"pdf-data")

    def test_oversized_attachment_is_visible_but_not_stored(self):
        msg = email.message.EmailMessage()
        msg.set_content("Text")
        msg.add_attachment(b"x" * (1024 * 1024 + 1), maintype="application", subtype="octet-stream", filename="gross.bin")
        with mock.patch.dict(os.environ, {"MAX_ATTACHMENT_MB": "1"}):
            attachment = message_attachments(msg)[0]
        self.assertEqual(attachment["stored"], 0)
        self.assertIsNone(attachment["content"])

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
            self.assertEqual(test_mode_value(), "false")
        with mock.patch.dict(os.environ, {"TEST_MODE": '"false"'}, clear=False):
            self.assertFalse(test_mode_enabled())
        with mock.patch.dict(os.environ, {"TEST_MODE": "'off'"}, clear=False):
            self.assertFalse(test_mode_enabled())
        with mock.patch.dict(os.environ, {"TEST_MODE": "live"}, clear=False):
            self.assertFalse(test_mode_enabled())
        with mock.patch.dict(os.environ, {"TEST_MODE": "unexpected"}, clear=False):
            self.assertTrue(test_mode_enabled())

    def test_test_mode_blocks_exchange_folder_creation(self):
        with mock.patch.dict(os.environ, {"TEST_MODE": "true"}, clear=False), \
             mock.patch.object(exchange, "connect_imap") as connect:
            with self.assertRaisesRegex(RuntimeError, "Testmodus aktiv"):
                create_folder({"id": 2}, "Rechnungen", "INBOX")
            connect.assert_not_called()

    def test_exchange_subfolder_creation_supports_umlauts(self):
        client = mock.MagicMock()
        client.list.side_effect = [
            ("OK", [b'(\\HasChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "INBOX/Archiv"']),
            ("OK", [b'(\\HasChildren) "/" "INBOX"', b'(\\HasChildren) "/" "INBOX/Archiv"', b'(\\HasNoChildren) "/" "INBOX/Archiv/Pr&APw-fung"']),
        ]
        client.create.return_value = ("OK", [b"CREATE completed"])
        with mock.patch.object(exchange, "test_mode_enabled", return_value=False), \
             mock.patch.object(exchange, "connect_imap", return_value=client):
            created = create_folder({"id": 2}, "Prüfung", "INBOX/Archiv")
        self.assertEqual(created, "INBOX/Archiv/Prüfung")
        client.create.assert_called_once_with(b'"INBOX/Archiv/Pr&APw-fung"')
        client.logout.assert_called_once()

    def test_exchange_folder_creation_defaults_under_configured_folder(self):
        client = mock.MagicMock()
        client.list.side_effect = [
            ("OK", [b'(\\HasChildren) "/" "INBOX"']),
            ("OK", [b'(\\HasChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "INBOX/Rechnungen"']),
        ]
        client.create.return_value = ("OK", [b"CREATE completed"])
        with mock.patch.object(exchange, "test_mode_enabled", return_value=False), \
             mock.patch.object(exchange, "connect_imap", return_value=client):
            created = create_folder({"id": 2, "folder": "INBOX"}, "Rechnungen", "")
        self.assertEqual(created, "INBOX/Rechnungen")
        client.create.assert_called_once_with(b'"INBOX/Rechnungen"')

    def test_exchange_folder_creation_requires_created_folder_to_be_listed(self):
        client = mock.MagicMock()
        client.list.return_value = ("OK", [b'(\\HasChildren) "/" "INBOX"'])
        client.create.return_value = ("OK", [b"CREATE completed"])
        with mock.patch.object(exchange, "test_mode_enabled", return_value=False), \
             mock.patch.object(exchange, "connect_imap", return_value=client), \
             self.assertRaisesRegex(RuntimeError, "erscheint danach nicht"):
            create_folder({"id": 2, "folder": "INBOX"}, "Rechnungen", "")

    def test_exchange_folder_list_decodes_utf7_utf8_and_windows_umlauts(self):
        client = mock.MagicMock()
        client.list.return_value = ("OK", [
            b'(\\HasNoChildren) "/" "INBOX/Pr&APw-fung"',
            b'(\\HasNoChildren) "/" "INBOX/B\xc3\xbcro"',
            b'(\\HasNoChildren) "/" "INBOX/R\xfcckfragen"',
        ])
        entries = exchange.folder_entries(client)
        self.assertEqual([entry["name"] for entry in entries], ["INBOX/Prüfung", "INBOX/Büro", "INBOX/Rückfragen"])
        self.assertEqual([entry["wire_encoding"] for entry in entries], ["imap-utf7", "utf-8", "cp1252"])

    def test_list_folders_only_returns_children_below_configured_inbox(self):
        client = mock.MagicMock()
        client.list.return_value = ("OK", [
            b'(\\HasChildren) "/" "INBOX"',
            b'(\\HasNoChildren) "/" "INBOX/Rechnungen"',
            b'(\\HasNoChildren) "/" "INBOX/Rechnungen/2026"',
            b'(\\HasNoChildren) "/" "Archiv"',
            b'(\\HasNoChildren) "/" "Gesendet"',
        ])
        with mock.patch.object(exchange, "connect_imap", return_value=client):
            folders = exchange.list_folders({"id": 2, "folder": "INBOX"})
        self.assertEqual(folders, [
            {"name": "INBOX/Rechnungen", "display": "Rechnungen"},
            {"name": "INBOX/Rechnungen/2026", "display": "Rechnungen/2026"},
        ])

    def test_exchange_folder_creation_follows_direct_utf8_server_encoding(self):
        client = mock.MagicMock()
        client.list.side_effect = [
            ("OK", [b'(\\HasChildren) "/" "INBOX/B\xc3\xbcro"']),
            ("OK", [b'(\\HasChildren) "/" "INBOX/B\xc3\xbcro"', b'(\\HasNoChildren) "/" "INBOX/B\xc3\xbcro/R\xc3\xbcckfragen"']),
        ]
        client.create.return_value = ("OK", [b"CREATE completed"])
        with mock.patch.object(exchange, "test_mode_enabled", return_value=False), \
             mock.patch.object(exchange, "connect_imap", return_value=client):
            created = create_folder({"id": 2}, "Rückfragen", "INBOX/Büro")
        self.assertEqual(created, "INBOX/Büro/Rückfragen")
        client.create.assert_called_once_with(b'"INBOX/B\xc3\xbcro/R\xc3\xbcckfragen"')

    def test_imap_folder_names_roundtrip_modified_utf7(self):
        name = "INBOX/Prüfung & Ablage 日本語"
        self.assertEqual(imap_utf7_decode(imap_utf7_encode(name)), name)
        self.assertEqual(imap_mailbox_arg("INBOX/Pr&APw-fung"), b'"INBOX/Pr&APw-fung"')

    def test_automatic_rule_only_logs_in_test_mode(self):
        message = {"id": 7, "mailbox_id": 2, "sender": "billing@example.org", "recipients": "inbox@example.org", "subject": "Rechnung", "text_body": "Test"}
        rule = {"id": 3, "mailbox_id": 2, "field": "subject", "operator": "contains", "value": "Rechnung", "action": "forward", "target_email": "team@example.org", "user_email": None, "target_folder": None, "post_forward_folder": "INBOX/Archiv", "stop_processing": 1}
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
            self.assertEqual(audit.call_args.kwargs["actions"], [{"action": "forward", "target": "team@example.org"}, {"action": "move", "target": "INBOX/Archiv"}])

    def test_forward_rule_can_move_message_after_forwarding(self):
        message = {"id": 7, "mailbox_id": 2, "sender": "billing@example.org", "recipients": "inbox@example.org", "subject": "Rechnung", "text_body": "Test"}
        rule = {"id": 3, "mailbox_id": 2, "field": "subject", "operator": "contains", "value": "Rechnung", "action": "forward", "target_email": "team@example.org", "user_email": None, "target_folder": None, "post_forward_folder": "INBOX/Archiv", "stop_processing": 1}
        with mock.patch.object(exchange, "test_mode_enabled", return_value=False), \
             mock.patch.object(exchange.db, "row", return_value=message), \
             mock.patch.object(exchange.db, "rows", return_value=[rule]), \
             mock.patch.object(exchange.db, "execute") as execute, \
             mock.patch.object(exchange, "forward_message") as forward, \
             mock.patch.object(exchange, "move_message") as move:
            apply_rules(7)
            forward.assert_called_once_with(7, "team@example.org", "rule", 3)
            move.assert_called_once_with(7, "INBOX/Archiv", "rule", 3)
            execute.assert_called_once_with("UPDATE messages SET matched_rule_id=? WHERE id=?", (3, 7))

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

    def test_forwarded_message_keeps_stored_attachments(self):
        message = {
            "id": 7, "email": "shared@example.org", "sender": "from@example.org", "recipients": "shared@example.org",
            "subject": "Unterlagen", "text_body": "Text", "html_body": "<p>Text</p>", "password_enc": "encrypted",
            "smtp_mode": "starttls", "smtp_host": "smtp.example.org", "smtp_port": 587,
            "smtp_username": "svc@example.org", "username": "svc@example.org", "mailbox_id": 2,
        }
        attachment = {"filename": "Prüfung.pdf", "content_type": "application/pdf", "size": 8, "stored": 1, "content": b"pdf-data"}
        smtp = mock.MagicMock()
        with mock.patch.object(exchange, "test_mode_enabled", return_value=False), \
             mock.patch.object(exchange.db, "row", return_value=message), \
             mock.patch.object(exchange.db, "rows", return_value=[attachment]), \
             mock.patch.object(exchange.db, "execute"), mock.patch.object(exchange.db, "audit"), \
             mock.patch.object(exchange, "decrypt", return_value="secret"), \
             mock.patch.object(exchange.smtplib, "SMTP", return_value=smtp):
            forward_message(7, "target@example.org", "test")
        sent = smtp.send_message.call_args.args[0]
        sent_attachments = list(sent.iter_attachments())
        self.assertEqual(len(sent_attachments), 1)
        self.assertEqual(sent_attachments[0].get_filename(), "Prüfung.pdf")
        self.assertEqual(sent_attachments[0].get_payload(decode=True), b"pdf-data")

    def test_attachment_download_is_forced_and_nosniff(self):
        attachment = {"id": 1, "filename": "Prüfung.pdf", "content_type": "application/pdf", "stored": 1, "content": b"pdf-data"}
        with mock.patch.object(main, "require_user"), mock.patch.object(db, "row", return_value=attachment):
            response = main.download_attachment(1, session=None)
        self.assertEqual(response.body, b"pdf-data")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertTrue(response.headers["content-disposition"].startswith("attachment;"))
        self.assertIn("filename*=UTF-8''Pr%C3%BCfung.pdf", response.headers["content-disposition"])

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

    def test_purge_mailbox_removes_local_messages_and_rules_but_keeps_audit(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            mailbox_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Alt", "alt@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 0, db.now_iso()))
            message_id = db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,created_at)
              VALUES(?,?,?,?,?,?)""", (mailbox_id, "1", "a@example.org", "b@example.org", "Test", db.now_iso()))
            db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,created_at) VALUES(?,?,?,?,?,?)""",
                       ("Postfachregel", mailbox_id, "subject", "contains", "Test", db.now_iso()))
            db.execute("""INSERT INTO attachments(message_id,filename,content_type,size,stored,content,created_at)
              VALUES(?,?,?,?,?,?,?)""", (message_id, "test.pdf", "application/pdf", 3, 1, b"pdf", db.now_iso()))
            db.audit("message_received", mailbox_id=mailbox_id, message_id=message_id)

            with mock.patch.object(main, "require_admin", return_value={"email": "admin@example.org"}):
                result = main.delete_mailbox(mailbox_id, session=None)
            details = result

            self.assertTrue(result["ok"])
            self.assertEqual(details["messages_deleted"], 1)
            self.assertEqual(details["attachments_deleted"], 1)
            self.assertEqual(details["rules_deleted"], 1)
            self.assertEqual(db.rows("SELECT * FROM mailboxes"), [])
            self.assertEqual(db.rows("SELECT * FROM messages"), [])
            self.assertEqual(db.rows("SELECT * FROM attachments"), [])
            self.assertEqual(db.rows("SELECT * FROM rules"), [])
            deletion = db.row("SELECT * FROM audit_log WHERE action='mailbox_deleted'")
            self.assertIsNotNone(deletion)
            self.assertIsNone(deletion["mailbox_id"])
            self.assertTrue(db.row("SELECT * FROM audit_log WHERE action='message_received'"))

    def test_sync_prunes_messages_missing_from_exchange_folder(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            mailbox_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Zentrale", "zentrale@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, db.now_iso()))
            keep_id = db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,created_at)
              VALUES(?,?,?,?,?,?)""", (mailbox_id, "10", "a@example.org", "zentrale@example.org", "Bleibt", db.now_iso()))
            remove_id = db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,created_at)
              VALUES(?,?,?,?,?,?)""", (mailbox_id, "11", "b@example.org", "zentrale@example.org", "Gelöscht", db.now_iso()))
            db.execute("""INSERT INTO attachments(message_id,filename,content_type,size,stored,content,created_at)
              VALUES(?,?,?,?,?,?,?)""", (remove_id, "alt.pdf", "application/pdf", 3, 1, b"pdf", db.now_iso()))

            removed = db.prune_mailbox_messages(mailbox_id, {"10"}, actor="sync")

            self.assertEqual(removed, 1)
            self.assertIsNotNone(db.row("SELECT * FROM messages WHERE id=?", (keep_id,)))
            self.assertIsNone(db.row("SELECT * FROM messages WHERE id=?", (remove_id,)))
            self.assertEqual(db.rows("SELECT * FROM attachments"), [])
            audit = db.row("SELECT * FROM audit_log WHERE action='message_removed_from_mailbox'")
            self.assertIsNotNone(audit)
            self.assertIsNone(audit["message_id"])

    def test_auto_sync_only_fetches_enabled_mailboxes(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            auto_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,auto_sync,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?)""", ("Auto", "auto@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, 1, db.now_iso()))
            db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,auto_sync,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?)""", ("Manuell", "manual@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, 0, db.now_iso()))
            with mock.patch.object(main, "fetch_mailbox", return_value={"new_messages": 2, "removed_messages": 1}) as fetch:
                main.sync_all()
            fetch.assert_called_once()
            self.assertEqual(fetch.call_args.args[0]["id"], auto_id)
            audit = db.row("SELECT * FROM audit_log WHERE action='auto_sync'")
            self.assertIsNotNone(audit)

    def test_system_interval_can_be_updated(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            with mock.patch.object(main, "require_admin", return_value={"email": "admin@example.org"}):
                result = main.update_system({"poll_interval_seconds": 120}, session=None)
            self.assertEqual(result["poll_interval_seconds"], 120)
            self.assertEqual(main.poll_interval_seconds(), 120)
            self.assertIsNotNone(db.row("SELECT * FROM audit_log WHERE action='system_updated'"))

    def test_existing_rule_can_be_edited_and_reactivated(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            mailbox_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Zentrale", "zentrale@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, db.now_iso()))
            rule_id = db.execute("""INSERT INTO rules(name,field,operator,value,action,target_email,target_folder,priority,active,stop_processing,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)""", ("Alt", "from", "contains", "alt@example.org", "forward", "alt-target@example.org", "Alter Ordner", 100, 0, 1, db.now_iso()))
            payload = {
                "name": "Neue Betreffregel", "field": "subject", "operator": "starts_with", "value": "Rechnung",
                "action": "forward", "target_email": "team@example.org", "mailbox_id": mailbox_id,
                "post_forward_folder": "INBOX/Archiv", "priority": 25,
                "stop_processing": 0, "active": 1,
            }
            with mock.patch.object(main, "require_user", return_value={"email": "editor@example.org"}):
                result = main.update_rule(rule_id, payload, session=None)
            updated = db.row("SELECT * FROM rules WHERE id=?", (rule_id,))
            self.assertTrue(result["ok"])
            self.assertEqual(updated["name"], "Neue Betreffregel")
            self.assertEqual(updated["field"], "subject")
            self.assertEqual(updated["operator"], "starts_with")
            self.assertEqual(updated["target_email"], "team@example.org")
            self.assertIsNone(updated["target_folder"])
            self.assertEqual(updated["post_forward_folder"], "INBOX/Archiv")
            self.assertEqual(updated["priority"], 25)
            self.assertEqual(updated["active"], 1)
            self.assertEqual(updated["stop_processing"], 0)
            self.assertIsNotNone(db.row("SELECT * FROM audit_log WHERE action='rule_updated'"))

    def test_rule_requires_a_specific_mailbox(self):
        payload = {
            "name": "Ohne Postfach", "field": "subject", "operator": "contains", "value": "Rechnung",
            "action": "forward", "target_email": "team@example.org", "post_forward_folder": "INBOX/Archiv",
        }
        with self.assertRaisesRegex(Exception, "Postfach"):
            main.normalized_rule(payload)

    def test_rules_export_and_import_are_mailbox_scoped(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            mailbox_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Zentrale", "zentrale@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, db.now_iso()))
            db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,value_logic,action,target_email,priority,active,stop_processing,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", ("Rechnung", mailbox_id, "subject", "contains", "Rechnung", "any", "forward", "team@example.org", 100, 1, 1, db.now_iso()))
            db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,action,target_email,priority,active,stop_processing,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)""", ("Alt global", None, "subject", "contains", "Alt", "forward", "team@example.org", 100, 1, 1, db.now_iso()))
            with mock.patch.object(main, "require_user", return_value={"id": 1, "email": "admin@example.org", "role": "admin"}):
                exported = main.export_rules(session=None)
            self.assertEqual(len(exported["rules"]), 1)
            self.assertEqual(exported["rules"][0]["mailbox_email"], "zentrale@example.org")
            db.execute("DELETE FROM rules")
            with mock.patch.object(main, "require_user", return_value={"id": 1, "email": "admin@example.org", "role": "admin"}):
                imported = main.import_rules(exported, session=None)
            self.assertEqual(imported["imported"], 1)
            self.assertEqual(db.row("SELECT count(*) n FROM rules WHERE mailbox_id=?", (mailbox_id,))["n"], 1)

    def test_apply_saved_rule_to_existing_messages_is_dry_run_in_test_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            mailbox_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Zentrale", "zentrale@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, db.now_iso()))
            rule_id = db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,action,target_email,priority,active,stop_processing,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)""", ("Rechnungen", mailbox_id, "subject", "contains", "Rechnung", "forward", "team@example.org", 100, 1, 1, db.now_iso()))
            db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,received_at,text_body,html_body,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", (mailbox_id, "1", "a@example.org", "zentrale@example.org", "Rechnung 1", db.now_iso(), "Text", "<p>Text</p>", db.now_iso()))
            db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,received_at,text_body,html_body,matched_rule_id,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?)""", (mailbox_id, "2", "b@example.org", "zentrale@example.org", "Rechnung 2", db.now_iso(), "Text", "<p>Text</p>", rule_id, db.now_iso()))
            with mock.patch.dict(os.environ, {"TEST_MODE": "true"}, clear=False), \
                 mock.patch.object(main, "require_user", return_value={"email": "editor@example.org"}), \
                 mock.patch.object(main, "forward_message") as forward, \
                 mock.patch.object(main, "move_message") as move:
                result = main.apply_rule_to_existing(rule_id, session=None)
            self.assertTrue(result["dry_run"])
            self.assertEqual(result["matched"], 1)
            self.assertEqual(result["applied"], 0)
            forward.assert_not_called()
            move.assert_not_called()
            self.assertIsNotNone(db.row("SELECT * FROM audit_log WHERE action='rule_apply_test'"))

    def test_apply_saved_rule_to_existing_messages_executes_live_once(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            mailbox_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Zentrale", "zentrale@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, db.now_iso()))
            rule_id = db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,action,target_email,post_forward_folder,priority,active,stop_processing,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", ("Rechnungen", mailbox_id, "subject", "contains", "Rechnung", "forward", "team@example.org", "INBOX/Archiv", 100, 1, 1, db.now_iso()))
            message_id = db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,received_at,text_body,html_body,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", (mailbox_id, "1", "a@example.org", "zentrale@example.org", "Rechnung 1", db.now_iso(), "Text", "<p>Text</p>", db.now_iso()))
            db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,received_at,text_body,html_body,matched_rule_id,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?)""", (mailbox_id, "2", "b@example.org", "zentrale@example.org", "Rechnung 2", db.now_iso(), "Text", "<p>Text</p>", rule_id, db.now_iso()))
            with mock.patch.object(main, "test_mode_enabled", return_value=False), \
                 mock.patch.object(main, "require_user", return_value={"email": "editor@example.org"}), \
                 mock.patch.object(main, "forward_message") as forward, \
                 mock.patch.object(main, "move_message") as move:
                result = main.apply_rule_to_existing(rule_id, session=None)
            self.assertFalse(result["dry_run"])
            self.assertEqual(result["matched"], 1)
            self.assertEqual(result["applied"], 1)
            forward.assert_called_once_with(message_id, "team@example.org", "editor@example.org", rule_id, None)
            move.assert_called_once_with(message_id, "INBOX/Archiv", "editor@example.org", rule_id)
            self.assertEqual(db.row("SELECT matched_rule_id FROM messages WHERE id=?", (message_id,))["matched_rule_id"], rule_id)
            self.assertIsNotNone(db.row("SELECT * FROM audit_log WHERE action='rule_applied_existing'"))

    def test_mailbox_permissions_limit_agent_visibility(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            agent_id = db.execute("INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)", ("agent@example.org", "Agent", "agent", "hash", db.now_iso()))
            allowed = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Erlaubt", "a@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, db.now_iso()))
            denied = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Verboten", "b@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, db.now_iso()))
            db.execute("INSERT INTO mailbox_permissions(mailbox_id,user_id,created_at) VALUES(?,?,?)", (allowed, agent_id, db.now_iso()))
            db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,text_body,html_body,created_at)
              VALUES(?,?,?,?,?,?,?,?)""", (allowed, "1", "a@example.org", "agent@example.org", "Sichtbar", "Text", "<p>Text</p>", db.now_iso()))
            db.execute("""INSERT INTO messages(mailbox_id,uid,sender,recipients,subject,text_body,html_body,created_at)
              VALUES(?,?,?,?,?,?,?,?)""", (denied, "2", "b@example.org", "agent@example.org", "Unsichtbar", "Text", "<p>Text</p>", db.now_iso()))
            user = {"id": agent_id, "email": "agent@example.org", "role": "agent"}
            with mock.patch.object(main, "require_user", return_value=user):
                boxes = main.mailboxes(session=None)
                mails = main.messages(session=None)
            self.assertEqual([b["id"] for b in boxes], [allowed])
            self.assertEqual([m["subject"] for m in mails], ["Sichtbar"])
            with mock.patch.object(main, "require_user", return_value=user):
                with self.assertRaises(Exception):
                    main.message(db.row("SELECT id FROM messages WHERE mailbox_id=?", (denied,))["id"], session=None)

    def test_admin_can_update_mailbox_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            admin_id = db.execute("INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)", ("admin@example.org", "Admin", "admin", "hash", db.now_iso()))
            agent_id = db.execute("INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)", ("agent@example.org", "Agent", "agent", "hash", db.now_iso()))
            mailbox_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,smtp_host,username,password_enc,folder,active,created_at)
              VALUES(?,?,?,?,?,?,?,?,?)""", ("Zentrale", "a@example.org", "imap", "smtp", "svc", "encrypted", "INBOX", 1, db.now_iso()))
            with mock.patch.object(main, "require_admin", return_value={"id": admin_id, "email": "admin@example.org", "role": "admin"}):
                result = main.update_mailbox_permissions(mailbox_id, {"user_ids": [agent_id]}, session=None)
            self.assertTrue(result["ok"])
            self.assertIsNotNone(db.row("SELECT * FROM mailbox_permissions WHERE mailbox_id=? AND user_id=?", (mailbox_id, agent_id)))
            self.assertIsNotNone(db.row("SELECT * FROM audit_log WHERE action='mailbox_permissions_updated'"))

    def test_admin_created_user_can_login(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(db, "DATA_DIR", Path(temp_dir)), \
             mock.patch.object(db, "DB_PATH", Path(temp_dir) / "test.sqlite3"):
            db.init_db()
            with mock.patch.object(main, "require_admin", return_value={"id": 1, "email": "admin@example.org", "role": "admin"}):
                created = main.add_user({"email": " agent@example.org ", "name": " Agent ", "role": "agent", "password": "start-password"}, session=None)
            response = main.Response()
            logged_in = main.login(response, {"email": "agent@example.org", "password": "start-password"})
            self.assertEqual(logged_in["id"], created["id"])
            self.assertEqual(logged_in["role"], "agent")
            self.assertIn("session=", response.headers["set-cookie"])

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

    def test_multiple_terms_support_and_or_logic(self):
        self.assertTrue(rule_matches({"field": "subject", "operator": "contains", "value": "Rechnung\nMahnung", "value_logic": "any"}, self.message))
        self.assertTrue(rule_matches({"field": "body", "operator": "contains", "value": "Betrag;EUR", "value_logic": "all"}, self.message))
        self.assertFalse(rule_matches({"field": "subject", "operator": "contains", "value": "Rechnung, Mahnung", "value_logic": "all"}, self.message))


if __name__ == "__main__":
    unittest.main()
