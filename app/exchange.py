import email
import imaplib
import os
import re
import smtplib
import ssl
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import parsedate_to_datetime

import bleach

from . import db
from .security import decrypt

ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | {
    "p", "br", "div", "span", "table", "thead", "tbody", "tr", "td", "th",
    "h1", "h2", "h3", "h4", "blockquote", "pre", "hr", "img"
}
ALLOWED_ATTRS = {"a": ["href", "title"], "img": ["alt", "width", "height"], "td": ["colspan", "rowspan"]}


def test_mode_enabled():
    # Fail safe: missing or malformed values keep all external mutations disabled.
    return os.getenv("TEST_MODE", "true").strip().lower() not in {"false", "0", "no", "off"}


def clean_html(value):
    # Remote images and active content are removed; links may only use safe protocols.
    value = re.sub(r"<\s*(script|style|iframe|object|embed|form)[^>]*>.*?<\s*/\s*\1\s*>", "", value or "", flags=re.I | re.S)
    return bleach.clean(value or "", tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, protocols={"http", "https", "mailto"}, strip=True)


def decoded(value):
    try:
        return str(make_header(decode_header(value or "")))
    except Exception:
        return value or ""


def message_bodies(msg):
    text, html = "", ""
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        value = payload.decode(charset, errors="replace")
        if ctype == "text/plain" and not text:
            text = value
        elif ctype == "text/html" and not html:
            html = clean_html(value)
    if not html and text:
        html = "<pre>" + bleach.clean(text) + "</pre>"
    return text, html


def connect_imap(box):
    client = imaplib.IMAP4_SSL(box["imap_host"], box["imap_port"], ssl_context=ssl.create_default_context()) if box["imap_ssl"] else imaplib.IMAP4(box["imap_host"], box["imap_port"])
    client.login(box.get("imap_username") or box["username"], decrypt(box["password_enc"]))
    return client


def connection_error(exc, protocol, box):
    raw = str(exc)
    upper = raw.upper()
    if protocol == "smtp" and "WRONG_VERSION_NUMBER" in upper:
        if int(box.get("smtp_port", 0)) == 587:
            return "Falscher TLS-Modus: Für Exchange-Port 587 STARTTLS wählen, nicht SSL/TLS."
        return "TLS-Modus passt nicht zum SMTP-Port. Für 587 meist STARTTLS, für 465 meist SSL/TLS verwenden."
    if "LOGIN FAILED" in upper or "AUTHENTICATIONFAILED" in upper or "AUTHENTICATION FAILED" in upper:
        if protocol == "imap":
            return "Exchange lehnt die IMAP-Anmeldung ab. UPN (benutzer@domain), DOMAIN\\benutzer und IMAP-Freigabe prüfen. Bei delegiertem Sammelpostfach kann ein eigener IMAP-Anmeldename nötig sein; das Dienstkonto braucht eine primäre SMTP-Adresse."
        return "Exchange lehnt die SMTP-Anmeldung ab. SMTP-Anmeldename, Authentifizierung am Client-Frontend-Connector und Send-As-Berechtigung prüfen."
    return raw[:300]


def test_mailbox_connection(box, password):
    """Test authentication and the configured inbox without sending or changing mail."""
    result = {"ok": True, "imap": {"ok": False}, "smtp": {"ok": False}}
    imap = None
    try:
        imap = imaplib.IMAP4_SSL(box["imap_host"], int(box.get("imap_port", 993)), ssl_context=ssl.create_default_context()) if box.get("imap_ssl", True) else imaplib.IMAP4(box["imap_host"], int(box.get("imap_port", 143)))
        imap.login(box.get("imap_username") or box.get("username"), password)
        if imap.select(box.get("folder") or "INBOX", readonly=True)[0] != "OK":
            raise RuntimeError(f"Ordner {box.get('folder') or 'INBOX'} nicht verfügbar")
        result["imap"] = {"ok": True, "message": "Anmeldung und Ordnerzugriff erfolgreich"}
    except Exception as exc:
        result["ok"] = False
        result["imap"] = {"ok": False, "message": connection_error(exc, "imap", box), "technical": str(exc)[:160]}
    finally:
        if imap:
            try: imap.logout()
            except Exception: pass

    smtp = None
    try:
        mode = box.get("smtp_mode") or "starttls"
        if mode == "ssl":
            smtp = smtplib.SMTP_SSL(box["smtp_host"], int(box.get("smtp_port", 465)), context=ssl.create_default_context(), timeout=20)
        else:
            smtp = smtplib.SMTP(box["smtp_host"], int(box.get("smtp_port", 587)), timeout=20)
            smtp.ehlo()
            if mode == "starttls":
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
        smtp.login(box.get("smtp_username") or box.get("username"), password)
        result["smtp"] = {"ok": True, "message": "Anmeldung erfolgreich; keine Mail gesendet"}
    except Exception as exc:
        result["ok"] = False
        result["smtp"] = {"ok": False, "message": connection_error(exc, "smtp", box), "technical": str(exc)[:160]}
    finally:
        if smtp:
            try: smtp.quit()
            except Exception: pass
    return result


def list_folders(box):
    client = connect_imap(box)
    try:
        status, values = client.list()
        if status != "OK": raise RuntimeError("IMAP-Ordner konnten nicht gelesen werden")
        result = []
        for raw in values or []:
            line = raw.decode(errors="replace")
            # IMAP LIST: flags, delimiter and quoted/unquoted mailbox name.
            match = re.match(r'.*?\s+(?:"([^"]*)"|NIL)\s+(?:"([^"]*)"|(.*))$', line)
            name = (match.group(2) or match.group(3)).strip('"') if match else line.rsplit(" ", 1)[-1].strip('"')
            if name: result.append(name)
        return result
    finally:
        try: client.logout()
        except Exception: pass


def move_message(message_id, folder, actor="system", rule_id=None):
    if test_mode_enabled():
        raise RuntimeError("Testmodus aktiv: Exchange-Mail wurde nicht verschoben")
    msg = db.row("SELECT m.*,b.* FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE m.id=?", (message_id,))
    if not msg: raise ValueError("Mail nicht gefunden")
    folder = str(folder or "").strip()
    if not folder or any(c in folder for c in "\r\n\0"):
        raise ValueError("Ungültiger Zielordner")
    client = connect_imap(msg)
    try:
        if client.select(msg["folder"], readonly=False)[0] != "OK": raise RuntimeError("Quellordner nicht verfügbar")
        # RFC 6851 MOVE where available, with broadly compatible COPY fallback.
        status, _ = client.uid("MOVE", msg["uid"], folder)
        if status != "OK":
            if client.uid("COPY", msg["uid"], folder)[0] != "OK": raise RuntimeError(f"Verschieben nach {folder} fehlgeschlagen")
            client.uid("STORE", msg["uid"], "+FLAGS", "(\\Deleted)")
            client.expunge()
    finally:
        try: client.logout()
        except Exception: pass
    db.execute("UPDATE messages SET status='done' WHERE id=?", (message_id,))
    db.audit("message_moved", actor=actor, message_id=message_id, mailbox_id=msg["mailbox_id"], folder=folder, rule_id=rule_id)


def fetch_mailbox(box):
    client = connect_imap(box)
    count = 0
    try:
        status, _ = client.select(box["folder"], readonly=True)
        if status != "OK":
            raise RuntimeError(f"IMAP-Ordner {box['folder']} nicht verfügbar")
        status, data = client.uid("search", None, "ALL")
        if status != "OK":
            raise RuntimeError("IMAP-Suche fehlgeschlagen")
        for uid_b in data[0].split()[-500:]:
            uid = uid_b.decode()
            if db.row("SELECT id FROM messages WHERE mailbox_id=? AND uid=?", (box["id"], uid)):
                continue
            status, raw = client.uid("fetch", uid_b, "(RFC822)")
            if status != "OK" or not raw or not isinstance(raw[0], tuple):
                continue
            msg = email.message_from_bytes(raw[0][1])
            text, html = message_bodies(msg)
            try:
                received = parsedate_to_datetime(msg.get("Date")).isoformat() if msg.get("Date") else db.now_iso()
            except Exception:
                received = db.now_iso()
            message_id = db.execute("""
              INSERT OR IGNORE INTO messages(mailbox_id,uid,message_id,sender,recipients,subject,received_at,text_body,html_body,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?)
            """, (box["id"], uid, decoded(msg.get("Message-ID")), decoded(msg.get("From")), decoded(msg.get("To")), decoded(msg.get("Subject")) or "(Ohne Betreff)", received, text, html, db.now_iso()))
            if message_id:
                db.audit("message_received", mailbox_id=box["id"], message_id=message_id, subject=decoded(msg.get("Subject")))
                apply_rules(message_id)
                count += 1
        db.execute("UPDATE mailboxes SET last_sync_at=?,last_error=NULL WHERE id=?", (db.now_iso(), box["id"]))
        return count
    finally:
        try: client.logout()
        except Exception: pass


def rule_matches(rule, msg):
    value = str(msg.get({"from": "sender", "to": "recipients", "subject": "subject", "body": "text_body"}.get(rule["field"], rule["field"]), ""))
    needle = rule["value"]
    if rule["operator"] == "contains": return needle.casefold() in value.casefold()
    if rule["operator"] == "equals": return needle.casefold() == value.casefold()
    if rule["operator"] == "starts_with": return value.casefold().startswith(needle.casefold())
    if rule["operator"] == "regex":
        try: return re.search(needle, value, re.I) is not None
        except re.error: return False
    return False


def apply_rules(message_id):
    msg = db.row("SELECT * FROM messages WHERE id=?", (message_id,))
    rules = db.rows("SELECT r.*,u.email user_email FROM rules r LEFT JOIN users u ON u.id=r.target_user_id WHERE r.active=1 AND (r.mailbox_id IS NULL OR r.mailbox_id=?) ORDER BY r.priority,r.id", (msg["mailbox_id"],))
    for rule in rules:
        if not rule_matches(rule, msg):
            continue
        if test_mode_enabled():
            target = rule["target_folder"] if rule.get("action", "forward") == "move" else (rule["target_email"] or rule["user_email"])
            db.audit("rule_test_match", actor="test-mode", message_id=message_id, mailbox_id=msg["mailbox_id"], rule_id=rule["id"], action=rule.get("action", "forward"), target=target)
            if rule["stop_processing"]:
                break
            continue
        try:
            if rule.get("action", "forward") == "move":
                move_message(message_id, rule["target_folder"], "rule", rule["id"])
            else:
                target = rule["target_email"] or rule["user_email"]
                forward_message(message_id, target, "rule", rule["id"])
            db.execute("UPDATE messages SET matched_rule_id=? WHERE id=?", (rule["id"], message_id))
        except Exception as exc:
            db.audit("forward_failed", message_id=message_id, mailbox_id=msg["mailbox_id"], rule_id=rule["id"], error=str(exc))
        if rule["stop_processing"]:
            break


def forward_message(message_id, target, actor, rule_id=None, user_id=None):
    if test_mode_enabled():
        raise RuntimeError("Testmodus aktiv: Mail wurde nicht weitergeleitet")
    if not target or "@" not in target:
        raise ValueError("Ungültige Zieladresse")
    msg = db.row("SELECT m.*,b.* FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE m.id=?", (message_id,))
    outgoing = EmailMessage()
    outgoing["From"] = msg["email"]
    outgoing["To"] = target
    outgoing["Subject"] = "WG: " + msg["subject"]
    outgoing.set_content(f"Automatisch weitergeleitete Nachricht\n\nVon: {msg['sender']}\nAn: {msg['recipients']}\nBetreff: {msg['subject']}\n\n{msg['text_body']}")
    outgoing.add_alternative(f"<p><strong>Automatisch weitergeleitete Nachricht</strong></p><p>Von: {bleach.clean(msg['sender'])}<br>An: {bleach.clean(msg['recipients'])}<br>Betreff: {bleach.clean(msg['subject'])}</p><hr>{msg['html_body']}", subtype="html")
    password = decrypt(msg["password_enc"])
    if msg["smtp_mode"] == "ssl":
        smtp = smtplib.SMTP_SSL(msg["smtp_host"], msg["smtp_port"], context=ssl.create_default_context(), timeout=30)
    else:
        smtp = smtplib.SMTP(msg["smtp_host"], msg["smtp_port"], timeout=30)
        if msg["smtp_mode"] == "starttls": smtp.starttls(context=ssl.create_default_context())
    try:
        smtp.login(msg.get("smtp_username") or msg["username"], password)
        smtp.send_message(outgoing)
    finally:
        smtp.quit()
    db.execute("UPDATE messages SET status='assigned',assigned_to=? WHERE id=?", (user_id, message_id))
    db.audit("message_forwarded", actor=actor, message_id=message_id, mailbox_id=msg["mailbox_id"], target=target, rule_id=rule_id)
