import base64
import email
import hashlib
import imaplib
import os
import re
import smtplib
import ssl
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import parsedate_to_datetime

import bleach
import spnego
from bleach.css_sanitizer import CSSSanitizer
from cryptography import x509
from spnego.channel_bindings import GssChannelBindings

from . import db
from .security import decrypt

MESSAGE_PARSER_VERSION = 3
MAX_INLINE_IMAGE_BYTES = 5 * 1024 * 1024
MAX_INLINE_IMAGES_BYTES = 12 * 1024 * 1024
SAFE_INLINE_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}
ALLOWED_TAGS = set(bleach.sanitizer.ALLOWED_TAGS) | {
    "p", "br", "div", "span", "table", "thead", "tbody", "tfoot", "tr", "td", "th",
    "caption", "colgroup", "col", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
    "pre", "hr", "img", "center", "font", "small", "big", "sup", "sub", "section"
}
ALLOWED_ATTRS = {
    "*": ["style", "title", "lang", "dir", "class"],
    "a": ["href", "title", "target"],
    "img": ["src", "data-external-src", "alt", "title", "width", "height", "border", "align"],
    "table": ["width", "height", "border", "cellpadding", "cellspacing", "align", "bgcolor", "role"],
    "td": ["colspan", "rowspan", "width", "height", "align", "valign", "bgcolor"],
    "th": ["colspan", "rowspan", "width", "height", "align", "valign", "bgcolor"],
    "col": ["span", "width"],
    "font": ["color", "face", "size"],
}
CSS_SANITIZER = CSSSanitizer(allowed_css_properties={
    "color", "background-color", "font", "font-family", "font-size", "font-style", "font-weight",
    "line-height", "letter-spacing", "text-align", "text-decoration", "text-indent", "text-transform",
    "white-space", "word-break", "overflow-wrap", "vertical-align", "width", "min-width", "max-width",
    "height", "min-height", "max-height", "margin", "margin-top", "margin-right", "margin-bottom",
    "margin-left", "padding", "padding-top", "padding-right", "padding-bottom", "padding-left", "border",
    "border-top", "border-right", "border-bottom", "border-left", "border-color", "border-style",
    "border-width", "border-collapse", "border-spacing", "table-layout", "display", "float", "clear",
})


def test_mode_value():
    return os.getenv("TEST_MODE", "true").strip().strip("\"'").strip().lower()


def test_mode_enabled():
    # Fail safe: missing or malformed values keep all external mutations disabled.
    return test_mode_value() not in {"false", "0", "no", "off", "disabled", "disable", "live", "production"}


def imap_utf7_encode(value):
    """Encode a Unicode mailbox name using IMAP modified UTF-7 (RFC 3501)."""
    result, buffered = [], []

    def flush():
        if not buffered:
            return
        raw = "".join(buffered).encode("utf-16-be")
        result.append("&" + base64.b64encode(raw).decode("ascii").rstrip("=").replace("/", ",") + "-")
        buffered.clear()

    for char in str(value):
        if " " <= char <= "~" and char != "&":
            flush()
            result.append(char)
        elif char == "&":
            flush()
            result.append("&-")
        else:
            buffered.append(char)
    flush()
    return "".join(result)


def imap_utf7_decode(value):
    """Decode an IMAP modified UTF-7 mailbox name for display in the UI."""
    value, result, position = str(value), [], 0
    while position < len(value):
        marker = value.find("&", position)
        if marker < 0:
            result.append(value[position:])
            break
        result.append(value[position:marker])
        end = value.find("-", marker)
        if end < 0:
            result.append(value[marker:])
            break
        encoded = value[marker + 1:end]
        if not encoded:
            result.append("&")
        else:
            padded = encoded.replace(",", "/") + "=" * (-len(encoded) % 4)
            try: result.append(base64.b64decode(padded).decode("utf-16-be"))
            except (ValueError, UnicodeDecodeError): result.append(value[marker:end + 1])
        position = end + 1
    return "".join(result)


def decode_imap_list_line(raw):
    if isinstance(raw, str):
        return raw, "utf-8"
    if all(byte < 128 for byte in raw):
        return raw.decode("ascii"), "imap-utf7"
    for charset in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(charset), charset
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8"


def imap_mailbox_arg(value, wire_encoding="imap-utf7"):
    value = str(value)
    if wire_encoding == "imap-utf7":
        decoded_value = imap_utf7_decode(value)
        # Keep folder values saved by older Mailsorter versions in their already encoded form.
        encoded = value if decoded_value != value and imap_utf7_encode(decoded_value) == value else imap_utf7_encode(value)
        raw = encoded.encode("ascii")
    else:
        raw = value.encode(wire_encoding)
    return b'"' + raw.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


def clean_html(value):
    # Preserve common email layout while stripping executable/overlay content. Remote images stay opt-in.
    value = re.sub(r"<\s*(script|style|iframe|object|embed|form)[^>]*>.*?<\s*/\s*\1\s*>", "", value or "", flags=re.I | re.S)
    cleaned = bleach.clean(
        value or "", tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS,
        protocols={"http", "https", "mailto", "data"}, css_sanitizer=CSS_SANITIZER, strip=True,
    )
    # The data protocol is needed for inline images, never for clickable links.
    cleaned = re.sub(r'(<a\b[^>]*?)\s+href="data:[^"]*"', r'\1', cleaned, flags=re.I)
    # Bleach normalizes attributes to double quotes, allowing remote sources to be parked safely.
    return re.sub(r'(<img\b[^>]*?)\s+src="(https?://[^"]+)"', r'\1 data-external-src="\2"', cleaned, flags=re.I)


def decoded(value):
    try:
        return str(make_header(decode_header(value or "")))
    except Exception:
        chunks = []
        for chunk, charset in decode_header(value or ""):
            chunks.append(decode_bytes(chunk, charset) if isinstance(chunk, bytes) else chunk)
        return "".join(chunks)


def decode_bytes(payload, declared_charset=None):
    candidates = [declared_charset, "utf-8", "windows-1252", "iso-8859-1"]
    for charset in dict.fromkeys(c for c in candidates if c):
        try:
            return payload.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", errors="replace")


def decode_part_text(part):
    return decode_bytes(part.get_payload(decode=True) or b"", part.get_content_charset())


def inline_image_sources(msg):
    sources, total = {}, 0
    for part in msg.walk():
        content_id = (part.get("Content-ID") or "").strip().strip("<>").lower()
        content_type = part.get_content_type().lower()
        if not content_id or content_type not in SAFE_INLINE_IMAGE_TYPES:
            continue
        payload = part.get_payload(decode=True) or b""
        if not payload or len(payload) > MAX_INLINE_IMAGE_BYTES or total + len(payload) > MAX_INLINE_IMAGES_BYTES:
            continue
        total += len(payload)
        sources[content_id] = f"data:{content_type};base64,{base64.b64encode(payload).decode('ascii')}"
    return sources


def embed_inline_images(value, msg):
    sources = inline_image_sources(msg)

    def replace(match):
        return sources.get(match.group(1).strip().strip("<>").lower(), match.group(0))

    return re.sub(r"cid:([^\s\"'<>]+)", replace, value or "", flags=re.I)


def attachment_limit(name, default_mb):
    try:
        return max(1, min(500, int(os.getenv(name, str(default_mb))))) * 1024 * 1024
    except ValueError:
        return default_mb * 1024 * 1024


def safe_attachment_filename(value):
    name = decoded(value or "Anlage")
    name = re.sub(r"[\x00-\x1f\x7f]+", "", name).replace("\\", "/").rsplit("/", 1)[-1].strip()
    return (name or "Anlage")[:240]


def message_attachments(msg):
    result, stored_total = [], 0
    max_file = attachment_limit("MAX_ATTACHMENT_MB", 50)
    max_total = attachment_limit("MAX_MESSAGE_ATTACHMENTS_MB", 100)
    for part in msg.walk():
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        raw_filename = part.get_filename()
        if disposition != "attachment" and not (raw_filename and disposition != "inline"):
            continue
        payload = part.get_payload(decode=True) or b""
        size = len(payload)
        stored = size <= max_file and stored_total + size <= max_total
        if stored:
            stored_total += size
        content_type = part.get_content_type().lower()
        if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", content_type):
            content_type = "application/octet-stream"
        result.append({
            "filename": safe_attachment_filename(raw_filename), "content_type": content_type,
            "size": size, "stored": int(stored), "content": payload if stored else None,
        })
    return result


def store_message_attachments(message_id, msg):
    db.execute("DELETE FROM attachments WHERE message_id=?", (message_id,))
    attachments = message_attachments(msg)
    for attachment in attachments:
        db.execute("""INSERT INTO attachments(message_id,filename,content_type,size,stored,content,created_at)
          VALUES(?,?,?,?,?,?,?)""", (message_id, attachment["filename"], attachment["content_type"],
          attachment["size"], attachment["stored"], attachment["content"], db.now_iso()))
    return attachments


def message_bodies(msg):
    text, html = "", ""
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        value = decode_part_text(part)
        if ctype == "text/plain" and not text:
            text = value
        elif ctype == "text/html" and not html:
            html = clean_html(embed_inline_images(value, msg))
    if not html and text:
        html = "<pre>" + bleach.clean(text) + "</pre>"
    return text, html


def open_imap(box):
    return imaplib.IMAP4_SSL(box["imap_host"], int(box["imap_port"]), ssl_context=ssl.create_default_context()) if box["imap_ssl"] else imaplib.IMAP4(box["imap_host"], int(box["imap_port"]))


def imap_tls_channel_bindings(client):
    """Build RFC 5929 tls-server-end-point bindings for Exchange Extended Protection."""
    sock = getattr(client, "sock", None)
    if not sock or not hasattr(sock, "getpeercert"):
        return None
    certificate_der = sock.getpeercert(binary_form=True)
    if not certificate_der:
        return None
    certificate = x509.load_der_x509_certificate(certificate_der)
    try:
        algorithm = getattr(certificate.signature_hash_algorithm, "name", "sha256").lower().replace("-", "")
    except Exception:
        algorithm = "sha256"
    # RFC 5929 replaces collision-prone MD5/SHA-1 certificate signatures with SHA-256.
    if algorithm in {"md5", "sha1"}:
        algorithm = "sha256"
    try:
        digest = hashlib.new(algorithm, certificate_der).digest()
    except ValueError:
        digest = hashlib.sha256(certificate_der).digest()
    return GssChannelBindings(application_data=b"tls-server-end-point:" + digest)


def authenticate_imap_ntlm(client, box, password):
    username = box.get("imap_username") or box["username"]
    channel_bindings = imap_tls_channel_bindings(client)
    context = spnego.client(
        username=username,
        password=password,
        hostname=box["imap_host"],
        service="imap",
        protocol="ntlm",
        channel_bindings=channel_bindings,
    )
    started = False

    def response(challenge):
        nonlocal started
        if not started:
            started = True
            return context.step()
        return context.step(challenge)

    try:
        client.authenticate("NTLM", response)
    except imaplib.IMAP4.error as exc:
        binding_status = "mit TLS-Kanalbindung" if channel_bindings else "ohne TLS-Kanalbindung"
        raise RuntimeError(f"NTLM AUTHENTICATE failed ({binding_status}): {exc}") from exc
    client._mailsorter_auth_mode = "NTLMv2"


def connect_imap_with_password(box, password):
    mode = (box.get("imap_auth_mode") or "auto").lower()
    username = box.get("imap_username") or box["username"]
    if mode not in {"auto", "login", "ntlm"}:
        raise ValueError("Ungültiger IMAP-Authentifizierungsmodus")
    client = open_imap(box)
    if mode in {"auto", "login"}:
        try:
            client.login(username, password)
            client._mailsorter_auth_mode = "LOGIN"
            return client
        except Exception as login_error:
            if mode == "login":
                try: client.logout()
                except Exception: pass
                raise
            capabilities = b" ".join(c if isinstance(c, bytes) else str(c).encode() for c in getattr(client, "capabilities", ())).upper()
            try: client.logout()
            except Exception: pass
            if b"AUTH=NTLM" not in capabilities:
                raise RuntimeError(f"LOGIN fehlgeschlagen und Exchange bietet AUTH=NTLM nicht an: {login_error}") from login_error
    client = open_imap(box)
    try:
        authenticate_imap_ntlm(client, box, password)
        return client
    except Exception:
        try: client.logout()
        except Exception: pass
        raise


def connect_imap(box):
    return connect_imap_with_password(box, decrypt(box["password_enc"]))


def connection_error(exc, protocol, box):
    raw = str(exc)
    upper = raw.upper()
    if protocol == "smtp" and "WRONG_VERSION_NUMBER" in upper:
        if int(box.get("smtp_port", 0)) == 587:
            return "Falscher TLS-Modus: Für Exchange-Port 587 STARTTLS wählen, nicht SSL/TLS."
        return "TLS-Modus passt nicht zum SMTP-Port. Für 587 meist STARTTLS, für 465 meist SSL/TLS verwenden."
    if "LOGIN FAILED" in upper or "AUTHENTICATIONFAILED" in upper or "AUTHENTICATION FAILED" in upper or "AUTHENTICATE FAILED" in upper:
        if protocol == "imap":
            if "NTLM" in upper:
                return "Exchange lehnt NTLMv2 ab. Für ein eigenes Postfach DOMAIN\\benutzer verwenden; für ein delegiertes Postfach DOMAIN\\dienstkonto/postfachalias testen. Das Dienstkonto braucht eine primäre SMTP-Adresse und Full-Access. Falls es weiter scheitert, zeigt das Exchange-IMAP-Protokoll den genauen Ablehnungsgrund."
            return "Exchange lehnt die IMAP-Anmeldung ab. UPN (benutzer@domain), DOMAIN\\benutzer und IMAP-Freigabe prüfen. Bei delegiertem Sammelpostfach kann ein eigener IMAP-Anmeldename nötig sein; das Dienstkonto braucht eine primäre SMTP-Adresse."
        return "Exchange lehnt die SMTP-Anmeldung ab. SMTP-Anmeldename, Authentifizierung am Client-Frontend-Connector und Send-As-Berechtigung prüfen."
    return raw[:300]


def test_mailbox_connection(box, password):
    """Test authentication and the configured inbox without sending or changing mail."""
    result = {"ok": True, "imap": {"ok": False}, "smtp": {"ok": False}}
    imap = None
    try:
        imap = connect_imap_with_password(box, password)
        if imap.select(box.get("folder") or "INBOX", readonly=True)[0] != "OK":
            raise RuntimeError(f"Ordner {box.get('folder') or 'INBOX'} nicht verfügbar")
        auth_mode = getattr(imap, "_mailsorter_auth_mode", "IMAP")
        result["imap"] = {"ok": True, "message": f"Anmeldung mit {auth_mode} und Ordnerzugriff erfolgreich"}
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


def folder_entries(client):
    status, values = client.list()
    if status != "OK": raise RuntimeError("IMAP-Ordner konnten nicht gelesen werden")
    result = []
    for raw in values or []:
        line, wire_encoding = decode_imap_list_line(raw)
        # IMAP LIST: flags, hierarchy delimiter and quoted/unquoted mailbox name.
        match = re.match(r'.*?\s+(?:"([^"]*)"|NIL)\s+(?:"((?:\\.|[^"])*)"|(.*))$', line)
        if not match:
            continue
        delimiter = match.group(1)
        raw_name = (match.group(2) if match.group(2) is not None else match.group(3) or "").strip()
        raw_name = raw_name.replace('\\"', '"').replace("\\\\", "\\")
        if raw_name:
            name = imap_utf7_decode(raw_name) if wire_encoding == "imap-utf7" else raw_name
            result.append({"name": name, "delimiter": delimiter, "wire_encoding": wire_encoding})
    return result


def list_folders(box):
    client = connect_imap(box)
    try:
        return [entry["name"] for entry in folder_entries(client)]
    finally:
        try: client.logout()
        except Exception: pass


def create_folder(box, name, parent=""):
    if test_mode_enabled():
        raise RuntimeError("Testmodus aktiv: Exchange-Ordner wurde nicht angelegt")
    name, parent = str(name or "").strip(), str(parent or "").strip()
    if not name or len(name) > 120 or any(c in name for c in "\r\n\0/\\"):
        raise ValueError("Ungültiger Ordnername; / und \\ sind nicht erlaubt")
    client = connect_imap(box)
    try:
        entries = folder_entries(client)
        delimiter = next((entry["delimiter"] for entry in entries if entry["delimiter"]), "/")
        wire_encoding = next((entry["wire_encoding"] for entry in entries if entry["wire_encoding"] != "imap-utf7"), "imap-utf7")
        parent = parent or str(box.get("folder") or "INBOX").strip()
        if parent and parent not in {entry["name"] for entry in entries}:
            raise ValueError("Übergeordneter Ordner wurde nicht gefunden")
        full_name = f"{parent}{delimiter}{name}" if parent else name
        if full_name in {entry["name"] for entry in entries}:
            raise ValueError("Dieser Ordner existiert bereits")
        status, details = client.create(imap_mailbox_arg(full_name, wire_encoding))
        if status != "OK":
            reason = " ".join(item.decode(errors="replace") if isinstance(item, bytes) else str(item) for item in details or [])
            raise RuntimeError(f"Exchange hat den Ordner nicht angelegt: {reason or status}")
        refreshed = folder_entries(client)
        if full_name not in {entry["name"] for entry in refreshed}:
            raise RuntimeError(f"Exchange meldet CREATE OK, aber der Ordner {full_name} erscheint danach nicht in der IMAP-Ordnerliste")
        return full_name
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
        try: entry = next((item for item in folder_entries(client) if item["name"] == folder), None)
        except Exception: entry = None
        folder_arg = imap_mailbox_arg(folder, entry["wire_encoding"] if entry else "imap-utf7")
        status, _ = client.uid("MOVE", msg["uid"], folder_arg)
        if status != "OK":
            if client.uid("COPY", msg["uid"], folder_arg)[0] != "OK": raise RuntimeError(f"Verschieben nach {folder} fehlgeschlagen")
            client.uid("STORE", msg["uid"], "+FLAGS", "(\\Deleted)")
            client.expunge()
    finally:
        try: client.logout()
        except Exception: pass
    db.execute("UPDATE messages SET status='done' WHERE id=?", (message_id,))
    db.audit("message_moved", actor=actor, message_id=message_id, mailbox_id=msg["mailbox_id"], folder=folder, rule_id=rule_id)


def fetch_mailbox(box):
    client = connect_imap(box)
    count = removed = 0
    try:
        status, _ = client.select(box["folder"], readonly=True)
        if status != "OK":
            raise RuntimeError(f"IMAP-Ordner {box['folder']} nicht verfügbar")
        status, data = client.uid("search", None, "ALL")
        if status != "OK":
            raise RuntimeError("IMAP-Suche fehlgeschlagen")
        found_uids = data[0].split() if data and data[0] else []
        present_uids = {uid_b.decode() for uid_b in found_uids}
        removed = db.prune_mailbox_messages(box["id"], present_uids)
        for uid_b in found_uids[-500:]:
            uid = uid_b.decode()
            existing = db.row("SELECT id,parser_version FROM messages WHERE mailbox_id=? AND uid=?", (box["id"], uid))
            if existing and int(existing.get("parser_version") or 1) >= MESSAGE_PARSER_VERSION:
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
            values = (decoded(msg.get("Message-ID")), decoded(msg.get("From")), decoded(msg.get("To")), decoded(msg.get("Subject")) or "(Ohne Betreff)", received, text, html)
            if existing:
                db.execute("""UPDATE messages SET message_id=?,sender=?,recipients=?,subject=?,received_at=?,text_body=?,html_body=?,parser_version=? WHERE id=?""",
                           (*values, MESSAGE_PARSER_VERSION, existing["id"]))
                attachments = store_message_attachments(existing["id"], msg)
                db.audit("message_rendering_refreshed", mailbox_id=box["id"], message_id=existing["id"], attachments=len(attachments))
                continue
            message_id = db.execute("""
              INSERT OR IGNORE INTO messages(mailbox_id,uid,message_id,sender,recipients,subject,received_at,text_body,html_body,parser_version,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (box["id"], uid, *values, MESSAGE_PARSER_VERSION, db.now_iso()))
            if message_id:
                attachments = store_message_attachments(message_id, msg)
                db.audit("message_received", mailbox_id=box["id"], message_id=message_id,
                         subject=decoded(msg.get("Subject")), attachments=len(attachments))
                apply_rules(message_id)
                count += 1
        db.execute("UPDATE mailboxes SET last_sync_at=?,last_error=NULL WHERE id=?", (db.now_iso(), box["id"]))
        return {"new_messages": count, "removed_messages": removed}
    finally:
        try: client.logout()
        except Exception: pass


def rule_matches(rule, msg):
    value = str(msg.get({"from": "sender", "to": "recipients", "subject": "subject", "body": "text_body"}.get(rule["field"], rule["field"]), ""))
    terms = [t.strip() for t in re.split(r"[\n,;]+", str(rule["value"])) if t.strip()] or [str(rule["value"])]
    logic = str(rule.get("value_logic") or "any").lower()
    def one(needle):
        if rule["operator"] == "contains": return needle.casefold() in value.casefold()
        if rule["operator"] == "equals": return needle.casefold() == value.casefold()
        if rule["operator"] == "starts_with": return value.casefold().startswith(needle.casefold())
        if rule["operator"] == "regex":
            try: return re.search(needle, value, re.I) is not None
            except re.error: return False
        return False
    results = [one(term) for term in terms]
    return all(results) if logic == "all" else any(results)


def apply_rules(message_id):
    msg = db.row("SELECT * FROM messages WHERE id=?", (message_id,))
    rules = db.rows("SELECT r.*,u.email user_email FROM rules r LEFT JOIN users u ON u.id=r.target_user_id WHERE r.active=1 AND (r.mailbox_id IS NULL OR r.mailbox_id=?) ORDER BY r.priority,r.id", (msg["mailbox_id"],))
    for rule in rules:
        if not rule_matches(rule, msg):
            continue
        if test_mode_enabled():
            if rule.get("action", "forward") == "move":
                actions = [{"action": "move", "target": rule["target_folder"]}]
            else:
                actions = [{"action": "forward", "target": rule["target_email"] or rule["user_email"]}]
                if rule.get("post_forward_folder"):
                    actions.append({"action": "move", "target": rule["post_forward_folder"]})
            db.audit("rule_test_match", actor="test-mode", message_id=message_id, mailbox_id=msg["mailbox_id"], rule_id=rule["id"], actions=actions)
            if rule["stop_processing"]:
                break
            continue
        try:
            if rule.get("action", "forward") == "move":
                move_message(message_id, rule["target_folder"], "rule", rule["id"])
            else:
                target = rule["target_email"] or rule["user_email"]
                forward_message(message_id, target, "rule", rule["id"])
                if rule.get("post_forward_folder"):
                    move_message(message_id, rule["post_forward_folder"], "rule", rule["id"])
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
    attachments = db.rows("SELECT filename,content_type,size,stored,content FROM attachments WHERE message_id=? ORDER BY id", (message_id,))
    missing = [a["filename"] for a in attachments if not a["stored"]]
    if missing:
        raise RuntimeError("Weiterleitung gestoppt: Anlage wurde wegen des Größenlimits nicht gespeichert: " + ", ".join(missing))
    for attachment in attachments:
        maintype, subtype = attachment["content_type"].split("/", 1)
        outgoing.add_attachment(attachment["content"] or b"", maintype=maintype, subtype=subtype, filename=attachment["filename"])
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
