import json
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import Body, Cookie, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .exchange import create_folder, fetch_mailbox, forward_message, list_folders, move_message, rule_matches, test_mailbox_connection, test_mode_enabled, test_mode_value
from .security import decrypt, encrypt, hash_password, new_session, session_max_age_seconds, token_hash, verify_password

STATIC = Path(__file__).parent / "static"
VERSION_FILE = Path(__file__).parent.parent / "VERSION"
stop_event = threading.Event()


class NoCacheStaticFiles(StaticFiles):
    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response


def asset_version():
    try:
        return str(max(p.stat().st_mtime_ns for p in STATIC.iterdir() if p.is_file()))
    except OSError:
        return db.now_iso()


def app_version():
    value = os.getenv("APP_VERSION")
    if not value:
        try:
            value = VERSION_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            value = "dev"
    return value


def bootstrap_admin():
    if db.row("SELECT id FROM users LIMIT 1"):
        return
    password = os.getenv("ADMIN_PASSWORD", "")
    if len(password) < 10:
        raise RuntimeError("ADMIN_PASSWORD muss beim ersten Start mindestens 10 Zeichen lang sein")
    db.execute("INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)", ("admin@local", "Administrator", "admin", hash_password(password), db.now_iso()))


def poll_interval_seconds():
    try:
        return max(15, int(db.get_setting("poll_interval_seconds", os.getenv("POLL_INTERVAL_SECONDS", "60"))))
    except (TypeError, ValueError):
        return 60


def sync_all():
    for box in db.rows("SELECT * FROM mailboxes WHERE active=1 AND auto_sync=1"):
        try:
            fetch_mailbox(box, process_rules=bool(box.get("auto_process", 0)))
        except Exception as exc:
            db.execute("UPDATE mailboxes SET last_error=? WHERE id=?", (str(exc)[:500], box["id"]))
            db.audit("sync_failed", mailbox_id=box["id"], error=str(exc)[:500])


def poll_loop():
    while not stop_event.wait(3):
        sync_all()
        stop_event.wait(poll_interval_seconds())


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    bootstrap_admin()
    thread = threading.Thread(target=poll_loop, daemon=True, name="mail-poller")
    thread.start()
    yield
    stop_event.set()


app = FastAPI(title="Mailsorter", version=app_version().lstrip("v"), lifespan=lifespan)
app.mount("/static", NoCacheStaticFiles(directory=STATIC), name="static")


def current_user(session: str | None):
    if not session:
        return None
    return db.row("""SELECT u.id,u.email,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""", (token_hash(session), datetime.now(timezone.utc).isoformat()))


def require_user(session):
    user = current_user(session)
    if not user:
        raise HTTPException(401, "Nicht angemeldet")
    return user


def require_admin(session):
    user = require_user(session)
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator-Rechte erforderlich")
    return user


def mailbox_filter(user, alias="m"):
    if user.get("role") == "admin" or "id" not in user:
        return "1=1", []
    return f"{alias}.mailbox_id IN (SELECT mailbox_id FROM mailbox_permissions WHERE user_id=?)", [user["id"]]


def mailbox_table_filter(user, alias="b"):
    if user.get("role") == "admin" or "id" not in user:
        return "1=1", []
    return f"{alias}.id IN (SELECT mailbox_id FROM mailbox_permissions WHERE user_id=?)", [user["id"]]


def ensure_mailbox_access(user, mailbox_id):
    if user.get("role") == "admin" or "id" not in user:
        return
    allowed = db.row("SELECT 1 ok FROM mailbox_permissions WHERE mailbox_id=? AND user_id=?", (mailbox_id, user["id"]))
    if not allowed:
        raise HTTPException(403, "Kein Zugriff auf dieses Postfach")


def normalized_contact(payload):
    name = str(payload.get("name") or "").strip()
    email = str(payload.get("email") or "").strip()
    color = str(payload.get("color") or "#315cf3").strip()
    if not name or not email:
        raise HTTPException(400, "Name und E-Mail sind erforderlich")
    if "@" not in email or len(email) > 254:
        raise HTTPException(400, "Ungültige Kontakt-E-Mail")
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
        raise HTTPException(400, "Farbe muss ein HEX-Wert sein, z. B. #315cf3")
    return {"name": name, "email": email, "color": color.lower()}


@app.get("/", response_class=HTMLResponse)
def index():
    html = (STATIC / "index.html").read_text(encoding="utf-8").replace("__ASSET_VERSION__", asset_version())
    return HTMLResponse(html, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    })


@app.get("/health")
def health():
    return {"status": "ok", "time": db.now_iso()}


@app.post("/api/login")
def login(response: Response, payload: dict = Body(...)):
    email = str(payload.get("email", "")).strip()
    user = db.row("SELECT * FROM users WHERE lower(email)=lower(?) AND active=1", (email,))
    if not user or not verify_password(str(payload.get("password", "")), user["password_hash"]):
        raise HTTPException(401, "E-Mail oder Passwort falsch")
    token, digest, expires = new_session()
    db.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)", (digest, user["id"], expires, db.now_iso()))
    response.set_cookie("session", token, httponly=True, samesite="strict", secure=os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true", max_age=session_max_age_seconds())
    db.audit("login", actor=user["email"])
    return {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]}


@app.post("/api/logout")
def logout(response: Response, session: str | None = Cookie(None)):
    if session:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(session),))
    response.delete_cookie("session")
    return {"ok": True}


@app.get("/api/me")
def me(session: str | None = Cookie(None)):
    return require_user(session)


@app.get("/api/dashboard")
def dashboard(session: str | None = Cookie(None)):
    user = require_user(session)
    msg_filter, msg_args = mailbox_filter(user, "m")
    box_filter, box_args = mailbox_table_filter(user, "b")
    rule_filter = "1=1" if user.get("role") == "admin" or "id" not in user else "(mailbox_id IS NOT NULL AND mailbox_id IN (SELECT mailbox_id FROM mailbox_permissions WHERE user_id=?))"
    rule_args = [] if user.get("role") == "admin" or "id" not in user else [user["id"]]
    return {
        "new": db.row(f"SELECT count(*) n FROM messages m WHERE status='new' AND {msg_filter}", msg_args)["n"],
        "assigned": db.row(f"SELECT count(*) n FROM messages m WHERE status='assigned' AND {msg_filter}", msg_args)["n"],
        "mailboxes": db.row(f"SELECT count(*) n FROM mailboxes b WHERE active=1 AND {box_filter}", box_args)["n"],
        "rules": db.row(f"SELECT count(*) n FROM rules WHERE active=1 AND {rule_filter}", rule_args)["n"],
        "test_mode": test_mode_enabled(),
    }


@app.get("/api/system")
def system_status(session: str | None = Cookie(None)):
    require_user(session)
    return {
        "test_mode": test_mode_enabled(),
        "test_mode_value": test_mode_value(),
        "poll_interval_seconds": poll_interval_seconds(),
        "app_version": app_version(),
    }


@app.put("/api/system")
def update_system(payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_admin(session)
    try:
        interval = int(payload.get("poll_interval_seconds", poll_interval_seconds()))
    except (TypeError, ValueError):
        raise HTTPException(400, "Intervall muss eine Zahl sein")
    if interval < 15 or interval > 86400:
        raise HTTPException(400, "Intervall muss zwischen 15 Sekunden und 24 Stunden liegen")
    db.set_setting("poll_interval_seconds", interval)
    db.audit("system_updated", actor=user["email"], poll_interval_seconds=interval)
    return {"ok": True, "poll_interval_seconds": interval}


@app.get("/api/messages")
def messages(status: str = "", mailbox_id: int | None = None, q: str = "", session: str | None = Cookie(None)):
    user = require_user(session)
    where, args = ["1=1"], []
    access, access_args = mailbox_filter(user, "m"); where.append(access); args.extend(access_args)
    if status:
        where.append("m.status=?"); args.append(status)
    if mailbox_id:
        ensure_mailbox_access(user, mailbox_id)
        where.append("m.mailbox_id=?"); args.append(mailbox_id)
    if q:
        where.append("(m.subject LIKE ? OR m.sender LIKE ? OR m.text_body LIKE ?)"); args.extend([f"%{q}%"] * 3)
    return db.rows(f"""SELECT m.id,m.mailbox_id,m.sender,m.recipients,m.subject,m.received_at,m.status,
      m.assigned_to,m.matched_rule_id,b.name mailbox_name,u.name assigned_name
      FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id LEFT JOIN users u ON u.id=m.assigned_to
      WHERE {' AND '.join(where)} ORDER BY m.received_at DESC LIMIT 500""", args)


@app.get("/api/messages/{message_id}")
def message(message_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
    result = db.row("""SELECT m.*,b.name mailbox_name,u.name assigned_name FROM messages m
      JOIN mailboxes b ON b.id=m.mailbox_id LEFT JOIN users u ON u.id=m.assigned_to WHERE m.id=?""", (message_id,))
    if not result: raise HTTPException(404, "Mail nicht gefunden")
    ensure_mailbox_access(user, result["mailbox_id"])
    result["attachments"] = db.rows("""SELECT id,filename,content_type,size,stored FROM attachments
      WHERE message_id=? ORDER BY id""", (message_id,))
    return result


@app.get("/api/attachments/{attachment_id}/download")
def download_attachment(attachment_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
    attachment = db.row("""SELECT a.*,m.mailbox_id FROM attachments a JOIN messages m ON m.id=a.message_id
      WHERE a.id=?""", (attachment_id,))
    if not attachment: raise HTTPException(404, "Anlage nicht gefunden")
    if "mailbox_id" in attachment:
        ensure_mailbox_access(user, attachment["mailbox_id"])
    if not attachment["stored"] or attachment["content"] is None:
        raise HTTPException(409, "Anlage überschreitet das konfigurierte Speicherlimit und kann nicht heruntergeladen werden")
    filename = attachment["filename"]
    fallback = re.sub(r'[^A-Za-z0-9._ -]+', '_', filename).strip() or "attachment"
    disposition = f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename)}"
    return Response(
        content=attachment["content"], media_type=attachment["content_type"],
        headers={"Content-Disposition": disposition, "X-Content-Type-Options": "nosniff", "Cache-Control": "private, no-store"},
    )


@app.post("/api/messages/{message_id}/assign")
def assign(message_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    msg = db.row("SELECT mailbox_id FROM messages WHERE id=?", (message_id,))
    if not msg: raise HTTPException(404, "Mail nicht gefunden")
    ensure_mailbox_access(user, msg["mailbox_id"])
    if test_mode_enabled():
        raise HTTPException(423, "Testmodus aktiv: Mail wurde nicht weitergeleitet")
    target_user = None
    if payload.get("user_id"):
        target_user = db.row("SELECT * FROM users WHERE id=? AND active=1", (int(payload["user_id"]),))
        if not target_user: raise HTTPException(400, "Zielbenutzer nicht gefunden")
    target_contact = None
    if payload.get("contact_id"):
        target_contact = db.row("SELECT * FROM mailbox_contacts WHERE id=? AND mailbox_id=? AND active=1", (int(payload["contact_id"]), msg["mailbox_id"]))
        if not target_contact: raise HTTPException(400, "Kontakt nicht gefunden")
    target = ((target_user or {}).get("email") or (target_contact or {}).get("email") or str(payload.get("email", ""))).strip()
    if not target:
        raise HTTPException(400, "Weiterleitung benötigt ein Ziel")
    try:
        forward_message(message_id, target, user["email"], user_id=(target_user or {}).get("id"))
        archive_folder = str(payload.get("archive_folder") or "").strip()
        if archive_folder:
            move_message(message_id, archive_folder, user["email"])
    except Exception as exc:
        prefix = "Weiterleitung oder Archivierung fehlgeschlagen" if payload.get("archive_folder") else "Weiterleitung fehlgeschlagen"
        raise HTTPException(502, f"{prefix}: {exc}")
    return {"ok": True}


@app.post("/api/messages/{message_id}/status")
def set_status(message_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    msg = db.row("SELECT mailbox_id FROM messages WHERE id=?", (message_id,))
    if not msg: raise HTTPException(404, "Mail nicht gefunden")
    ensure_mailbox_access(user, msg["mailbox_id"])
    status = payload.get("status")
    if status not in {"new", "assigned", "done", "ignored"}: raise HTTPException(400, "Ungültiger Status")
    db.execute("UPDATE messages SET status=? WHERE id=?", (status, message_id))
    db.audit("status_changed", actor=user["email"], message_id=message_id, status=status)
    return {"ok": True}


@app.post("/api/messages/{message_id}/move")
def move(message_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    msg = db.row("SELECT mailbox_id FROM messages WHERE id=?", (message_id,))
    if not msg: raise HTTPException(404, "Mail nicht gefunden")
    ensure_mailbox_access(user, msg["mailbox_id"])
    if test_mode_enabled():
        raise HTTPException(423, "Testmodus aktiv: Exchange-Mail wurde nicht verschoben")
    try: move_message(message_id, payload.get("folder"), user["email"])
    except Exception as exc: raise HTTPException(502, f"Verschieben fehlgeschlagen: {exc}")
    return {"ok": True}


@app.get("/api/mailboxes")
def mailboxes(session: str | None = Cookie(None)):
    user = require_user(session)
    access, args = mailbox_table_filter(user, "b")
    return db.rows(f"""SELECT b.id,b.name,b.email,b.imap_host,b.imap_port,b.smtp_host,b.smtp_port,b.username,
      b.imap_username,b.smtp_username,b.imap_auth_mode,b.imap_ssl,b.smtp_mode,b.folder,b.active,b.last_sync_at,
      b.auto_sync,b.auto_process,b.last_error,b.created_at,(SELECT count(*) FROM messages m WHERE m.mailbox_id=b.id) message_count,
      (SELECT count(*) FROM attachments a JOIN messages m ON m.id=a.message_id WHERE m.mailbox_id=b.id) attachment_count,
      (SELECT count(*) FROM rules r WHERE r.mailbox_id=b.id) rule_count,
      (SELECT count(*) FROM mailbox_contacts c WHERE c.mailbox_id=b.id AND c.active=1) contact_count
      FROM mailboxes b WHERE {access} ORDER BY b.name""", args)


@app.post("/api/mailboxes")
def add_mailbox(payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_admin(session)
    imap_username = payload.get("imap_username") or payload.get("username")
    smtp_username = payload.get("smtp_username") or imap_username
    required = ["name", "email", "imap_host", "smtp_host", "password"]
    if any(not str(payload.get(k, "")).strip() for k in required): raise HTTPException(400, "Pflichtfelder fehlen")
    if not imap_username: raise HTTPException(400, "IMAP-Anmeldename fehlt")
    auth_mode = payload.get("imap_auth_mode", "auto")
    if auth_mode not in {"auto", "login", "ntlm"}: raise HTTPException(400, "Ungültiger IMAP-Authentifizierungsmodus")
    box_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,imap_port,smtp_host,smtp_port,username,imap_username,smtp_username,imap_auth_mode,password_enc,imap_ssl,smtp_mode,folder,auto_sync,auto_process,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (payload["name"], payload["email"], payload["imap_host"], int(payload.get("imap_port",993)), payload["smtp_host"], int(payload.get("smtp_port",587)), imap_username, imap_username, smtp_username, auth_mode, encrypt(payload["password"]), int(bool(payload.get("imap_ssl",True))), payload.get("smtp_mode","starttls"), payload.get("folder","INBOX"), int(bool(payload.get("auto_sync", False))), int(bool(payload.get("auto_process", False))), db.now_iso()))
    db.audit("mailbox_created", actor=user["email"], mailbox_id=box_id, name=payload["name"])
    return {"id": box_id}


@app.get("/api/mailboxes/{mailbox_id}/contacts")
def mailbox_contacts(mailbox_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
    ensure_mailbox_access(user, mailbox_id)
    box = db.row("SELECT id FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    return db.rows("""SELECT id,mailbox_id,name,email,color,active,created_at FROM mailbox_contacts
      WHERE mailbox_id=? AND active=1 ORDER BY name,email""", (mailbox_id,))


@app.post("/api/mailboxes/{mailbox_id}/contacts")
def add_mailbox_contact(mailbox_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    ensure_mailbox_access(user, mailbox_id)
    box = db.row("SELECT id FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    contact = normalized_contact(payload)
    try:
        contact_id = db.execute("""INSERT INTO mailbox_contacts(mailbox_id,name,email,color,created_at)
          VALUES(?,?,?,?,?)""", (mailbox_id, contact["name"], contact["email"], contact["color"], db.now_iso()))
    except Exception:
        raise HTTPException(409, "Kontakt mit dieser E-Mail existiert für dieses Postfach bereits")
    db.audit("mailbox_contact_created", actor=user["email"], mailbox_id=mailbox_id, contact_id=contact_id, name=contact["name"], email=contact["email"])
    return {"id": contact_id}


@app.put("/api/mailboxes/{mailbox_id}/contacts/{contact_id}")
def update_mailbox_contact(mailbox_id: int, contact_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    ensure_mailbox_access(user, mailbox_id)
    current = db.row("SELECT id FROM mailbox_contacts WHERE id=? AND mailbox_id=?", (contact_id, mailbox_id))
    if not current: raise HTTPException(404, "Kontakt nicht gefunden")
    contact = normalized_contact(payload)
    active = int(bool(payload.get("active", 1)))
    try:
        db.execute("UPDATE mailbox_contacts SET name=?,email=?,color=?,active=? WHERE id=? AND mailbox_id=?", (contact["name"], contact["email"], contact["color"], active, contact_id, mailbox_id))
    except Exception:
        raise HTTPException(409, "Kontakt mit dieser E-Mail existiert für dieses Postfach bereits")
    db.audit("mailbox_contact_updated", actor=user["email"], mailbox_id=mailbox_id, contact_id=contact_id, name=contact["name"], email=contact["email"], active=bool(active))
    return {"ok": True, "id": contact_id}


@app.delete("/api/mailboxes/{mailbox_id}/contacts/{contact_id}")
def disable_mailbox_contact(mailbox_id: int, contact_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
    ensure_mailbox_access(user, mailbox_id)
    current = db.row("SELECT id,name,email FROM mailbox_contacts WHERE id=? AND mailbox_id=?", (contact_id, mailbox_id))
    if not current: raise HTTPException(404, "Kontakt nicht gefunden")
    db.execute("UPDATE mailbox_contacts SET active=0 WHERE id=? AND mailbox_id=?", (contact_id, mailbox_id))
    db.audit("mailbox_contact_disabled", actor=user["email"], mailbox_id=mailbox_id, contact_id=contact_id, name=current["name"], email=current["email"])
    return {"ok": True}


@app.get("/api/mailboxes/{mailbox_id}/permissions")
def mailbox_permissions(mailbox_id: int, session: str | None = Cookie(None)):
    require_admin(session)
    box = db.row("SELECT id FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    return db.rows("""SELECT u.id,u.email,u.name,u.role,u.active,CASE WHEN p.user_id IS NULL THEN 0 ELSE 1 END allowed
      FROM users u LEFT JOIN mailbox_permissions p ON p.user_id=u.id AND p.mailbox_id=?
      WHERE u.role<>'admin' ORDER BY u.name""", (mailbox_id,))


@app.put("/api/mailboxes/{mailbox_id}/permissions")
def update_mailbox_permissions(mailbox_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    admin = require_admin(session)
    box = db.row("SELECT id,name FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    user_ids = sorted({int(x) for x in payload.get("user_ids", [])})
    if user_ids:
        found = db.rows(f"SELECT id FROM users WHERE role<>'admin' AND active=1 AND id IN ({','.join('?' for _ in user_ids)})", user_ids)
        valid_ids = {u["id"] for u in found}
        missing = set(user_ids) - valid_ids
        if missing: raise HTTPException(400, "Ein oder mehrere Benutzer sind ungültig oder inaktiv")
    db.execute("DELETE FROM mailbox_permissions WHERE mailbox_id=?", (mailbox_id,))
    for user_id in user_ids:
        db.execute("INSERT INTO mailbox_permissions(mailbox_id,user_id,granted_by,created_at) VALUES(?,?,?,?)", (mailbox_id, user_id, admin["id"], db.now_iso()))
    db.audit("mailbox_permissions_updated", actor=admin["email"], mailbox_id=mailbox_id, users=user_ids)
    return {"ok": True, "user_ids": user_ids}


@app.put("/api/mailboxes/{mailbox_id}")
def update_mailbox(mailbox_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_admin(session)
    current = db.row("SELECT * FROM mailboxes WHERE id=?", (mailbox_id,))
    if not current: raise HTTPException(404, "Postfach nicht gefunden")
    imap_username = payload.get("imap_username") or payload.get("username")
    smtp_username = payload.get("smtp_username") or imap_username
    required = ["name", "email", "imap_host", "smtp_host"]
    if any(not str(payload.get(k, "")).strip() for k in required): raise HTTPException(400, "Pflichtfelder fehlen")
    if not imap_username: raise HTTPException(400, "IMAP-Anmeldename fehlt")
    password_enc = encrypt(payload["password"]) if payload.get("password") else current["password_enc"]
    auth_mode = payload.get("imap_auth_mode", current.get("imap_auth_mode") or "auto")
    if auth_mode not in {"auto", "login", "ntlm"}: raise HTTPException(400, "Ungültiger IMAP-Authentifizierungsmodus")
    db.execute("""UPDATE mailboxes SET name=?,email=?,imap_host=?,imap_port=?,smtp_host=?,smtp_port=?,username=?,imap_username=?,smtp_username=?,imap_auth_mode=?,password_enc=?,imap_ssl=?,smtp_mode=?,folder=?,active=?,auto_sync=?,auto_process=?,last_error=NULL WHERE id=?""",
      (payload["name"], payload["email"], payload["imap_host"], int(payload.get("imap_port",993)), payload["smtp_host"], int(payload.get("smtp_port",587)), imap_username, imap_username, smtp_username, auth_mode, password_enc, int(bool(payload.get("imap_ssl",True))), payload.get("smtp_mode","starttls"), payload.get("folder","INBOX"), int(bool(payload.get("active", current["active"]))), int(bool(payload.get("auto_sync", current.get("auto_sync", 0)))), int(bool(payload.get("auto_process", current.get("auto_process", 0)))), mailbox_id))
    db.audit("mailbox_updated", actor=user["email"], mailbox_id=mailbox_id, name=payload["name"], password_changed=bool(payload.get("password")), auto_sync=bool(payload.get("auto_sync", current.get("auto_sync", 0))), auto_process=bool(payload.get("auto_process", current.get("auto_process", 0))))
    return {"ok": True}


@app.post("/api/mailboxes/test")
def test_mailbox(payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_admin(session)
    current = db.row("SELECT * FROM mailboxes WHERE id=?", (int(payload["id"]),)) if payload.get("id") else None
    values = dict(current or {})
    values.update({k: v for k, v in payload.items() if v is not None and k != "password"})
    values["imap_username"] = values.get("imap_username") or values.get("username")
    values["smtp_username"] = values.get("smtp_username") or values["imap_username"]
    required = ["imap_host", "smtp_host", "imap_username", "smtp_username"]
    if any(not str(values.get(k, "")).strip() for k in required): raise HTTPException(400, "Server und Benutzername werden für den Test benötigt")
    password = str(payload.get("password") or "")
    if not password and current:
        password = decrypt(current["password_enc"])
    if not password: raise HTTPException(400, "Passwort wird für den Verbindungstest benötigt")
    result = test_mailbox_connection(values, password)
    db.audit("mailbox_connection_test", actor=user["email"], mailbox_id=(current or {}).get("id"), imap_ok=result["imap"]["ok"], smtp_ok=result["smtp"]["ok"])
    return result


@app.post("/api/mailboxes/{mailbox_id}/sync")
def sync_mailbox(mailbox_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
    ensure_mailbox_access(user, mailbox_id)
    box = db.row("SELECT * FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    try: result = fetch_mailbox(box, process_rules=True)
    except Exception as exc: raise HTTPException(502, f"Synchronisierung fehlgeschlagen: {exc}")
    db.audit("manual_sync", actor=user["email"], mailbox_id=mailbox_id, new_messages=result["new_messages"], removed_messages=result["removed_messages"])
    return result


@app.get("/api/mailboxes/{mailbox_id}/folders")
def mailbox_folders(mailbox_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
    ensure_mailbox_access(user, mailbox_id)
    box = db.row("SELECT * FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    try: return list_folders(box)
    except Exception as exc: raise HTTPException(502, f"Ordner konnten nicht geladen werden: {exc}")


@app.post("/api/mailboxes/{mailbox_id}/folders")
def add_mailbox_folder(mailbox_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_admin(session)
    box = db.row("SELECT * FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    if not box["active"]: raise HTTPException(409, "Das Postfach ist deaktiviert")
    try: folder = create_folder(box, payload.get("name"), payload.get("parent"))
    except ValueError as exc: raise HTTPException(400, str(exc))
    except RuntimeError as exc:
        status = 409 if test_mode_enabled() else 502
        raise HTTPException(status, str(exc))
    db.audit("mailbox_folder_created", actor=user["email"], mailbox_id=mailbox_id, folder=folder, parent=payload.get("parent") or "")
    root = str(box.get("folder") or "INBOX").strip().rstrip("/") + "/"
    return {"ok": True, "folder": folder, "display": folder[len(root):] if folder.startswith(root) else folder}


@app.delete("/api/mailboxes/{mailbox_id}")
def disable_mailbox(mailbox_id: int, session: str | None = Cookie(None)):
    user = require_admin(session)
    box = db.row("SELECT id,name FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    db.execute("UPDATE mailboxes SET active=0 WHERE id=?", (mailbox_id,))
    db.audit("mailbox_disabled", actor=user["email"], mailbox_id=mailbox_id, name=box["name"])
    return {"ok": True}


@app.delete("/api/mailboxes/{mailbox_id}/purge")
def delete_mailbox(mailbox_id: int, session: str | None = Cookie(None)):
    user = require_admin(session)
    box = db.row("SELECT id,name,active FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    if box["active"]: raise HTTPException(409, "Postfach zuerst deaktivieren, danach kann es endgültig gelöscht werden")
    details = db.purge_mailbox(mailbox_id, user["email"])
    return {"ok": True, **details}


@app.get("/api/users")
def users(session: str | None = Cookie(None)):
    require_user(session)
    return db.rows("SELECT id,email,name,role,active,created_at FROM users ORDER BY name")


@app.post("/api/users")
def add_user(payload: dict = Body(...), session: str | None = Cookie(None)):
    admin = require_admin(session)
    email, name = str(payload.get("email", "")).strip(), str(payload.get("name", "")).strip()
    role = payload.get("role", "agent") if payload.get("role") in {"agent", "admin"} else "agent"
    if not email or not name or len(str(payload.get("password", ""))) < 10: raise HTTPException(400, "Name, E-Mail und Passwort (mind. 10 Zeichen) erforderlich")
    try:
        user_id = db.execute("INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)", (email, name, role, hash_password(payload["password"]), db.now_iso()))
    except Exception: raise HTTPException(409, "E-Mail bereits vorhanden")
    db.audit("user_created", actor=admin["email"], user_id=user_id, email=email)
    return {"id": user_id}


@app.put("/api/users/{user_id}/password")
def reset_user_password(user_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    admin = require_admin(session)
    user = db.row("SELECT id,email,name FROM users WHERE id=?", (user_id,))
    if not user: raise HTTPException(404, "Benutzer nicht gefunden")
    password = str(payload.get("password") or "")
    if len(password) < 10: raise HTTPException(400, "Passwort muss mindestens 10 Zeichen lang sein")
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(password), user_id))
    db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    db.audit("user_password_reset", actor=admin["email"], user_id=user_id, email=user["email"])
    return {"ok": True, "id": user_id}


@app.get("/api/rules")
def rules(session: str | None = Cookie(None)):
    user = require_user(session)
    where = "r.mailbox_id IS NOT NULL" if user.get("role") == "admin" or "id" not in user else "(r.mailbox_id IS NOT NULL AND r.mailbox_id IN (SELECT mailbox_id FROM mailbox_permissions WHERE user_id=?))"
    args = [] if user.get("role") == "admin" or "id" not in user else [user["id"]]
    return db.rows(f"""SELECT r.*,b.name mailbox_name,u.name target_name,u.email user_email FROM rules r
      LEFT JOIN mailboxes b ON b.id=r.mailbox_id LEFT JOIN users u ON u.id=r.target_user_id
      WHERE {where} ORDER BY r.priority,r.id""", args)


RULE_IMPORT_FIELDS = ("name", "field", "operator", "value", "value_logic", "action", "target_email", "target_folder", "post_forward_folder", "priority", "stop_processing")


def rule_export_row(rule):
    return {
        "name": rule["name"], "mailbox_email": rule["mailbox_email"], "mailbox_name": rule["mailbox_name"],
        "field": rule["field"], "operator": rule["operator"], "value": rule["value"], "value_logic": rule.get("value_logic") or "any",
        "action": rule["action"], "target_email": rule.get("target_email"), "target_folder": rule.get("target_folder"),
        "post_forward_folder": rule.get("post_forward_folder"), "priority": rule["priority"],
        "stop_processing": int(bool(rule["stop_processing"])), "active": int(bool(rule["active"])),
    }


@app.get("/api/rules/export")
def export_rules(mailbox_id: int | None = None, session: str | None = Cookie(None)):
    user = require_user(session)
    where, args = ["r.mailbox_id IS NOT NULL"], []
    if mailbox_id:
        ensure_mailbox_access(user, mailbox_id)
        where.append("r.mailbox_id=?"); args.append(mailbox_id)
    elif user.get("role") != "admin" and "id" in user:
        where.append("r.mailbox_id IN (SELECT mailbox_id FROM mailbox_permissions WHERE user_id=?)"); args.append(user["id"])
    rows = db.rows(f"""SELECT r.*,b.email mailbox_email,b.name mailbox_name FROM rules r
      JOIN mailboxes b ON b.id=r.mailbox_id WHERE {' AND '.join(where)} ORDER BY b.name,r.priority,r.id""", args)
    db.audit("rules_exported", actor=user["email"], count=len(rows), mailbox_id=mailbox_id)
    return {"version": 1, "exported_at": db.now_iso(), "rules": [rule_export_row(r) for r in rows]}


@app.post("/api/rules/import")
def import_rules(payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    items = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise HTTPException(400, "Importdatei enthält keine Regeln")
    target_mailbox_id = payload.get("mailbox_id") or None
    if target_mailbox_id:
        ensure_mailbox_access(user, int(target_mailbox_id))
    imported, skipped = 0, 0
    for item in items:
        if not isinstance(item, dict):
            skipped += 1; continue
        mailbox_id = int(target_mailbox_id) if target_mailbox_id else None
        if not mailbox_id:
            mailbox_email = str(item.get("mailbox_email") or "").strip()
            box = db.row("SELECT id FROM mailboxes WHERE lower(email)=lower(?) AND active=1", (mailbox_email,))
            if not box:
                skipped += 1; continue
            mailbox_id = box["id"]
            ensure_mailbox_access(user, mailbox_id)
        rule_payload = {k: item.get(k) for k in RULE_IMPORT_FIELDS}
        rule_payload["mailbox_id"] = mailbox_id
        try:
            rule = normalized_rule(rule_payload)
        except HTTPException:
            skipped += 1; continue
        db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,value_logic,action,target_user_id,target_email,target_folder,post_forward_folder,priority,active,stop_processing,created_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (rule["name"], rule["mailbox_id"], rule["field"], rule["operator"], rule["value"], rule["value_logic"], rule["action"], None, rule["target_email"], rule["target_folder"], rule["post_forward_folder"], rule["priority"], int(bool(item.get("active", 1))), rule["stop_processing"], db.now_iso()))
        imported += 1
    db.audit("rules_imported", actor=user["email"], imported=imported, skipped=skipped, target_mailbox_id=target_mailbox_id)
    return {"ok": True, "imported": imported, "skipped": skipped}


def get_saved_rule_for_apply(rule_id, user):
    rule = db.row("""SELECT r.*,u.name target_name,u.email user_email FROM rules r
      LEFT JOIN users u ON u.id=r.target_user_id WHERE r.id=?""", (rule_id,))
    if not rule: raise HTTPException(404, "Regel nicht gefunden")
    if not rule["active"]: raise HTTPException(409, "Nur aktive Regeln können angewendet werden")
    if rule["mailbox_id"] is None:
        raise HTTPException(400, "Diese alte globale Regel kann nicht mehr angewendet werden")
    ensure_mailbox_access(user, rule["mailbox_id"])
    return rule


def apply_saved_rule_to_existing(rule, user):
    access, access_args = mailbox_filter(user, "m")
    messages = db.rows("""SELECT m.id,m.mailbox_id,m.sender,m.recipients,m.subject,m.received_at,
      m.text_body,m.status,m.matched_rule_id,b.name mailbox_name FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
      WHERE (? IS NULL OR m.mailbox_id=?) AND (m.matched_rule_id IS NULL OR m.matched_rule_id<>?) AND """ + access + """
      ORDER BY m.received_at DESC LIMIT 2000""", (rule["mailbox_id"], rule["mailbox_id"], rule["id"], *access_args))
    matches = [m for m in messages if rule_matches(rule, m)]
    actions = planned_rule_actions(rule)
    samples = [{k: m[k] for k in ("id", "mailbox_id", "mailbox_name", "sender", "subject", "received_at", "status")} for m in matches[:100]]
    dry_run = test_mode_enabled()
    if dry_run:
        db.audit("rule_apply_test", actor=user["email"], rule_id=rule["id"], matched=len(matches), actions=actions)
        return {"rule_id": rule["id"], "rule_name": rule["name"], "dry_run": True, "tested": len(messages), "matched": len(matches), "applied": 0, "failed": 0, "actions": len(actions) * len(matches), "samples": samples, "failures": []}
    applied, failures = 0, []
    for message in matches:
        try:
            if rule.get("action") == "move":
                move_message(message["id"], rule["target_folder"], user["email"], rule["id"])
            else:
                target = rule["target_email"] or rule["user_email"]
                forward_message(message["id"], target, user["email"], rule["id"], rule.get("target_user_id"))
                if rule.get("post_forward_folder"):
                    move_message(message["id"], rule["post_forward_folder"], user["email"], rule["id"])
            db.execute("UPDATE messages SET matched_rule_id=? WHERE id=?", (rule["id"], message["id"]))
            applied += 1
        except Exception as exc:
            failures.append({"id": message["id"], "subject": message["subject"], "error": str(exc)})
            db.audit("rule_apply_failed", actor=user["email"], message_id=message["id"], mailbox_id=message["mailbox_id"], rule_id=rule["id"], error=str(exc)[:500])
    db.audit("rule_applied_existing", actor=user["email"], rule_id=rule["id"], matched=len(matches), applied=applied, failed=len(failures))
    return {"rule_id": rule["id"], "rule_name": rule["name"], "dry_run": False, "tested": len(messages), "matched": len(matches), "applied": applied, "failed": len(failures), "actions": len(actions) * applied, "samples": samples, "failures": failures[:20]}


def validate_rule_condition(payload):
    if payload.get("field") not in {"from", "to", "subject", "body"}:
        raise HTTPException(400, "Ungültiges Regelfeld")
    if payload.get("operator") not in {"contains", "equals", "starts_with", "regex"}:
        raise HTTPException(400, "Ungültiger Regelvergleich")
    if not str(payload.get("value", "")):
        raise HTTPException(400, "Regelwert fehlt")
    if payload.get("value_logic", "any") not in {"any", "all"}:
        raise HTTPException(400, "Ungültige Suchlogik")


def normalized_rule(payload):
    validate_rule_condition(payload)
    action = payload.get("action", "forward")
    if action not in {"forward", "move"}: raise HTTPException(400, "Ungültige Regelaktion")
    mailbox_id = payload.get("mailbox_id") or None
    target_user_id = payload.get("target_user_id") or None
    target_email = str(payload.get("target_email") or "").strip() or None
    target_folder = str(payload.get("target_folder") or "").strip() or None
    post_forward_folder = str(payload.get("post_forward_folder") or "").strip() or None
    if not mailbox_id: raise HTTPException(400, "Regeln müssen einem Postfach zugeordnet sein")
    if action == "forward" and not target_user_id and not target_email: raise HTTPException(400, "Weiterleitung benötigt ein Ziel")
    if action == "move" and (not mailbox_id or not target_folder): raise HTTPException(400, "Verschieben benötigt Postfach und Zielordner")
    if action == "forward" and post_forward_folder and not mailbox_id: raise HTTPException(400, "Archivierung nach Weiterleitung benötigt ein konkretes Postfach")
    try: priority = int(payload.get("priority", 100))
    except (TypeError, ValueError): raise HTTPException(400, "Priorität muss eine Zahl sein")
    return {
        "name": str(payload.get("name") or "Neue Regel").strip() or "Neue Regel",
        "mailbox_id": mailbox_id, "field": payload["field"], "operator": payload["operator"],
        "value": str(payload.get("value", "")), "value_logic": payload.get("value_logic", "any"), "action": action,
        "target_user_id": target_user_id if action == "forward" else None,
        "target_email": target_email if action == "forward" else None,
        "target_folder": target_folder if action == "move" else None,
        "post_forward_folder": post_forward_folder if action == "forward" else None,
        "priority": priority, "stop_processing": int(bool(payload.get("stop_processing", 1))),
    }


@app.post("/api/rules/preview")
def preview_rule(payload: dict = Body(...), session: str | None = Cookie(None)):
    """Evaluate one unsaved rule without performing an action or writing audit data."""
    user = require_user(session)
    validate_rule_condition(payload)
    mailbox_id = payload.get("mailbox_id") or None
    if mailbox_id:
        ensure_mailbox_access(user, mailbox_id)
    else:
        raise HTTPException(400, "Regeltest benötigt ein Postfach")
    access, access_args = mailbox_filter(user, "m")
    messages = db.rows("""SELECT m.id,m.mailbox_id,m.sender,m.recipients,m.subject,m.received_at,
      m.text_body,m.status,b.name mailbox_name FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
      WHERE (? IS NULL OR m.mailbox_id=?) AND """ + access + " ORDER BY m.received_at DESC LIMIT 2000", (mailbox_id, mailbox_id, *access_args))
    matches = [m for m in messages if rule_matches(payload, m)]
    samples = [{k: m[k] for k in ("id", "mailbox_id", "mailbox_name", "sender", "subject", "received_at", "status")} for m in matches[:100]]
    return {"tested": len(messages), "matched": len(matches), "unmatched": len(messages) - len(matches), "samples": samples}


@app.get("/api/rules/simulate")
def simulate_rules(mailbox_id: int | None = None, session: str | None = Cookie(None)):
    """Dry-run the complete active ruleset in production order without side effects."""
    user = require_user(session)
    if mailbox_id:
        ensure_mailbox_access(user, mailbox_id)
    access, access_args = mailbox_filter(user, "m")
    messages = db.rows("""SELECT m.id,m.mailbox_id,m.sender,m.recipients,m.subject,m.received_at,
      m.text_body,m.status,b.name mailbox_name FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
      WHERE (? IS NULL OR m.mailbox_id=?) AND """ + access + " ORDER BY m.received_at DESC LIMIT 2000", (mailbox_id, mailbox_id, *access_args))
    rule_where = "r.active=1 AND r.mailbox_id IS NOT NULL" if user.get("role") == "admin" or "id" not in user else "r.active=1 AND r.mailbox_id IS NOT NULL AND r.mailbox_id IN (SELECT mailbox_id FROM mailbox_permissions WHERE user_id=?)"
    rule_args = [] if user.get("role") == "admin" or "id" not in user else [user["id"]]
    ruleset = db.rows("""SELECT r.*,u.name target_name,u.email user_email FROM rules r
      LEFT JOIN users u ON u.id=r.target_user_id WHERE """ + rule_where + " ORDER BY r.priority,r.id", rule_args)
    results, matched_messages, action_count = [], 0, 0
    for message in messages:
        actions = []
        for rule in ruleset:
            if rule["mailbox_id"] is not None and rule["mailbox_id"] != message["mailbox_id"]:
                continue
            if not rule_matches(rule, message):
                continue
            if rule.get("action") == "move":
                actions.append({"rule_id": rule["id"], "rule_name": rule["name"], "priority": rule["priority"], "action": "move", "target": rule["target_folder"], "stops": bool(rule["stop_processing"])})
                action_count += 1
            else:
                actions.append({"rule_id": rule["id"], "rule_name": rule["name"], "priority": rule["priority"], "action": "forward", "target": rule["target_name"] or rule["target_email"] or rule["user_email"], "stops": bool(rule["stop_processing"]) and not rule.get("post_forward_folder")})
                action_count += 1
                if rule.get("post_forward_folder"):
                    actions.append({"rule_id": rule["id"], "rule_name": rule["name"], "priority": rule["priority"], "action": "move", "target": rule["post_forward_folder"], "stops": bool(rule["stop_processing"])})
                    action_count += 1
            if rule["stop_processing"]:
                break
        if actions:
            matched_messages += 1
            if len(results) < 200:
                results.append({"id": message["id"], "mailbox_name": message["mailbox_name"], "sender": message["sender"], "subject": message["subject"], "received_at": message["received_at"], "actions": actions})
    return {"tested": len(messages), "matched_messages": matched_messages, "unmatched_messages": len(messages) - matched_messages, "actions": action_count, "results": results}


def planned_rule_actions(rule):
    if rule.get("action") == "move":
        return [{"action": "move", "target": rule["target_folder"]}]
    actions = [{"action": "forward", "target": rule["target_name"] or rule["target_email"] or rule["user_email"]}]
    if rule.get("post_forward_folder"):
        actions.append({"action": "move", "target": rule["post_forward_folder"]})
    return actions


@app.post("/api/rules/{rule_id}/apply")
def apply_rule_to_existing(rule_id: int, session: str | None = Cookie(None)):
    """Apply one saved rule to already imported messages. In test mode this is only a dry-run."""
    user = require_user(session)
    rule = get_saved_rule_for_apply(rule_id, user)
    result = apply_saved_rule_to_existing(rule, user)
    result.pop("rule_id", None)
    result.pop("rule_name", None)
    return result


@app.post("/api/rules/apply")
def apply_multiple_rules_to_existing(payload: dict = Body(...), session: str | None = Cookie(None)):
    """Apply several saved rules to already imported messages. In test mode this is only a dry-run."""
    user = require_user(session)
    rule_ids = []
    for value in payload.get("rule_ids", []):
        try:
            rule_id = int(value)
        except (TypeError, ValueError):
            continue
        if rule_id not in rule_ids:
            rule_ids.append(rule_id)
    if not rule_ids:
        raise HTTPException(400, "Keine Regeln ausgewählt")
    if len(rule_ids) > 50:
        raise HTTPException(400, "Maximal 50 Regeln gleichzeitig anwenden")
    results, errors = [], []
    for rule_id in rule_ids:
        try:
            rule = get_saved_rule_for_apply(rule_id, user)
            results.append(apply_saved_rule_to_existing(rule, user))
        except HTTPException as exc:
            errors.append({"rule_id": rule_id, "error": str(exc.detail)})
    totals = {
        "dry_run": test_mode_enabled(),
        "requested": len(rule_ids), "processed": len(results), "errors": len(errors),
        "tested": sum(r["tested"] for r in results), "matched": sum(r["matched"] for r in results),
        "applied": sum(r["applied"] for r in results), "failed": sum(r["failed"] for r in results),
        "actions": sum(r["actions"] for r in results),
    }
    db.audit("rules_batch_applied_existing", actor=user["email"], rule_ids=rule_ids, **totals)
    return {**totals, "results": results, "error_details": errors}


@app.post("/api/rules")
def add_rule(payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    rule = normalized_rule(payload)
    ensure_mailbox_access(user, rule["mailbox_id"])
    rule_id = db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,value_logic,action,target_user_id,target_email,target_folder,post_forward_folder,priority,active,stop_processing,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""", (rule["name"], rule["mailbox_id"], rule["field"], rule["operator"], rule["value"], rule["value_logic"], rule["action"], rule["target_user_id"], rule["target_email"], rule["target_folder"], rule["post_forward_folder"], rule["priority"], rule["stop_processing"], db.now_iso()))
    db.audit("rule_created", actor=user["email"], rule_id=rule_id, name=rule["name"])
    return {"id": rule_id}


@app.post("/api/rules/{rule_id}/copy")
def copy_rule(rule_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
    current = db.row("SELECT * FROM rules WHERE id=?", (rule_id,))
    if not current: raise HTTPException(404, "Regel nicht gefunden")
    if current["mailbox_id"] is None:
        raise HTTPException(400, "Diese alte globale Regel kann nicht mehr kopiert werden")
    ensure_mailbox_access(user, current["mailbox_id"])
    new_name = f"Kopie von {current['name']}"[:120]
    new_id = db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,value_logic,action,target_user_id,target_email,target_folder,post_forward_folder,priority,active,stop_processing,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)""", (new_name, current["mailbox_id"], current["field"], current["operator"], current["value"], current.get("value_logic") or "any", current["action"], current["target_user_id"], current["target_email"], current["target_folder"], current["post_forward_folder"], current["priority"], current["stop_processing"], db.now_iso()))
    db.audit("rule_copied", actor=user["email"], rule_id=rule_id, copied_rule_id=new_id, name=new_name)
    return {"id": new_id, "name": new_name, "active": False}


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    current = db.row("SELECT * FROM rules WHERE id=?", (rule_id,))
    if not current: raise HTTPException(404, "Regel nicht gefunden")
    was_global = current["mailbox_id"] is None
    if current["mailbox_id"] is not None:
        ensure_mailbox_access(user, current["mailbox_id"])
    rule = normalized_rule(payload)
    ensure_mailbox_access(user, rule["mailbox_id"])
    active = int(bool(payload.get("active", current["active"])))
    db.execute("""UPDATE rules SET name=?,mailbox_id=?,field=?,operator=?,value=?,value_logic=?,action=?,target_user_id=?,target_email=?,target_folder=?,post_forward_folder=?,priority=?,active=?,stop_processing=? WHERE id=?""",
      (rule["name"], rule["mailbox_id"], rule["field"], rule["operator"], rule["value"], rule["value_logic"], rule["action"], rule["target_user_id"], rule["target_email"], rule["target_folder"], rule["post_forward_folder"], rule["priority"], active, rule["stop_processing"], rule_id))
    db.audit("rule_updated", actor=user["email"], rule_id=rule_id, name=rule["name"], rule_action=rule["action"], post_forward_folder=rule["post_forward_folder"], active=bool(active), converted_global=was_global)
    return {"ok": True, "id": rule_id}


@app.delete("/api/rules/{rule_id}")
def disable_rule(rule_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
    rule = db.row("SELECT id,mailbox_id FROM rules WHERE id=?", (rule_id,))
    if not rule: raise HTTPException(404, "Regel nicht gefunden")
    if rule["mailbox_id"] is not None:
        ensure_mailbox_access(user, rule["mailbox_id"])
    db.execute("UPDATE rules SET active=0 WHERE id=?", (rule_id,))
    db.audit("rule_disabled", actor=user["email"], rule_id=rule_id)
    return {"ok": True}


@app.get("/api/audit")
def audit_log(session: str | None = Cookie(None)):
    require_user(session)
    result = db.rows("""SELECT a.*,m.subject,b.name mailbox_name FROM audit_log a LEFT JOIN messages m ON m.id=a.message_id
      LEFT JOIN mailboxes b ON b.id=a.mailbox_id ORDER BY a.created_at DESC LIMIT 1000""")
    for item in result:
        try: item["details"] = json.loads(item["details"])
        except Exception: pass
    return result
