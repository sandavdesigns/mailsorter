import json
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, Cookie, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .exchange import fetch_mailbox, forward_message, list_folders, move_message, rule_matches, test_mailbox_connection, test_mode_enabled
from .security import decrypt, encrypt, hash_password, new_session, token_hash, verify_password

STATIC = Path(__file__).parent / "static"
stop_event = threading.Event()


def bootstrap_admin():
    if db.row("SELECT id FROM users LIMIT 1"):
        return
    password = os.getenv("ADMIN_PASSWORD", "")
    if len(password) < 10:
        raise RuntimeError("ADMIN_PASSWORD muss beim ersten Start mindestens 10 Zeichen lang sein")
    db.execute("INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)", ("admin@local", "Administrator", "admin", hash_password(password), db.now_iso()))


def sync_all():
    for box in db.rows("SELECT * FROM mailboxes WHERE active=1"):
        try:
            fetch_mailbox(box)
        except Exception as exc:
            db.execute("UPDATE mailboxes SET last_error=? WHERE id=?", (str(exc)[:500], box["id"]))
            db.audit("sync_failed", mailbox_id=box["id"], error=str(exc)[:500])


def poll_loop():
    interval = max(15, int(os.getenv("POLL_INTERVAL_SECONDS", "60")))
    while not stop_event.wait(3):
        sync_all()
        stop_event.wait(interval)


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    bootstrap_admin()
    thread = threading.Thread(target=poll_loop, daemon=True, name="mail-poller")
    thread.start()
    yield
    stop_event.set()


app = FastAPI(title="Mailsorter", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


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


@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "time": db.now_iso()}


@app.post("/api/login")
def login(response: Response, payload: dict = Body(...)):
    user = db.row("SELECT * FROM users WHERE lower(email)=lower(?) AND active=1", (str(payload.get("email", "")),))
    if not user or not verify_password(str(payload.get("password", "")), user["password_hash"]):
        raise HTTPException(401, "E-Mail oder Passwort falsch")
    token, digest, expires = new_session()
    db.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)", (digest, user["id"], expires, db.now_iso()))
    response.set_cookie("session", token, httponly=True, samesite="strict", secure=os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true", max_age=43200)
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
    require_user(session)
    return {
        "new": db.row("SELECT count(*) n FROM messages WHERE status='new'")["n"],
        "assigned": db.row("SELECT count(*) n FROM messages WHERE status='assigned'")["n"],
        "mailboxes": db.row("SELECT count(*) n FROM mailboxes WHERE active=1")["n"],
        "rules": db.row("SELECT count(*) n FROM rules WHERE active=1")["n"],
        "test_mode": test_mode_enabled(),
    }


@app.get("/api/system")
def system_status(session: str | None = Cookie(None)):
    require_user(session)
    return {"test_mode": test_mode_enabled()}


@app.get("/api/messages")
def messages(status: str = "", mailbox_id: int | None = None, q: str = "", session: str | None = Cookie(None)):
    require_user(session)
    where, args = ["1=1"], []
    if status:
        where.append("m.status=?"); args.append(status)
    if mailbox_id:
        where.append("m.mailbox_id=?"); args.append(mailbox_id)
    if q:
        where.append("(m.subject LIKE ? OR m.sender LIKE ? OR m.text_body LIKE ?)"); args.extend([f"%{q}%"] * 3)
    return db.rows(f"""SELECT m.id,m.mailbox_id,m.sender,m.recipients,m.subject,m.received_at,m.status,
      m.assigned_to,m.matched_rule_id,b.name mailbox_name,u.name assigned_name
      FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id LEFT JOIN users u ON u.id=m.assigned_to
      WHERE {' AND '.join(where)} ORDER BY m.received_at DESC LIMIT 500""", args)


@app.get("/api/messages/{message_id}")
def message(message_id: int, session: str | None = Cookie(None)):
    require_user(session)
    result = db.row("""SELECT m.*,b.name mailbox_name,u.name assigned_name FROM messages m
      JOIN mailboxes b ON b.id=m.mailbox_id LEFT JOIN users u ON u.id=m.assigned_to WHERE m.id=?""", (message_id,))
    if not result: raise HTTPException(404, "Mail nicht gefunden")
    return result


@app.post("/api/messages/{message_id}/assign")
def assign(message_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    if test_mode_enabled():
        raise HTTPException(423, "Testmodus aktiv: Mail wurde nicht weitergeleitet")
    target_user = None
    if payload.get("user_id"):
        target_user = db.row("SELECT * FROM users WHERE id=? AND active=1", (int(payload["user_id"]),))
        if not target_user: raise HTTPException(400, "Zielbenutzer nicht gefunden")
    target = (target_user or {}).get("email") or str(payload.get("email", ""))
    try:
        forward_message(message_id, target, user["email"], user_id=(target_user or {}).get("id"))
    except Exception as exc:
        raise HTTPException(502, f"Weiterleitung fehlgeschlagen: {exc}")
    return {"ok": True}


@app.post("/api/messages/{message_id}/status")
def set_status(message_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    status = payload.get("status")
    if status not in {"new", "assigned", "done", "ignored"}: raise HTTPException(400, "Ungültiger Status")
    db.execute("UPDATE messages SET status=? WHERE id=?", (status, message_id))
    db.audit("status_changed", actor=user["email"], message_id=message_id, status=status)
    return {"ok": True}


@app.post("/api/messages/{message_id}/move")
def move(message_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    if test_mode_enabled():
        raise HTTPException(423, "Testmodus aktiv: Exchange-Mail wurde nicht verschoben")
    try: move_message(message_id, payload.get("folder"), user["email"])
    except Exception as exc: raise HTTPException(502, f"Verschieben fehlgeschlagen: {exc}")
    return {"ok": True}


@app.get("/api/mailboxes")
def mailboxes(session: str | None = Cookie(None)):
    require_user(session)
    return db.rows("SELECT id,name,email,imap_host,imap_port,smtp_host,smtp_port,username,imap_ssl,smtp_mode,folder,active,last_sync_at,last_error,created_at FROM mailboxes ORDER BY name")


@app.post("/api/mailboxes")
def add_mailbox(payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_admin(session)
    required = ["name", "email", "imap_host", "smtp_host", "username", "password"]
    if any(not str(payload.get(k, "")).strip() for k in required): raise HTTPException(400, "Pflichtfelder fehlen")
    box_id = db.execute("""INSERT INTO mailboxes(name,email,imap_host,imap_port,smtp_host,smtp_port,username,password_enc,imap_ssl,smtp_mode,folder,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (payload["name"], payload["email"], payload["imap_host"], int(payload.get("imap_port",993)), payload["smtp_host"], int(payload.get("smtp_port",587)), payload["username"], encrypt(payload["password"]), int(bool(payload.get("imap_ssl",True))), payload.get("smtp_mode","starttls"), payload.get("folder","INBOX"), db.now_iso()))
    db.audit("mailbox_created", actor=user["email"], mailbox_id=box_id, name=payload["name"])
    return {"id": box_id}


@app.put("/api/mailboxes/{mailbox_id}")
def update_mailbox(mailbox_id: int, payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_admin(session)
    current = db.row("SELECT * FROM mailboxes WHERE id=?", (mailbox_id,))
    if not current: raise HTTPException(404, "Postfach nicht gefunden")
    required = ["name", "email", "imap_host", "smtp_host", "username"]
    if any(not str(payload.get(k, "")).strip() for k in required): raise HTTPException(400, "Pflichtfelder fehlen")
    password_enc = encrypt(payload["password"]) if payload.get("password") else current["password_enc"]
    db.execute("""UPDATE mailboxes SET name=?,email=?,imap_host=?,imap_port=?,smtp_host=?,smtp_port=?,username=?,password_enc=?,imap_ssl=?,smtp_mode=?,folder=?,active=?,last_error=NULL WHERE id=?""",
      (payload["name"], payload["email"], payload["imap_host"], int(payload.get("imap_port",993)), payload["smtp_host"], int(payload.get("smtp_port",587)), payload["username"], password_enc, int(bool(payload.get("imap_ssl",True))), payload.get("smtp_mode","starttls"), payload.get("folder","INBOX"), int(bool(payload.get("active", current["active"]))), mailbox_id))
    db.audit("mailbox_updated", actor=user["email"], mailbox_id=mailbox_id, name=payload["name"], password_changed=bool(payload.get("password")))
    return {"ok": True}


@app.post("/api/mailboxes/test")
def test_mailbox(payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_admin(session)
    current = db.row("SELECT * FROM mailboxes WHERE id=?", (int(payload["id"]),)) if payload.get("id") else None
    values = dict(current or {})
    values.update({k: v for k, v in payload.items() if v is not None and k != "password"})
    required = ["imap_host", "smtp_host", "username"]
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
    box = db.row("SELECT * FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    try: count = fetch_mailbox(box)
    except Exception as exc: raise HTTPException(502, f"Synchronisierung fehlgeschlagen: {exc}")
    db.audit("manual_sync", actor=user["email"], mailbox_id=mailbox_id, new_messages=count)
    return {"new_messages": count}


@app.get("/api/mailboxes/{mailbox_id}/folders")
def mailbox_folders(mailbox_id: int, session: str | None = Cookie(None)):
    require_user(session)
    box = db.row("SELECT * FROM mailboxes WHERE id=?", (mailbox_id,))
    if not box: raise HTTPException(404, "Postfach nicht gefunden")
    try: return list_folders(box)
    except Exception as exc: raise HTTPException(502, f"Ordner konnten nicht geladen werden: {exc}")


@app.delete("/api/mailboxes/{mailbox_id}")
def disable_mailbox(mailbox_id: int, session: str | None = Cookie(None)):
    user = require_admin(session)
    db.execute("UPDATE mailboxes SET active=0 WHERE id=?", (mailbox_id,))
    db.audit("mailbox_disabled", actor=user["email"], mailbox_id=mailbox_id)
    return {"ok": True}


@app.get("/api/users")
def users(session: str | None = Cookie(None)):
    require_user(session)
    return db.rows("SELECT id,email,name,role,active,created_at FROM users ORDER BY name")


@app.post("/api/users")
def add_user(payload: dict = Body(...), session: str | None = Cookie(None)):
    admin = require_admin(session)
    if not payload.get("email") or not payload.get("name") or len(str(payload.get("password", ""))) < 10: raise HTTPException(400, "Name, E-Mail und Passwort (mind. 10 Zeichen) erforderlich")
    try:
        user_id = db.execute("INSERT INTO users(email,name,role,password_hash,created_at) VALUES(?,?,?,?,?)", (payload["email"], payload["name"], payload.get("role","agent"), hash_password(payload["password"]), db.now_iso()))
    except Exception: raise HTTPException(409, "E-Mail bereits vorhanden")
    db.audit("user_created", actor=admin["email"], user_id=user_id, email=payload["email"])
    return {"id": user_id}


@app.get("/api/rules")
def rules(session: str | None = Cookie(None)):
    require_user(session)
    return db.rows("""SELECT r.*,b.name mailbox_name,u.name target_name,u.email user_email FROM rules r
      LEFT JOIN mailboxes b ON b.id=r.mailbox_id LEFT JOIN users u ON u.id=r.target_user_id ORDER BY r.priority,r.id""")


def validate_rule_condition(payload):
    if payload.get("field") not in {"from", "to", "subject", "body"}:
        raise HTTPException(400, "Ungültiges Regelfeld")
    if payload.get("operator") not in {"contains", "equals", "starts_with", "regex"}:
        raise HTTPException(400, "Ungültiger Regelvergleich")
    if not str(payload.get("value", "")):
        raise HTTPException(400, "Regelwert fehlt")


@app.post("/api/rules/preview")
def preview_rule(payload: dict = Body(...), session: str | None = Cookie(None)):
    """Evaluate one unsaved rule without performing an action or writing audit data."""
    require_user(session)
    validate_rule_condition(payload)
    mailbox_id = payload.get("mailbox_id") or None
    messages = db.rows("""SELECT m.id,m.mailbox_id,m.sender,m.recipients,m.subject,m.received_at,
      m.text_body,m.status,b.name mailbox_name FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
      WHERE (? IS NULL OR m.mailbox_id=?) ORDER BY m.received_at DESC LIMIT 2000""", (mailbox_id, mailbox_id))
    matches = [m for m in messages if rule_matches(payload, m)]
    samples = [{k: m[k] for k in ("id", "mailbox_id", "mailbox_name", "sender", "subject", "received_at", "status")} for m in matches[:100]]
    return {"tested": len(messages), "matched": len(matches), "unmatched": len(messages) - len(matches), "samples": samples}


@app.get("/api/rules/simulate")
def simulate_rules(mailbox_id: int | None = None, session: str | None = Cookie(None)):
    """Dry-run the complete active ruleset in production order without side effects."""
    require_user(session)
    messages = db.rows("""SELECT m.id,m.mailbox_id,m.sender,m.recipients,m.subject,m.received_at,
      m.text_body,m.status,b.name mailbox_name FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
      WHERE (? IS NULL OR m.mailbox_id=?) ORDER BY m.received_at DESC LIMIT 2000""", (mailbox_id, mailbox_id))
    ruleset = db.rows("""SELECT r.*,u.name target_name,u.email user_email FROM rules r
      LEFT JOIN users u ON u.id=r.target_user_id WHERE r.active=1 ORDER BY r.priority,r.id""")
    results, matched_messages, action_count = [], 0, 0
    for message in messages:
        actions = []
        for rule in ruleset:
            if rule["mailbox_id"] is not None and rule["mailbox_id"] != message["mailbox_id"]:
                continue
            if not rule_matches(rule, message):
                continue
            target = rule["target_folder"] if rule.get("action") == "move" else (rule["target_name"] or rule["target_email"] or rule["user_email"])
            actions.append({"rule_id": rule["id"], "rule_name": rule["name"], "priority": rule["priority"], "action": rule.get("action", "forward"), "target": target, "stops": bool(rule["stop_processing"])})
            action_count += 1
            if rule["stop_processing"]:
                break
        if actions:
            matched_messages += 1
            if len(results) < 200:
                results.append({"id": message["id"], "mailbox_name": message["mailbox_name"], "sender": message["sender"], "subject": message["subject"], "received_at": message["received_at"], "actions": actions})
    return {"tested": len(messages), "matched_messages": matched_messages, "unmatched_messages": len(messages) - matched_messages, "actions": action_count, "results": results}


@app.post("/api/rules")
def add_rule(payload: dict = Body(...), session: str | None = Cookie(None)):
    user = require_user(session)
    validate_rule_condition(payload)
    action = payload.get("action", "forward")
    if action not in {"forward", "move"}: raise HTTPException(400, "Ungültige Regelaktion")
    if action == "forward" and not payload.get("target_user_id") and not payload.get("target_email"): raise HTTPException(400, "Weiterleitung benötigt ein Ziel")
    if action == "move" and (not payload.get("mailbox_id") or not payload.get("target_folder")): raise HTTPException(400, "Verschieben benötigt Postfach und Zielordner")
    rule_id = db.execute("""INSERT INTO rules(name,mailbox_id,field,operator,value,action,target_user_id,target_email,target_folder,priority,active,stop_processing,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)""", (payload.get("name") or "Neue Regel", payload.get("mailbox_id") or None, payload["field"], payload["operator"], payload.get("value", ""), action, payload.get("target_user_id") or None, payload.get("target_email") or None, payload.get("target_folder") or None, int(payload.get("priority",100)), int(payload.get("stop_processing",1)), db.now_iso()))
    db.audit("rule_created", actor=user["email"], rule_id=rule_id, name=payload.get("name"))
    return {"id": rule_id}


@app.delete("/api/rules/{rule_id}")
def disable_rule(rule_id: int, session: str | None = Cookie(None)):
    user = require_user(session)
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
