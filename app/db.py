import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(os.getenv("APP_DATA_DIR", "data"))
DB_PATH = DATA_DIR / "mailsorter.sqlite3"
_lock = threading.RLock()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        con = sqlite3.connect(DB_PATH, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        try:
            yield con
            con.commit()
        finally:
            con.close()


def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'agent', password_hash TEXT NOT NULL,
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mailboxes (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
          imap_host TEXT NOT NULL, imap_port INTEGER NOT NULL DEFAULT 993,
          smtp_host TEXT NOT NULL, smtp_port INTEGER NOT NULL DEFAULT 587,
          username TEXT NOT NULL, imap_username TEXT, smtp_username TEXT,
          imap_auth_mode TEXT NOT NULL DEFAULT 'auto', password_enc TEXT NOT NULL,
          imap_ssl INTEGER NOT NULL DEFAULT 1, smtp_mode TEXT NOT NULL DEFAULT 'starttls',
          folder TEXT NOT NULL DEFAULT 'INBOX', active INTEGER NOT NULL DEFAULT 1,
          auto_sync INTEGER NOT NULL DEFAULT 0, auto_process INTEGER NOT NULL DEFAULT 0,
          last_sync_at TEXT, last_error TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY, mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
          uid TEXT NOT NULL, message_id TEXT, sender TEXT NOT NULL, recipients TEXT NOT NULL,
          subject TEXT NOT NULL, received_at TEXT, text_body TEXT NOT NULL DEFAULT '',
          html_body TEXT NOT NULL DEFAULT '', parser_version INTEGER NOT NULL DEFAULT 3,
          status TEXT NOT NULL DEFAULT 'new',
          assigned_to INTEGER REFERENCES users(id), matched_rule_id INTEGER,
          created_at TEXT NOT NULL, UNIQUE(mailbox_id, uid)
        );
        CREATE TABLE IF NOT EXISTS attachments (
          id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
          filename TEXT NOT NULL, content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
          size INTEGER NOT NULL DEFAULT 0, stored INTEGER NOT NULL DEFAULT 1,
          content BLOB, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rules (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, mailbox_id INTEGER REFERENCES mailboxes(id) ON DELETE CASCADE,
          field TEXT NOT NULL, operator TEXT NOT NULL, value TEXT NOT NULL,
          value_logic TEXT NOT NULL DEFAULT 'any',
          action TEXT NOT NULL DEFAULT 'forward', target_user_id INTEGER REFERENCES users(id), target_email TEXT,
          target_folder TEXT, post_forward_folder TEXT,
          priority INTEGER NOT NULL DEFAULT 100, active INTEGER NOT NULL DEFAULT 1,
          stop_processing INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS mailbox_permissions (
          mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          granted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
          created_at TEXT NOT NULL,
          PRIMARY KEY(mailbox_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS mailbox_contacts (
          id INTEGER PRIMARY KEY,
          mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          email TEXT NOT NULL,
          color TEXT NOT NULL DEFAULT '#315cf3',
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          UNIQUE(mailbox_id,email)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY, message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
          mailbox_id INTEGER REFERENCES mailboxes(id) ON DELETE SET NULL,
          actor TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status, received_at DESC);
        CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
        CREATE INDEX IF NOT EXISTS idx_rules_order ON rules(active, priority, id);
        CREATE INDEX IF NOT EXISTS idx_mailbox_permissions_user ON mailbox_permissions(user_id, mailbox_id);
        CREATE INDEX IF NOT EXISTS idx_mailbox_contacts_mailbox ON mailbox_contacts(mailbox_id, active, name);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
        """)
        # Additive migrations for installations created by earlier versions.
        rule_columns = {r[1] for r in db.execute("PRAGMA table_info(rules)")}
        if "action" not in rule_columns:
            db.execute("ALTER TABLE rules ADD COLUMN action TEXT NOT NULL DEFAULT 'forward'")
        if "target_folder" not in rule_columns:
            db.execute("ALTER TABLE rules ADD COLUMN target_folder TEXT")
        if "post_forward_folder" not in rule_columns:
            db.execute("ALTER TABLE rules ADD COLUMN post_forward_folder TEXT")
        if "value_logic" not in rule_columns:
            db.execute("ALTER TABLE rules ADD COLUMN value_logic TEXT NOT NULL DEFAULT 'any'")
        mailbox_columns = {r[1] for r in db.execute("PRAGMA table_info(mailboxes)")}
        if "imap_username" not in mailbox_columns:
            db.execute("ALTER TABLE mailboxes ADD COLUMN imap_username TEXT")
        if "smtp_username" not in mailbox_columns:
            db.execute("ALTER TABLE mailboxes ADD COLUMN smtp_username TEXT")
        if "imap_auth_mode" not in mailbox_columns:
            db.execute("ALTER TABLE mailboxes ADD COLUMN imap_auth_mode TEXT NOT NULL DEFAULT 'auto'")
        if "auto_sync" not in mailbox_columns:
            db.execute("ALTER TABLE mailboxes ADD COLUMN auto_sync INTEGER NOT NULL DEFAULT 0")
        if "auto_process" not in mailbox_columns:
            db.execute("ALTER TABLE mailboxes ADD COLUMN auto_process INTEGER NOT NULL DEFAULT 0")
            db.execute("UPDATE mailboxes SET auto_process=auto_sync")
        message_columns = {r[1] for r in db.execute("PRAGMA table_info(messages)")}
        if "parser_version" not in message_columns:
            # Existing messages are refreshed from Exchange on their next mailbox sync.
            db.execute("ALTER TABLE messages ADD COLUMN parser_version INTEGER NOT NULL DEFAULT 1")
        db.execute("UPDATE mailboxes SET imap_username=COALESCE(imap_username,username),smtp_username=COALESCE(smtp_username,username)")
        db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('poll_interval_seconds', ?)", (os.getenv("POLL_INTERVAL_SECONDS", "60"),))


def rows(sql, args=()):
    with connect() as db:
        return [dict(r) for r in db.execute(sql, args).fetchall()]


def row(sql, args=()):
    with connect() as db:
        found = db.execute(sql, args).fetchone()
        return dict(found) if found else None


def execute(sql, args=()):
    with connect() as db:
        cur = db.execute(sql, args)
        return cur.lastrowid


def audit(action, actor="system", message_id=None, mailbox_id=None, **details):
    execute(
        "INSERT INTO audit_log(message_id,mailbox_id,actor,action,details,created_at) VALUES(?,?,?,?,?,?)",
        (message_id, mailbox_id, actor, action, json.dumps(details, ensure_ascii=False), now_iso()),
    )


def get_setting(key, default=None):
    found = row("SELECT value FROM settings WHERE key=?", (key,))
    return found["value"] if found else default


def set_setting(key, value):
    execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def purge_mailbox(mailbox_id, actor):
    """Permanently remove one local mailbox and its dependent data, preserving an audit record."""
    with connect() as con:
        mailbox = con.execute("SELECT id,name,email,active FROM mailboxes WHERE id=?", (mailbox_id,)).fetchone()
        if not mailbox:
            return None
        if mailbox["active"]:
            raise ValueError("Postfach muss vor dem Löschen deaktiviert werden")
        message_count = con.execute("SELECT count(*) FROM messages WHERE mailbox_id=?", (mailbox_id,)).fetchone()[0]
        attachment_count = con.execute("""SELECT count(*) FROM attachments a JOIN messages m ON m.id=a.message_id
          WHERE m.mailbox_id=?""", (mailbox_id,)).fetchone()[0]
        rule_count = con.execute("SELECT count(*) FROM rules WHERE mailbox_id=?", (mailbox_id,)).fetchone()[0]
        contact_count = con.execute("SELECT count(*) FROM mailbox_contacts WHERE mailbox_id=?", (mailbox_id,)).fetchone()[0]
        details = {"name": mailbox["name"], "email": mailbox["email"], "messages_deleted": message_count,
                   "attachments_deleted": attachment_count, "rules_deleted": rule_count, "contacts_deleted": contact_count}
        con.execute(
            "INSERT INTO audit_log(mailbox_id,actor,action,details,created_at) VALUES(?,?,?,?,?)",
            (mailbox_id, actor, "mailbox_deleted", json.dumps(details, ensure_ascii=False), now_iso()),
        )
        con.execute("DELETE FROM mailboxes WHERE id=?", (mailbox_id,))
        return details


def prune_mailbox_messages(mailbox_id, present_uids, actor="sync"):
    """Remove local messages that no longer exist in the monitored Exchange folder."""
    present_uids = {str(uid) for uid in present_uids}
    with connect() as con:
        if present_uids:
            placeholders = ",".join("?" for _ in present_uids)
            sql = f"SELECT id,uid,subject,sender FROM messages WHERE mailbox_id=? AND uid NOT IN ({placeholders})"
            removed = [dict(r) for r in con.execute(sql, (mailbox_id, *present_uids)).fetchall()]
        else:
            removed = [dict(r) for r in con.execute("SELECT id,uid,subject,sender FROM messages WHERE mailbox_id=?", (mailbox_id,)).fetchall()]
        for message in removed:
            con.execute(
                "INSERT INTO audit_log(message_id,mailbox_id,actor,action,details,created_at) VALUES(?,?,?,?,?,?)",
                (
                    message["id"], mailbox_id, actor, "message_removed_from_mailbox",
                    json.dumps({"uid": message["uid"], "subject": message["subject"], "sender": message["sender"]}, ensure_ascii=False),
                    now_iso(),
                ),
            )
        if removed:
            con.executemany("DELETE FROM messages WHERE id=?", [(message["id"],) for message in removed])
        return len(removed)
