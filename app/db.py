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
          username TEXT NOT NULL, imap_username TEXT, smtp_username TEXT, password_enc TEXT NOT NULL,
          imap_ssl INTEGER NOT NULL DEFAULT 1, smtp_mode TEXT NOT NULL DEFAULT 'starttls',
          folder TEXT NOT NULL DEFAULT 'INBOX', active INTEGER NOT NULL DEFAULT 1,
          last_sync_at TEXT, last_error TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY, mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
          uid TEXT NOT NULL, message_id TEXT, sender TEXT NOT NULL, recipients TEXT NOT NULL,
          subject TEXT NOT NULL, received_at TEXT, text_body TEXT NOT NULL DEFAULT '',
          html_body TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'new',
          assigned_to INTEGER REFERENCES users(id), matched_rule_id INTEGER,
          created_at TEXT NOT NULL, UNIQUE(mailbox_id, uid)
        );
        CREATE TABLE IF NOT EXISTS rules (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, mailbox_id INTEGER REFERENCES mailboxes(id) ON DELETE CASCADE,
          field TEXT NOT NULL, operator TEXT NOT NULL, value TEXT NOT NULL,
          action TEXT NOT NULL DEFAULT 'forward', target_user_id INTEGER REFERENCES users(id), target_email TEXT,
          target_folder TEXT,
          priority INTEGER NOT NULL DEFAULT 100, active INTEGER NOT NULL DEFAULT 1,
          stop_processing INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
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
        CREATE INDEX IF NOT EXISTS idx_rules_order ON rules(active, priority, id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
        """)
        # Additive migrations for installations created by earlier versions.
        rule_columns = {r[1] for r in db.execute("PRAGMA table_info(rules)")}
        if "action" not in rule_columns:
            db.execute("ALTER TABLE rules ADD COLUMN action TEXT NOT NULL DEFAULT 'forward'")
        if "target_folder" not in rule_columns:
            db.execute("ALTER TABLE rules ADD COLUMN target_folder TEXT")
        mailbox_columns = {r[1] for r in db.execute("PRAGMA table_info(mailboxes)")}
        if "imap_username" not in mailbox_columns:
            db.execute("ALTER TABLE mailboxes ADD COLUMN imap_username TEXT")
        if "smtp_username" not in mailbox_columns:
            db.execute("ALTER TABLE mailboxes ADD COLUMN smtp_username TEXT")
        db.execute("UPDATE mailboxes SET imap_username=COALESCE(imap_username,username),smtp_username=COALESCE(smtp_username,username)")


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
