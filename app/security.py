import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet


DEFAULT_SESSION_DAYS = 30


def _secret():
    value = os.getenv("APP_SECRET", "")
    if len(value) < 24:
        raise RuntimeError("APP_SECRET muss mindestens 24 Zeichen lang sein")
    return value.encode()


def fernet():
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(_secret()).digest()))


def encrypt(value):
    return fernet().encrypt(value.encode()).decode()


def decrypt(value):
    return fernet().decrypt(value.encode()).decode()


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
    return f"{salt}${digest}"


def verify_password(password, stored):
    try:
        salt, expected = stored.split("$", 1)
        return hmac.compare_digest(hash_password(password, salt), stored)
    except ValueError:
        return False


def session_max_age_seconds():
    try:
        days = int(os.getenv("SESSION_MAX_AGE_DAYS", str(DEFAULT_SESSION_DAYS)))
    except (TypeError, ValueError):
        days = DEFAULT_SESSION_DAYS
    return max(1, days) * 24 * 60 * 60


def new_session():
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode()).hexdigest(), (datetime.now(timezone.utc) + timedelta(seconds=session_max_age_seconds())).isoformat()


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()
