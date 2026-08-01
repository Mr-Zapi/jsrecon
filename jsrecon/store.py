"""Persistent, multi-user storage — no SQL (so no SQL injection), guarded by a
single lock with atomic file writes (so no read-modify-write races).

Layout under JSRECON_DATA (default ~/.jsrecon_data):
    users.json              {username: {salt, hash, created}}
    token                   the API bearer token (auto-generated once)
    projects/<username>.json   one saved project per user (overwritten on save)

Usernames are strictly validated (no path traversal into the projects dir).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time

DATA_DIR = os.environ.get("JSRECON_DATA", os.path.expanduser("~/.jsrecon_data"))
_PROJECTS = os.path.join(DATA_DIR, "projects")
_USERS = os.path.join(DATA_DIR, "users.json")

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")
_PBKDF_ROUNDS = 200_000

# One global lock serializes every read-modify-write, killing race conditions
# in a single-process server (uvicorn). File writes are atomic via os.replace.
_LOCK = threading.RLock()


def init() -> None:
    os.makedirs(_PROJECTS, exist_ok=True)
    if not os.path.exists(_USERS):
        _write_json(_USERS, {})


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _write_json(path: str, data: dict) -> None:
    tmp = f"{path}.{secrets.token_hex(6)}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)
    os.replace(tmp, path)  # atomic on POSIX


def valid_username(name: str) -> bool:
    return bool(USERNAME_RE.match(name or ""))


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF_ROUNDS).hex()


# ------------------------------- users -------------------------------

def user_count() -> int:
    with _LOCK:
        return len(_read_json(_USERS))


def first_user() -> str | None:
    """The earliest-registered username (the de-facto owner), or None."""
    with _LOCK:
        users = _read_json(_USERS)
    if not users:
        return None
    return min(users, key=lambda u: users[u].get("created", 0))


def registration_open() -> bool:
    """Open only until the first account exists (single-owner bootstrap)."""
    return user_count() == 0


def register(username: str, password: str) -> tuple[bool, str]:
    """Register the owner account. Allowed only while no users exist yet."""
    if not valid_username(username):
        return False, "invalid username (3-32 chars: a-z A-Z 0-9 _ -)"
    if len(password or "") < 6:
        return False, "password too short (min 6)"
    with _LOCK:
        users = _read_json(_USERS)
        if users:
            return False, "registration is closed (an account already exists)"
        salt = secrets.token_bytes(16)
        users[username] = {"salt": salt.hex(), "hash": _hash(password, salt),
                           "created": time.time()}
        _write_json(_USERS, users)
    return True, "ok"


def verify(username: str, password: str) -> bool:
    if not valid_username(username):
        return False
    with _LOCK:
        users = _read_json(_USERS)
        u = users.get(username)
    if not u:
        # constant-ish work to reduce user-enumeration timing signal
        _hash(password, b"0" * 16)
        return False
    salt = bytes.fromhex(u["salt"])
    return secrets.compare_digest(_hash(password, salt), u["hash"])


# ------------------------------ projects ------------------------------

def _project_path(username: str) -> str:
    if not valid_username(username):
        raise ValueError("invalid username")
    return os.path.join(_PROJECTS, f"{username}.json")


def save_project(username: str, data: dict) -> None:
    """Overwrite the user's single project atomically."""
    path = _project_path(username)
    payload = {"saved_at": time.time(), **data}
    with _LOCK:
        _write_json(path, payload)


def load_project(username: str) -> dict | None:
    path = _project_path(username)
    with _LOCK:
        if not os.path.exists(path):
            return None
        return _read_json(path)


def delete_project(username: str) -> bool:
    """Remove the user's saved project file. Returns True if a file was deleted."""
    path = _project_path(username)
    with _LOCK:
        if os.path.exists(path):
            os.remove(path)
            return True
    return False


def project_info(username: str) -> dict:
    path = _project_path(username)
    if not os.path.exists(path):
        return {"exists": False}
    d = _read_json(path)
    return {"exists": True, "saved_at": d.get("saved_at"),
            "endpoints": len(d.get("endpoints", [])),
            "findings": len(d.get("findings", []))}
