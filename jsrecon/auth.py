"""Single-owner auth.

- Registration is open only until the first account exists; after that it is
  closed. Users log in with username+password (hashed in store.py); a session
  cookie maps to a username.
- An API bearer token authenticates the MCP server / programmatic clients. The
  token is persisted to DATA_DIR/token (auto-generated once), so no env var is
  needed; JSRECON_TOKEN still overrides. The bearer principal acts as the owner
  account automatically, so the LLM shares the human's workspace.

Put behind TLS for real remote exposure.
"""
from __future__ import annotations

import os
import secrets

COOKIE_NAME = "jsrecon_session"
OPERATOR = "*operator*"
# When left as OPERATOR, the bearer/MCP principal resolves dynamically to the
# owner account (store.first_user()); an explicit MCP_USER still overrides.
MCP_USER = OPERATOR


def _load_token() -> tuple[str, str]:
    """Return (token, source). Prefer env, else a persisted file, else make one."""
    env = os.environ.get("JSRECON_TOKEN")
    if env:
        return env, "env"
    from . import store
    store.init()
    path = os.path.join(store.DATA_DIR, "token")
    try:
        with open(path, encoding="utf-8") as fh:
            t = fh.read().strip()
        if t:
            return t, "file"
    except FileNotFoundError:
        pass
    t = secrets.token_urlsafe(24)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(t)
        os.chmod(path, 0o600)
    except Exception:
        pass
    return t, "generated"


TOKEN, _TOKEN_SOURCE = _load_token()

# session cookie token -> username (in-memory; single-process tool)
SESSIONS: dict[str, str] = {}


def mcp_user() -> str:
    """Username the bearer/MCP principal acts as: explicit override, else owner."""
    if MCP_USER != OPERATOR:
        return MCP_USER
    from . import store
    return store.first_user() or OPERATOR


def print_banner() -> None:
    from . import store
    owner = store.first_user()
    print("=" * 60)
    print("  jsrecon auth (single-owner)")
    print(f"  DATA DIR:  {store.DATA_DIR}")
    print(f"  API TOKEN: {TOKEN}  ({_TOKEN_SOURCE}; stored in {store.DATA_DIR}/token)")
    if owner:
        print(f"  OWNER:     {owner}  (registration is CLOSED)")
    else:
        print("  OWNER:     none yet - open the UI and register the first account")
    print("=" * 60)


def new_session(username: str) -> str:
    tok = secrets.token_urlsafe(24)
    SESSIONS[tok] = username
    return tok


def drop_session(tok: str) -> None:
    SESSIONS.pop(tok, None)


def session_user(request) -> str | None:
    return SESSIONS.get(request.cookies.get(COOKIE_NAME, ""))


def bearer_ok(request) -> bool:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return secrets.compare_digest(auth[7:].strip(), TOKEN)
    return False


def principal(request) -> str | None:
    """Return the acting username, OPERATOR for a valid bearer token, else None."""
    u = session_user(request)
    if u:
        return u
    if bearer_ok(request):
        return mcp_user()
    return None
