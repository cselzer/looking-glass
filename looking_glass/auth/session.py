"""Server-side GUI sessions under ~/.looking-glass/data/sessions/.

Tokens are 256-bit secrets stored as 0600 JSON files, not JWTs. The cookie
carries only the id; the server holds expiry, so a session can be revoked by
deleting the file. HttpOnly + SameSite=Lax; Secure on HTTPS. There is no
username: a valid session is the admin.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from ..utility import get_data_dir, load_json_cache, save_json_cache

COOKIE = "looking_glass_session"
TTL_S = 7 * 24 * 60 * 60
SLIDE_REMAINING = TTL_S / 2


def effective_scheme(connection: Optional[str] = None, forwarded: Optional[str] = None) -> str:
    """https if the socket or X-Forwarded-Proto is https; never downgrade https."""
    conn = str(connection or "").strip().lower()
    proto = str(forwarded or "").split(",")[0].strip().lower()
    if conn == "https" or proto == "https":
        return "https"
    return conn or "http"


def _dir() -> str:
    path = os.path.join(get_data_dir(), "sessions")
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _path(token: str) -> str:
    return os.path.join(_dir(), f"{token}.json")


def parse_token(header: Optional[str]) -> Optional[str]:
    if not header:
        return None
    for part in str(header).split(";"):
        item = part.strip()
        if not item:
            continue
        name, _, value = item.partition("=")
        if name.strip() == COOKIE:
            token = value.strip()
            if token and all(ch.isalnum() or ch in "-_" for ch in token):
                return token
            return None
    return None


def load(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    payload = load_json_cache(_path(token))
    if not isinstance(payload, dict):
        return None
    expires = float(payload.get("expires") or 0)
    if expires <= time.time():
        delete(token)
        return None
    remaining = expires - time.time()
    if remaining > SLIDE_REMAINING:
        return payload
    payload["expires"] = time.time() + TTL_S
    save_json_cache(_path(token), payload)
    try:
        os.chmod(_path(token), 0o600)
    except OSError:
        pass
    return payload


def user_from_cookie(header: Optional[str]) -> Optional[str]:
    token = parse_token(header)
    if not token:
        return None
    rec = load(token)
    if not rec:
        return None
    return "admin"


def create() -> str:
    token = secrets.token_hex(32)
    now = time.time()
    path = _path(token)
    if not save_json_cache(
        path,
        {"created": now, "expires": now + TTL_S},
    ):
        raise OSError("could not write session")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return token


def delete(token: str) -> None:
    if not token:
        return
    try:
        os.remove(_path(token))
    except OSError:
        pass


def clear_all() -> int:
    removed = 0
    try:
        names = os.listdir(_dir())
    except OSError:
        names = []
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            os.remove(os.path.join(_dir(), name))
            removed += 1
        except OSError:
            continue
    return removed


def cookie_header(
    token: str,
    *,
    scheme: Optional[str] = None,
    forwarded: Optional[str] = None,
    clear: bool = False,
) -> str:
    secure = " Secure;" if effective_scheme(scheme, forwarded) == "https" else ""
    if clear:
        return f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax;{secure} Max-Age=0"
    return f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax;{secure} Max-Age={int(TTL_S)}"


def set_cookie_headers(
    token: str,
    *,
    scheme: Optional[str] = None,
    forwarded: Optional[str] = None,
    clear: bool = False,
) -> List[Tuple[str, str]]:
    return [("Set-Cookie", cookie_header(token, scheme=scheme, forwarded=forwarded, clear=clear))]
