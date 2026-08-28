"""Admin allowlist in ~/.looking-glass/config.json (`auth.users`).

Empty list: the first successful non-root PAM login is appended.
Root and uid 0 are never allowed.
"""

from __future__ import annotations

import pwd
import re
from typing import List

from .. import config as app_config

_NAME = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$")


def normalize(name: str) -> str:
    return str(name or "").strip()


def is_forbidden(name: str) -> bool:
    raw = normalize(name)
    if not raw or raw.lower() == "root":
        return True
    try:
        return pwd.getpwnam(raw).pw_uid == 0
    except KeyError:
        return False


def valid_name(name: str) -> bool:
    raw = normalize(name)
    return bool(raw and _NAME.fullmatch(raw) and not is_forbidden(raw))


def list_users() -> List[str]:
    users = app_config.load().get("auth", {}).get("users") or []
    return [str(name) for name in users if isinstance(name, str)]


def _write(users: List[str]) -> List[str]:
    cfg = app_config.load()
    seen: List[str] = []
    for name in users:
        raw = normalize(name)
        if not valid_name(raw) or raw in seen:
            continue
        seen.append(raw)
    cfg["auth"] = {"users": seen}
    app_config.save(cfg)
    return seen


def add_user(name: str) -> List[str]:
    raw = normalize(name)
    if not valid_name(raw):
        raise ValueError("invalid or forbidden user")
    with app_config.file_lock():
        users = list_users()
        if raw not in users:
            users.append(raw)
        return _write(users)


def remove_user(name: str) -> List[str]:
    raw = normalize(name)
    with app_config.file_lock():
        users = [item for item in list_users() if item != raw]
        return _write(users)


def admit(name: str) -> bool:
    """After PAM succeeds: bootstrap if empty, else require allowlist membership."""
    raw = normalize(name)
    if not valid_name(raw):
        return False
    with app_config.file_lock():
        users = list_users()
        if not users:
            _write([raw])
            return True
        return raw in users
