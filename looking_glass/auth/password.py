"""Single admin password. Unset hash means login is disabled, not open."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Optional

from . import store

_N = 2**14
_R = 8
_P = 1
_DKLEN = 32


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * ((4 - len(text) % 4) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_secret(secret: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        str(secret).encode("utf-8"),
        salt=salt,
        n=_N,
        r=_R,
        p=_P,
        dklen=_DKLEN,
    )
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def _check(secret: str, stored: str) -> bool:
    parts = str(stored or "").split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = _unb64(parts[4])
        expected = _unb64(parts[5])
    except (TypeError, ValueError):
        return False
    digest = hashlib.scrypt(
        str(secret).encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=len(expected) or _DKLEN,
    )
    return hmac.compare_digest(digest, expected)


def is_set() -> bool:
    return bool(str(store.load().get("password_hash") or "").strip())


def set_password(secret: str) -> None:
    text = str(secret or "")
    if not text:
        raise ValueError("password required")
    with store.file_lock():
        data = store.load()
        data["password_hash"] = hash_secret(text)
        store.save(data)


def clear() -> None:
    with store.file_lock():
        data = store.load()
        data["password_hash"] = ""
        store.save(data)


def verify(secret: str) -> bool:
    text = str(secret or "")
    if not text:
        return False
    stored = str(store.load().get("password_hash") or "").strip()
    if not stored:
        return False
    return _check(text, stored)


def status() -> dict:
    return {"ok": True, "set": is_set()}
