"""Hashed API keys. The secret is shown once at create."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from typing import Any, Dict, List, Optional

from . import store

_PREFIX = "lg_"
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _digest(secret: str) -> str:
    return hashlib.sha256(str(secret).encode("utf-8")).hexdigest()


def _public(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(item.get("id") or ""),
        "name": str(item.get("name") or ""),
        "created": float(item.get("created") or 0),
    }


def list_keys() -> List[Dict[str, Any]]:
    return [_public(item) for item in store.load().get("keys") or []]


def create(name: str = "") -> Dict[str, Any]:
    label = str(name or "").strip() or "key"
    if not _NAME.fullmatch(label):
        raise ValueError("key name must be 1–64 letters, digits, dot, underscore, or hyphen")
    secret = _PREFIX + secrets.token_urlsafe(32)
    rec = {
        "id": secrets.token_hex(4),
        "name": label,
        "hash": _digest(secret),
        "created": time.time(),
    }
    with store.file_lock():
        data = store.load()
        keys = list(data.get("keys") or [])
        while any(str(item.get("id")) == rec["id"] for item in keys):
            rec["id"] = secrets.token_hex(4)
        keys.append(rec)
        data["keys"] = keys
        store.save(data)
    out = _public(rec)
    out["secret"] = secret
    return out


def revoke(key_id: str) -> bool:
    want = str(key_id or "").strip()
    if not want:
        return False
    with store.file_lock():
        data = store.load()
        keys = list(data.get("keys") or [])
        kept = [item for item in keys if str(item.get("id") or "") != want]
        if len(kept) == len(keys):
            return False
        data["keys"] = kept
        store.save(data)
        return True


def verify(secret: str) -> Optional[str]:
    text = str(secret or "").strip()
    if not text:
        return None
    digest = _digest(text)
    for item in store.load().get("keys") or []:
        stored = str(item.get("hash") or "").strip().lower()
        if stored and hmac.compare_digest(digest, stored):
            return str(item.get("name") or item.get("id") or "key")
    return None


def verify_authorization(header: Optional[str]) -> Optional[str]:
    raw = str(header or "").strip()
    if len(raw) < 8 or raw[:7].lower() != "bearer ":
        return None
    return verify(raw[7:].strip())
