"""Admin secrets under ~/.looking-glass/data/auth.json (0600)."""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from copy import deepcopy
from typing import Any, Dict, Iterator, List

from ..utility import atomic_write, get_data_dir

_EMPTY: Dict[str, Any] = {"password_hash": "", "keys": []}


def path() -> str:
    return os.path.join(get_data_dir(), "auth.json")


def lock_path() -> str:
    return path() + ".lock"


@contextmanager
def file_lock() -> Iterator[None]:
    dest = lock_path()
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    fd = os.open(dest, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _normalize(raw: Any) -> Dict[str, Any]:
    data = raw if isinstance(raw, dict) else {}
    hash_text = str(data.get("password_hash") or "")
    keys_out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in data.get("keys") or []:
        if not isinstance(item, dict):
            continue
        key_id = str(item.get("id") or "").strip()
        name = str(item.get("name") or "").strip() or key_id
        digest = str(item.get("hash") or "").strip().lower()
        if not key_id or not digest or key_id in seen:
            continue
        seen.add(key_id)
        try:
            created = float(item.get("created") or 0)
        except (TypeError, ValueError):
            created = 0.0
        keys_out.append({"id": key_id, "name": name, "hash": digest, "created": created})
    return {"password_hash": hash_text, "keys": keys_out}


def load() -> Dict[str, Any]:
    dest = path()
    try:
        with open(dest, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeError):
        return deepcopy(_EMPTY)
    return _normalize(raw)


def save(payload: Dict[str, Any]) -> str:
    dest = path()
    cleaned = _normalize(payload)
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    atomic_write(dest, json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n")
    try:
        os.chmod(dest, 0o600)
    except OSError:
        pass
    return dest
