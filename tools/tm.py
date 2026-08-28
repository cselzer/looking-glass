"""Sidecar translation memory: DST + '.tm.json'."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from looking_glass.utility import atomic_write

TM_VERSION = 1


def en_sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def tm_path_for(dst: str | Path) -> Path:
    return Path(str(dst) + ".tm.json")


def load_tm(path: str | Path) -> Dict[str, Any]:
    dest = Path(path)
    if not dest.is_file():
        return {"version": TM_VERSION, "provider": None, "model": None, "keys": {}}
    try:
        data = json.loads(dest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": TM_VERSION, "provider": None, "model": None, "keys": {}}
    if not isinstance(data, dict):
        return {"version": TM_VERSION, "provider": None, "model": None, "keys": {}}
    keys = data.get("keys")
    if not isinstance(keys, dict):
        keys = {}
    return {
        "version": int(data.get("version") or TM_VERSION),
        "provider": data.get("provider"),
        "model": data.get("model"),
        "keys": keys,
    }


def save_tm(path: str | Path, tm: Mapping[str, Any]) -> Path:
    dest = Path(path)
    payload = {
        "version": int(tm.get("version") or TM_VERSION),
        "provider": tm.get("provider"),
        "model": tm.get("model"),
        "keys": tm.get("keys") or {},
    }
    atomic_write(str(dest), json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    return dest


def unique_hashes(messages: Mapping[str, Mapping[str, str]]) -> int:
    return len({en_sha256(row.get("en") or "") for row in messages.values()})


def classify_keys(
    src: Mapping[str, Mapping[str, str]],
    dst: Mapping[str, Mapping[str, str]],
    tm: Mapping[str, Any],
) -> Dict[str, List[str]]:
    """new / changed / unchanged / missing vs TM and DST."""
    tm_keys = tm.get("keys") if isinstance(tm.get("keys"), dict) else {}
    new: List[str] = []
    changed: List[str] = []
    unchanged: List[str] = []
    missing: List[str] = []
    for key, row in src.items():
        en = row.get("en") or ""
        digest = en_sha256(en)
        record = tm_keys.get(key) if isinstance(tm_keys.get(key), dict) else None
        if record is None:
            new.append(key)
        elif str(record.get("en_sha256") or "") != digest:
            changed.append(key)
        else:
            unchanged.append(key)
        got = dst.get(key) or {}
        text = str(got.get("text") or "").strip()
        if key not in dst or not text:
            missing.append(key)
    return {
        "new": new,
        "changed": changed,
        "unchanged": unchanged,
        "missing": missing,
    }


def keys_to_send(
    classified: Mapping[str, Iterable[str]],
    *,
    only_changed: bool,
) -> List[str]:
    buckets = ("new", "changed", "unchanged") if not only_changed else ("new", "changed")
    send: List[str] = []
    for bucket in buckets:
        for key in classified.get(bucket) or []:
            if key not in send:
                send.append(key)
    return send


def group_by_en_hash(
    src: Mapping[str, Mapping[str, str]], keys: Iterable[str]
) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    for key in keys:
        row = src.get(key) or {}
        digest = en_sha256(row.get("en") or "")
        groups.setdefault(digest, []).append(key)
    return groups


def put_tm_key(
    tm: Dict[str, Any],
    key: str,
    *,
    en: str,
    text: str,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> None:
    if provider:
        tm["provider"] = provider
    if model:
        tm["model"] = model
    keys = tm.setdefault("keys", {})
    keys[key] = {"en_sha256": en_sha256(en), "text": text}
