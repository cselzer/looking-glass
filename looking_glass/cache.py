"""Shared on-disk lookup cache.

Feature caches (RDAP, BGP, RBL, …) live under ~/.looking-glass/data/cache/<type>/.
TTL and whether the web GUI is shown come from ~/.looking-glass/config.json.
"""

from __future__ import annotations

import os
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from .utility import get_cache_path, load_json_cache, save_json_cache
from . import config as app_config

NAMESPACES = ("rdap", "bgp")
CACHE_ROOT = "cache"


def root_dir() -> str:
    path = get_cache_path(CACHE_ROOT)
    os.makedirs(path, exist_ok=True)
    return path


def layout_dir(name: str) -> str:
    """Return ~/.looking-glass/data/cache/<name>/, moving a legacy data/<name>/ folder if present."""
    dest = os.path.join(root_dir(), name)
    legacy = get_cache_path(name)
    dest_abs = os.path.abspath(dest)
    legacy_abs = os.path.abspath(legacy)
    if dest_abs != legacy_abs and not os.path.isdir(dest_abs) and os.path.isdir(legacy_abs):
        os.makedirs(os.path.dirname(dest_abs), exist_ok=True)
        try:
            os.rename(legacy_abs, dest_abs)
        except OSError:
            pass
    os.makedirs(dest, exist_ok=True)
    return dest


def config_path() -> str:
    return app_config.path()


def load_config() -> Dict[str, Any]:
    cache = app_config.load()["cache"]
    return {"ttl_days": int(cache["ttl_days"]), "gui": bool(cache["gui"])}


def ttl_days() -> int:
    return int(load_config()["ttl_days"])


def gui_enabled() -> bool:
    return bool(load_config()["gui"])


def _namespace_dir(namespace: str) -> str:
    if namespace not in NAMESPACES:
        raise ValueError(f"unknown cache {namespace}")
    path = layout_dir(namespace)
    os.makedirs(path, exist_ok=True)
    return path


def _filename(key: str) -> str:
    return urllib.parse.quote(str(key), safe="") + ".json"


def entry_path(namespace: str, key: str) -> str:
    return os.path.join(_namespace_dir(namespace), _filename(key))


def _read(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None
    payload = load_json_cache(path)
    if not isinstance(payload, dict):
        return None
    return payload


def get(namespace: str, key: str) -> Optional[Any]:
    """Return cached data when it is still within TTL."""
    payload = _read(entry_path(namespace, key))
    if payload is None:
        return None
    days = ttl_days()
    if days <= 0:
        return None
    cached_at = int(payload.get("_cached_at") or 0)
    if cached_at <= 0 or int(time.time()) - cached_at > days * 86400:
        return None
    return payload.get("data")


def get_any(namespace: str, key: str) -> Optional[Any]:
    """Return cached data even when stale."""
    payload = _read(entry_path(namespace, key))
    if payload is None:
        return None
    return payload.get("data")


def put(namespace: str, key: str, data: Any) -> None:
    save_json_cache(entry_path(namespace, key), {"_cached_at": int(time.time()), "data": data})


def _file_row(namespace: str, directory: str, name: str, now: int) -> Optional[Dict[str, Any]]:
    if not name.endswith(".json"):
        return None
    path = os.path.join(directory, name)
    try:
        size = int(os.path.getsize(path))
        mtime = int(os.path.getmtime(path))
        payload = _read(path) or {}
        cached_at = int(payload.get("_cached_at") or mtime or 0)
    except OSError:
        return None
    stem = urllib.parse.unquote(name[: -len(".json")])
    kind, sep, query = stem.partition("_")
    if namespace == "rdap" and sep:
        row_kind, row_query = kind, query
    else:
        row_kind, row_query = namespace, stem
    return {
        "file": name,
        "namespace": namespace,
        "kind": row_kind or None,
        "query": row_query or stem,
        "bytes": size,
        "cached_at": cached_at,
        "age_hours": round(max(0, now - cached_at) / 3600.0, 1) if cached_at else None,
    }


def _namespace_stats(namespace: str) -> Dict[str, Any]:
    directory = _namespace_dir(namespace)
    now = int(time.time())
    files: List[Dict[str, Any]] = []
    total = 0
    try:
        names = os.listdir(directory)
    except OSError:
        names = []
    for name in sorted(names):
        row = _file_row(namespace, directory, name, now)
        if row is None:
            continue
        files.append(row)
        total += int(row["bytes"])
    return {
        "directory": directory,
        "ttl_days": ttl_days(),
        "count": len(files),
        "bytes": total,
        "files": files,
    }


def stats(namespace: Optional[str] = None) -> Dict[str, Any]:
    cfg = load_config()
    if namespace:
        out = _namespace_stats(namespace)
        out["gui"] = cfg["gui"]
        out["config"] = config_path()
        return out
    namespaces: Dict[str, Any] = {}
    files: List[Dict[str, Any]] = []
    total = 0
    count = 0
    for name in NAMESPACES:
        bucket = _namespace_stats(name)
        namespaces[name] = bucket
        files.extend(bucket["files"])
        total += int(bucket["bytes"])
        count += int(bucket["count"])
    files.sort(key=lambda row: (row.get("namespace") or "", row.get("query") or ""))
    return {
        "directory": root_dir(),
        "ttl_days": cfg["ttl_days"],
        "gui": cfg["gui"],
        "config": config_path(),
        "count": count,
        "bytes": total,
        "namespaces": namespaces,
        "files": files,
    }


def _clear_dir(namespace: str, name: Optional[str] = None) -> Dict[str, Any]:
    directory = _namespace_dir(namespace)
    removed: List[str] = []
    if name in (None, "", "*", "all"):
        try:
            names = os.listdir(directory)
        except OSError:
            names = []
        for filename in names:
            if not filename.endswith(".json"):
                continue
            path = os.path.join(directory, filename)
            try:
                os.remove(path)
                removed.append(filename)
            except OSError:
                continue
        out = _namespace_stats(namespace)
        out["ok"] = True
        out["removed"] = removed
        return out
    safe = os.path.basename(str(name).strip())
    if not safe.endswith(".json"):
        safe = f"{safe}.json"
    path = os.path.join(directory, safe)
    if not os.path.isfile(path):
        return {"ok": False, "error": "cache file not found", "file": safe, "namespace": namespace}
    os.remove(path)
    out = _namespace_stats(namespace)
    out["ok"] = True
    out["removed"] = [safe]
    return out


def clear(namespace: Optional[str] = None, name: Optional[str] = None) -> Dict[str, Any]:
    if namespace:
        return _clear_dir(namespace, name)
    if name not in (None, "", "*", "all"):
        return {"ok": False, "error": "namespace required to clear one file"}
    removed: List[str] = []
    for ns in NAMESPACES:
        result = _clear_dir(ns, None)
        for filename in result.get("removed") or []:
            removed.append(f"{ns}/{filename}")
    out = stats()
    out["ok"] = True
    out["removed"] = removed
    return out
