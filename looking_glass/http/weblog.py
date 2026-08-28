"""GUI access / error / login logs and per-page stats under ~/.looking-glass/data/logs/."""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

from ..utility import atomic_write, get_data_dir

ACCESS_NAME = "access.jsonl"
ERROR_NAME = "error.jsonl"
LOGIN_NAME = "login.jsonl"
STATS_NAME = "stats.json"
MAX_JSONL = 8 * 1024 * 1024
TAIL_BYTES = 64 * 1024
STEP = 900
DAY_SPAN = 24 * 60 * 60
WEEK_SPAN = 7 * 24 * 60 * 60

JSONL_KINDS = ("access", "error", "login")
FILE_KINDS = ("lookup", "serve-out", "serve-err", "wall", "challenge", "build")
PUZZLE_EVENTS = frozenset({"issued", "solved", "failed"})
SKIP_ACCESS = {"status", "static"}
INTEL_KEYS = (
    "asn",
    "org_name",
    "prefix",
    "country",
    "country_name",
    "flag",
    "flag_url",
    "flag_html",
)

_LOOKUP_PREFIXES = {
    "dns",
    "dnstrace",
    "dnssec",
    "apex",
    "rdap",
    "whois",
    "bgp",
    "reputation",
    "tls",
    "http",
    "mail",
    "ptr",
    "ping",
    "traceroute",
    "mtr",
    "tcptraceroute",
    "tcp",
    "pmtu",
}

_lock = threading.Lock()
_stats: Optional[Dict[str, Any]] = None
_intel_cache: Dict[str, Optional[Dict[str, Any]]] = {}
_INTEL_CACHE_MAX = 256

_KIND_FILES = {
    "access": ACCESS_NAME,
    "error": ERROR_NAME,
    "login": LOGIN_NAME,
}


def _dir() -> str:
    path = os.path.join(get_data_dir(), "logs")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        pass
    return path


def _path(name: str) -> str:
    return os.path.join(_dir(), name)


def _token(path: str) -> str:
    text = unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    return text.rstrip("/")


def classify_request(path: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Return (page family, lookup kind, query)."""
    token = _token(path)
    if not token:
        return "index", None, None
    if token in {"login", "logout", "session", "docs", "status", "config"}:
        return token, None, None
    if token == "static" or token.startswith("static/"):
        return "static", None, None
    if token == "logs" or token.startswith("logs/"):
        return "logs", None, None
    if token == "cache" or token.startswith("cache/"):
        return "cache", None, None
    if token == "wall" or token.startswith("wall/"):
        return "wall", None, None
    if token.startswith("_wall/"):
        return "wall", None, None
    if token == "history" or token.startswith("history/"):
        return "history", None, None
    if token.startswith("serve/"):
        return "serve", None, None
    first, _, rest = token.partition("/")
    if first in _LOOKUP_PREFIXES:
        return first, first, rest or None
    try:
        from ..intel_server.pipeline import classify_query

        kind, value = classify_query(token)
        return kind, kind, value
    except (ValueError, TypeError):
        return "other", "other", token


def skip_access(path: str) -> bool:
    token = _token(path)
    if token in SKIP_ACCESS or token.startswith("static/"):
        return True
    if token == "logs" or token.startswith("logs/"):
        return True
    if token == "wall/traffic" or token == "wall/challenge":
        return True
    return False


def compact_intel(value: Optional[str]) -> Optional[Dict[str, Any]]:
    """Local ASN/country/org/flag for an IP, ASN, or country. Never raises."""
    text = str(value or "").strip()
    if not text:
        return None
    cached = _intel_cache.get(text, _SENTINEL)
    if cached is not _SENTINEL:
        return cached
    try:
        out = _lookup_intel(text)
    except Exception:
        out = None
    if len(_intel_cache) >= _INTEL_CACHE_MAX:
        _intel_cache.clear()
    _intel_cache[text] = out
    return out


_SENTINEL = object()


def _lookup_intel(text: str) -> Optional[Dict[str, Any]]:
    from ..intel_server.pipeline import classify_query, lookup_ip
    from ..intel import asn_org, flags

    kind, token = classify_query(text)
    blob: Dict[str, Any] = {}
    if kind == "ip":
        payload = lookup_ip(token, load=False)
        blob = dict(payload.get("result") or {})
    elif kind == "asn":
        blob["asn"] = int(token)
        org = asn_org.find_org(blob["asn"])
        if org and org.get("name"):
            blob["org_name"] = org["name"]
    elif kind == "country":
        blob["country"] = token
        blob.update(flags.lookup_fields(token))
    else:
        return None
    out = {key: blob[key] for key in INTEL_KEYS if blob.get(key) not in (None, "", False)}
    return out or None


def _row_intel(*values: Optional[str]) -> Optional[Dict[str, Any]]:
    for value in values:
        intel = compact_intel(value)
        if intel:
            return intel
    return None


def _trim_jsonl_fd(fd: int) -> None:
    keep = MAX_JSONL // 2
    size = os.fstat(fd).st_size
    if size <= MAX_JSONL:
        return
    os.lseek(fd, max(0, size - keep), os.SEEK_SET)
    leftover = os.read(fd, size)
    nl = leftover.find(b"\n")
    data = leftover[nl + 1 :] if nl >= 0 else leftover
    os.lseek(fd, 0, os.SEEK_SET)
    os.ftruncate(fd, 0)
    os.write(fd, data)


def _append_jsonl(name: str, row: Dict[str, Any]) -> None:
    path = _path(name)
    payload = (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.lseek(fd, 0, os.SEEK_END)
            os.write(fd, payload)
            _trim_jsonl_fd(fd)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)
    except OSError:
        pass


def _empty_stats() -> Dict[str, Any]:
    return {"step": STEP, "series": {}}


def _merge_bucket(dest: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    dest["hits"] = int(dest.get("hits") or 0) + int(row.get("hits") or 0)
    dest["errors"] = int(dest.get("errors") or 0) + int(row.get("errors") or 0)
    dest["bytes"] = int(dest.get("bytes") or 0) + int(row.get("bytes") or 0)
    dest["ms_sum"] = float(dest.get("ms_sum") or 0) + float(row.get("ms_sum") or 0)
    dest["ms_n"] = int(dest.get("ms_n") or 0) + int(row.get("ms_n") or 0)
    return dest


def _rebucket(
    pages: Any,
    old_step: int,
    *,
    now: float,
    span: int,
) -> Dict[str, Dict[str, Any]]:
    cutoff = int(now) - span
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(pages, dict):
        return out
    for page, buckets in pages.items():
        if not isinstance(buckets, dict):
            continue
        merged: Dict[str, Any] = {}
        for key, row in buckets.items():
            if not isinstance(row, dict):
                continue
            try:
                stamp = int(key) * old_step
            except (TypeError, ValueError):
                continue
            if stamp < cutoff:
                continue
            bucket = str(stamp // STEP)
            dest = merged.get(bucket)
            if dest is None:
                dest = {"hits": 0, "errors": 0, "bytes": 0, "ms_sum": 0.0, "ms_n": 0}
                merged[bucket] = dest
            _merge_bucket(dest, row)
        if merged:
            out[str(page)] = merged
    return out


def _normalize_stats(payload: Any, now: float) -> Dict[str, Any]:
    if (
        isinstance(payload, dict)
        and payload.get("step") == STEP
        and isinstance(payload.get("series"), dict)
    ):
        store = {"step": STEP, "series": payload["series"]}
        _prune_series(store["series"], STEP, WEEK_SPAN, now)
        return store
    series: Dict[str, Dict[str, Any]] = {}
    if isinstance(payload, dict):
        for key, old_step in (("day", 300), ("week", 3600), ("series", int(payload.get("step") or STEP))):
            extra = _rebucket(payload.get(key) or {}, old_step, now=now, span=WEEK_SPAN)
            for page, buckets in extra.items():
                dest = series.setdefault(page, {})
                for bucket, row in buckets.items():
                    existing = dest.get(bucket)
                    if existing is None:
                        dest[bucket] = dict(row)
                    else:
                        _merge_bucket(existing, row)
    store = {"step": STEP, "series": series}
    _prune_series(store["series"], STEP, WEEK_SPAN, now)
    return store


def _load_stats() -> Dict[str, Any]:
    global _stats
    if _stats is not None:
        return _stats
    payload = None
    try:
        with open(_path(STATS_NAME), encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError, TypeError):
        payload = None
    _stats = _normalize_stats(payload, time.time())
    return _stats


def _save_stats() -> None:
    if _stats is None:
        return
    try:
        atomic_write(_path(STATS_NAME), json.dumps(_stats, ensure_ascii=False))
    except OSError:
        pass


def reset() -> None:
    """Drop in-memory stats. Tests use this after patching the data dir."""
    global _stats
    with _lock:
        _stats = None
        _intel_cache.clear()


def _prune_series(series: Dict[str, Dict[str, Any]], step: int, span: int, now: float) -> None:
    cutoff = int(now) - span
    for page in list(series.keys()):
        buckets = series.get(page) or {}
        keep = {k: v for k, v in buckets.items() if int(k) * step >= cutoff}
        if keep:
            series[page] = keep
        else:
            series.pop(page, None)


def _bump(page: str, status: int, nbytes: int, ms: float, now: Optional[float] = None) -> None:
    current = now if now is not None else time.time()
    with _lock:
        store = _load_stats()
        series = store.setdefault("series", {})
        _prune_series(series, STEP, WEEK_SPAN, current)
        pages = series.setdefault(page, {})
        bucket = str(int(current) // STEP)
        row = pages.get(bucket)
        if not isinstance(row, dict):
            row = {"hits": 0, "errors": 0, "bytes": 0, "ms_sum": 0.0, "ms_n": 0}
            pages[bucket] = row
        row["hits"] = int(row.get("hits") or 0) + 1
        if int(status) >= 500:
            row["errors"] = int(row.get("errors") or 0) + 1
        row["bytes"] = int(row.get("bytes") or 0) + max(0, int(nbytes))
        row["ms_sum"] = float(row.get("ms_sum") or 0) + max(0.0, float(ms))
        row["ms_n"] = int(row.get("ms_n") or 0) + 1
        _save_stats()


def write_access(
    *,
    method: str,
    path: str,
    status: int,
    peer: Optional[str] = None,
    user: Optional[str] = None,
    ms: float = 0,
    nbytes: int = 0,
    kind: Optional[str] = None,
    query: Optional[str] = None,
    page: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> None:
    page_name, look_kind, look_query = classify_request(path)
    kind = kind or look_kind
    query = query or look_query
    page = page or page_name
    if skip_access(path):
        return
    _bump(page, status, nbytes, ms)
    row = {
        "ts": time.time(),
        "method": (method or "GET").upper(),
        "path": path or "/",
        "status": int(status),
        "ms": round(float(ms), 1),
        "bytes": int(nbytes),
        "peer": peer,
        "user": user,
        "page": page,
        "kind": kind,
        "query": query,
        "intel": _row_intel(query, peer),
    }
    if correlation_id:
        row["id"] = correlation_id
    _append_jsonl(ACCESS_NAME, row)


def write_error(
    *,
    path: str,
    status: int,
    error: str,
    peer: Optional[str] = None,
    user: Optional[str] = None,
    kind: Optional[str] = None,
    query: Optional[str] = None,
) -> None:
    page, look_kind, look_query = classify_request(path)
    _append_jsonl(
        ERROR_NAME,
        {
            "ts": time.time(),
            "path": path or "/",
            "status": int(status),
            "error": str(error or "")[:2000],
            "peer": peer,
            "user": user,
            "page": page,
            "kind": kind or look_kind,
            "query": query or look_query,
            "intel": _row_intel(query or look_query, peer),
        },
    )


def write_login(
    *,
    ok: bool,
    username: str,
    peer: Optional[str] = None,
    reason: str = "",
) -> None:
    _append_jsonl(
        LOGIN_NAME,
        {
            "ts": time.time(),
            "ok": bool(ok),
            "user": str(username or ""),
            "peer": peer,
            "reason": str(reason or ("ok" if ok else "failed")),
            "intel": _row_intel(peer),
        },
    )


def _tail_bytes(path: str, max_bytes: int = TAIL_BYTES) -> str:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return ""
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        size = os.fstat(fd).st_size
        if size > max_bytes:
            os.lseek(fd, size - max_bytes, os.SEEK_SET)
            leftover = os.read(fd, max_bytes)
            nl = leftover.find(b"\n")
            data = leftover[nl + 1 :] if nl >= 0 else leftover
        else:
            data = os.read(fd, size) if size else b""
        return data.decode("utf-8", "replace")
    except OSError:
        return ""
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _parse_jsonl(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _file_source(kind: str) -> Optional[str]:
    name = "lookup" if kind == "serve-out" else kind
    if name in {"lookup", "serve-err"}:
        from ..intel_server import app as lookup_mod

        info = lookup_mod.status()
        key = "out_log" if name == "lookup" else "err_log"
        return str(info.get(key) or "") or None
    if name in {"wall", "challenge"}:
        return os.path.join(get_data_dir(), "wall.log")
    if name == "build":
        return os.path.join(get_data_dir(), "build.raw.log")
    return None


def _enrich_row(row: Dict[str, Any]) -> Dict[str, Any]:
    if row.get("intel"):
        return row
    intel = _row_intel(
        row.get("query") if isinstance(row.get("query"), str) else None,
        row.get("peer") if isinstance(row.get("peer"), str) else None,
        row.get("value") if isinstance(row.get("value"), str) else None,
    )
    if not intel:
        return row
    out = dict(row)
    out["intel"] = intel
    return out


def tail(
    kind: str,
    *,
    limit: int = 200,
    ok: Optional[bool] = None,
) -> Dict[str, Any]:
    name = str(kind or "access").strip()
    if name == "serve-out":
        name = "lookup"
    cap = max(1, min(int(limit or 200), 500))
    if name in JSONL_KINDS:
        path = _path(_KIND_FILES[name])
        rows = [_enrich_row(row) for row in _parse_jsonl(_tail_bytes(path))]
        if name == "login" and ok is not None:
            want = bool(ok)
            rows = [row for row in rows if bool(row.get("ok")) is want]
        return {"ok": True, "kind": name, "rows": rows[-cap:], "path": path}
    if name in FILE_KINDS:
        path = _file_source(name) or ""
        rows = [_enrich_row(row) for row in _parse_jsonl(_tail_bytes(path) if path else "")]
        if name == "challenge":
            rows = [
                row
                for row in rows
                if str(row.get("kind") or "") == "puzzle"
                or str(row.get("event") or "") in PUZZLE_EVENTS
            ]
            if ok is not None:
                want = "solved" if ok else "failed"
                rows = [row for row in rows if str(row.get("event") or "") == want]
        elif name == "wall":
            rows = [
                row
                for row in rows
                if str(row.get("kind") or "") != "puzzle"
                and str(row.get("event") or "") not in PUZZLE_EVENTS
            ]
        return {"ok": True, "kind": name, "rows": rows[-cap:], "path": path}
    return {"ok": False, "error": "unknown kind"}


def _sparse_window(
    pages: Dict[str, Any],
    start: float,
    end: float,
) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for page, buckets in (pages or {}).items():
        if not isinstance(buckets, dict):
            continue
        series: List[Dict[str, Any]] = []
        for key, row in buckets.items():
            if not isinstance(row, dict):
                continue
            try:
                stamp = int(key) * STEP
            except (TypeError, ValueError):
                continue
            if stamp < start or stamp > end:
                continue
            n = int(row.get("ms_n") or 0)
            ms = (float(row.get("ms_sum") or 0) / n) if n else 0.0
            series.append(
                {
                    "t": stamp,
                    "hits": int(row.get("hits") or 0),
                    "errors": int(row.get("errors") or 0),
                    "bytes": int(row.get("bytes") or 0),
                    "ms": round(ms, 1),
                }
            )
        series.sort(key=lambda item: item["t"])
        if series:
            out[str(page)] = series
    return out


def stats_payload() -> Dict[str, Any]:
    now = time.time()
    with _lock:
        store = _load_stats()
        series = store.get("series") or {}
        day = _sparse_window(series, now - DAY_SPAN, now)
        week = _sparse_window(series, now - WEEK_SPAN, now)
    totals: Dict[str, Dict[str, int]] = {}
    for page, rows in day.items():
        hits = sum(int(row.get("hits") or 0) for row in rows)
        errors = sum(int(row.get("errors") or 0) for row in rows)
        totals[page] = {"hits": hits, "errors": errors}
    return {"ok": True, "day": day, "week": week, "totals": totals, "step": STEP}


def record_response(
    *,
    method: str,
    path: str,
    status: int,
    body: bytes,
    peer: Optional[str] = None,
    user: Optional[str] = None,
    ms: float = 0,
    error: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> None:
    page, kind, query = classify_request(path)
    nbytes = len(body or b"")
    write_access(
        method=method,
        path=path,
        status=status,
        peer=peer,
        user=user,
        ms=ms,
        nbytes=nbytes,
        kind=kind,
        query=query,
        page=page,
        correlation_id=correlation_id,
    )
    if int(status) >= 500 or error:
        write_error(
            path=path,
            status=status,
            error=error or f"HTTP {status}",
            peer=peer,
            user=user,
            kind=kind,
            query=query,
        )
