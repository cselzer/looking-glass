"""Recent wall decisions and challenge outcomes.

In-memory deques for a single process. When a lists path is configured, JSON
lines are also appended beside wall.json so other processes can tail the same
rings.
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

MAX = 500
SKIP_GET = frozenset({"/status", "/wall", "/wall/traffic", "/wall/challenge"})
PUZZLE_EVENTS = frozenset({"issued", "solved", "failed"})
TRAFFIC_FILE = "wall.traffic"
CHALLENGE_FILE = "wall.challenge"

_lock = threading.Lock()
_ring: Deque[Dict[str, Any]] = deque(maxlen=MAX)
_challenges: Deque[Dict[str, Any]] = deque(maxlen=MAX)
_persist_dir: Optional[str] = None
_lists_file: Optional[str] = None


def configure(lists_path: Optional[str]) -> None:
    """Persist rings next to wall.json. None disables files (in-memory tests)."""
    global _persist_dir, _lists_file
    if lists_path:
        _lists_file = os.path.abspath(lists_path)
        _persist_dir = os.path.dirname(_lists_file) or "."
    else:
        _lists_file = None
        _persist_dir = None


def reset() -> None:
    with _lock:
        _ring.clear()
        _challenges.clear()


def skip_path(method: str, path: str) -> bool:
    """True for operator heartbeats that should not fill the traffic ring."""
    verb = (method or "GET").upper()
    text = str(path or "/")
    if "?" in text:
        text = text.split("?", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    text = text.rstrip("/") or "/"
    return verb == "GET" and text in SKIP_GET


def _normalize_path(path: str) -> str:
    text = str(path or "/")
    if "?" in text:
        text = text.split("?", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    return text or "/"


def _ring_path(name: str) -> Optional[str]:
    if not _persist_dir:
        return None
    return os.path.join(_persist_dir, name)


def _append_jsonl(path: str, row: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, payload)
        size = os.fstat(fd).st_size
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, size)
        if raw.count(b"\n") > MAX * 2:
            lines = [ln for ln in raw.decode("utf-8").splitlines() if ln.strip()]
            keep = ("\n".join(lines[-MAX:]) + "\n").encode("utf-8")
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, keep)
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return []
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        size = os.fstat(fd).st_size
        raw = os.read(fd, size) if size else b""
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)
    for line in raw.decode("utf-8", "replace").splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows[-MAX:]


def _persist(name: str, row: Dict[str, Any]) -> None:
    path = _ring_path(name)
    if not path:
        return
    try:
        _append_jsonl(path, row)
    except Exception:
        pass


def record(
    *,
    id: str,
    peer: Optional[str],
    method: str,
    path: str,
    decision: str,
    status: int,
    ms: float,
    reason: Optional[str] = None,
    prefix: Optional[str] = None,
) -> Dict[str, Any]:
    if skip_path(method, path):
        return {}
    row: Dict[str, Any] = {
        "id": str(id),
        "ts": time.time(),
        "peer": peer,
        "method": (method or "GET").upper(),
        "path": _normalize_path(path),
        "decision": str(decision or ""),
        "status": int(status),
        "ms": round(float(ms), 1),
        "reason": reason or None,
    }
    if prefix:
        row["prefix"] = str(prefix)
    with _lock:
        _ring.append(row)
    _persist(TRAFFIC_FILE, row)
    return row


def record_challenge(
    *,
    id: str,
    peer: Optional[str],
    event: str,
    reason: Optional[str] = None,
    bits: Optional[int] = None,
    prefix: Optional[str] = None,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    kind = str(event or "").strip().lower()
    if kind not in PUZZLE_EVENTS:
        kind = "issued"
    row: Dict[str, Any] = {
        "id": str(id),
        "ts": time.time(),
        "peer": peer,
        "event": kind,
        "reason": reason or None,
        "path": _normalize_path(path or "/"),
    }
    if bits is not None:
        row["bits"] = int(bits)
    if prefix:
        row["prefix"] = str(prefix)
    with _lock:
        _challenges.append(row)
    _persist(CHALLENGE_FILE, row)
    try:
        from .lists import append_action

        append_action(
            {
                "event": kind,
                "kind": "puzzle",
                "value": peer,
                "peer": peer,
                "reason": reason,
                "bits": bits,
                "prefix": prefix,
                "url": row["path"],
                "source": "wall",
                "id": row["id"],
            },
            _lists_file,
        )
    except Exception:
        pass
    return row


def _slice_rows(rows: List[Dict[str, Any]], after: Optional[str], limit: int) -> List[Dict[str, Any]]:
    cap = max(1, min(int(limit or 200), MAX))
    if after:
        idx = None
        for i, row in enumerate(rows):
            if row.get("id") == after:
                idx = i
                break
        if idx is not None:
            rows = rows[idx + 1 :]
    return rows[-cap:]


def _tail_ring(ring: Deque[Dict[str, Any]], after: Optional[str], limit: int) -> List[Dict[str, Any]]:
    with _lock:
        rows = list(ring)
    return _slice_rows(rows, after, limit)


def tail(after: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    path = _ring_path(TRAFFIC_FILE)
    if path and os.path.isfile(path):
        return _slice_rows(_read_jsonl(path), after, limit)
    return _tail_ring(_ring, after, limit)


def tail_challenge(after: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    path = _ring_path(CHALLENGE_FILE)
    if path and os.path.isfile(path):
        return _slice_rows(_read_jsonl(path), after, limit)
    return _tail_ring(_challenges, after, limit)
