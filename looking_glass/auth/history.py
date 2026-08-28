"""Replayable lookup history under ~/.looking-glass/data/history/."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from ..utility import get_data_dir, load_json_cache, save_json_cache

CAP = 500
CHANGES_CAP = 200
SNAPSHOT_KINDS = frozenset(
    {"tcp", "tls", "http", "ping", "traceroute", "mtr", "tcptraceroute", "pmtu"}
)
_PORTED = frozenset({"tcp", "tls", "tcptraceroute"})


def _root() -> str:
    path = os.path.join(get_data_dir(), "history")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        pass
    return path


def snapshot_cap() -> int:
    try:
        from ..config import get as config_get

        raw = config_get("history.snapshots")
    except Exception:
        return -1
    if isinstance(raw, bool):
        return -1
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return -1
    return value if value >= -1 else -1


def _safe_id(ident: str) -> Optional[str]:
    safe = os.path.basename(str(ident or "").strip())
    if not safe or safe != str(ident or "").strip():
        return None
    if safe.endswith(".json"):
        safe = safe[:-5]
    return safe or None


def _iter_files() -> List[str]:
    root = _root()
    found: List[str] = []
    try:
        entries = list(os.scandir(root))
    except OSError:
        return found
    for entry in entries:
        if entry.is_file() and entry.name.endswith(".json"):
            found.append(entry.path)
            continue
        if not entry.is_dir() or entry.name == "targets":
            continue
        try:
            nested = os.listdir(entry.path)
        except OSError:
            continue
        for name in nested:
            if name.endswith(".json"):
                found.append(os.path.join(entry.path, name))
    return found


def _trim() -> None:
    if snapshot_cap() != 0:
        return
    files = _iter_files()
    if len(files) <= CAP:
        return
    files.sort(key=lambda path: os.path.basename(path))
    for path in files[: len(files) - CAP]:
        try:
            os.remove(path)
        except OSError:
            continue


def snapshot_query(kind: str, query: str, payload: Dict[str, Any]) -> str:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    host = str(result.get("host") or result.get("target") or query or "").strip()
    port = result.get("port")
    if kind in _PORTED and port not in (None, ""):
        try:
            return f"{host}:{int(port)}"
        except (TypeError, ValueError):
            pass
    return str(query or host or "")


def _target_path(kind: str, query: str) -> str:
    digest = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
    return os.path.join(_root(), "targets", kind, f"{digest}.json")


def _load_index(kind: str, query: str) -> Dict[str, Any]:
    data = load_json_cache(_target_path(kind, query))
    if not isinstance(data, dict):
        return {"query": query, "ids": []}
    ids = [str(item) for item in (data.get("ids") or []) if item]
    return {"query": str(data.get("query") or query), "ids": ids}


def _save_index(kind: str, query: str, ids: List[str]) -> None:
    dest = _target_path(kind, query)
    try:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
    except OSError:
        return
    save_json_cache(dest, {"query": query, "ids": ids})


def _record_path(ident: str) -> str:
    return os.path.join(_root(), f"{ident}.json")


def _load_payload(ident: str) -> Optional[Dict[str, Any]]:
    data = load_json_cache(_record_path(ident))
    if not isinstance(data, dict):
        return None
    payload = data.get("payload")
    return payload if isinstance(payload, dict) else None


def _hop_hosts(result: Dict[str, Any]) -> Tuple[str, ...]:
    hops = result.get("hops") if isinstance(result.get("hops"), list) else []
    out: List[str] = []
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        host = hop.get("host")
        if host:
            out.append(str(host))
            continue
        hosts = hop.get("hosts") or []
        if isinstance(hosts, list) and hosts:
            out.append(",".join(str(item) for item in hosts if item))
        else:
            out.append("")
    return tuple(out)


def _dest_asn(result: Dict[str, Any]) -> Any:
    if result.get("asn") is not None:
        return result.get("asn")
    hops = result.get("hops") if isinstance(result.get("hops"), list) else []
    for hop in reversed(hops):
        if isinstance(hop, dict) and hop.get("asn") is not None:
            return hop.get("asn")
    return None


def _last_rtt(result: Dict[str, Any]) -> Any:
    if result.get("rtt_ms") is not None:
        return result.get("rtt_ms")
    if result.get("avg_ms") is not None:
        return result.get("avg_ms")
    hops = result.get("hops") if isinstance(result.get("hops"), list) else []
    if hops and isinstance(hops[-1], dict):
        last = hops[-1]
        for key in ("rtt_ms", "last_ms", "avg_ms"):
            if last.get(key) is not None:
                return last.get(key)
    return None


def _rtt_delta(prev: Any, current: Any) -> Optional[float]:
    try:
        return round(float(current) - float(prev), 1)
    except (TypeError, ValueError):
        return None


def _http_path(result: Dict[str, Any]) -> Tuple[Any, ...]:
    chain = result.get("chain") if isinstance(result.get("chain"), list) else []
    urls = tuple(str(hop.get("url") or hop.get("status") or "") for hop in chain if isinstance(hop, dict))
    if urls:
        return urls
    return (result.get("final_url") or result.get("status"),)


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return str(value)


def _walk_changes(
    previous: Any,
    current: Any,
    path: str,
    out: List[Dict[str, Any]],
    cap: int,
    stopped: List[bool],
) -> None:
    if stopped[0] or len(out) >= cap:
        stopped[0] = True
        return
    if isinstance(previous, dict) and isinstance(current, dict):
        keys: List[Any] = []
        seen = set()
        for key in list(previous.keys()) + list(current.keys()):
            if key in seen:
                continue
            seen.add(key)
            keys.append(key)
        for key in keys:
            if len(out) >= cap:
                stopped[0] = True
                return
            child = f"{path}.{key}" if path else str(key)
            if key not in previous:
                out.append({"op": "add", "path": child, "previous": None, "current": _jsonable(current[key])})
            elif key not in current:
                out.append({"op": "remove", "path": child, "previous": _jsonable(previous[key]), "current": None})
            else:
                _walk_changes(previous[key], current[key], child, out, cap, stopped)
        return
    if isinstance(previous, list) and isinstance(current, list):
        n = max(len(previous), len(current))
        for i in range(n):
            if len(out) >= cap:
                stopped[0] = True
                return
            child = f"{path}[{i}]"
            if i >= len(previous):
                out.append({"op": "add", "path": child, "previous": None, "current": _jsonable(current[i])})
            elif i >= len(current):
                out.append({"op": "remove", "path": child, "previous": _jsonable(previous[i]), "current": None})
            else:
                _walk_changes(previous[i], current[i], child, out, cap, stopped)
        return
    if previous != current:
        out.append(
            {
                "op": "change",
                "path": path,
                "previous": _jsonable(previous),
                "current": _jsonable(current),
            }
        )


def result_changes(
    previous: Dict[str, Any],
    current: Dict[str, Any],
    cap: int = CHANGES_CAP,
) -> Tuple[List[Dict[str, Any]], bool]:
    out: List[Dict[str, Any]] = []
    stopped = [False]
    prev_ok = previous.get("ok") if "ok" in previous else None
    curr_ok = current.get("ok") if "ok" in current else None
    if prev_ok != curr_ok:
        out.append({"op": "change", "path": "ok", "previous": prev_ok, "current": curr_ok})
    prev_r = previous.get("result") if isinstance(previous.get("result"), dict) else {}
    curr_r = current.get("result") if isinstance(current.get("result"), dict) else {}
    _walk_changes(prev_r, curr_r, "result", out, cap, stopped)
    return out, bool(stopped[0])


def compute_diff(kind: str, previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    prev_r = previous.get("result") if isinstance(previous.get("result"), dict) else {}
    new_r = current.get("result") if isinstance(current.get("result"), dict) else {}
    prev_ok = bool(previous.get("ok") if "ok" in previous else prev_r.get("ok"))
    new_ok = bool(current.get("ok") if "ok" in current else new_r.get("ok"))
    diff: Dict[str, Any] = {
        "changed": False,
        "cert_changed": False,
        "path_changed": False,
        "peer_changed": False,
        "ok_changed": False,
        "rtt_ms_delta": None,
    }
    if kind == "tcp":
        diff["ok_changed"] = prev_ok != new_ok or prev_r.get("status") != new_r.get("status")
        diff["peer_changed"] = (prev_r.get("peer") or None) != (new_r.get("peer") or None)
        diff["rtt_ms_delta"] = _rtt_delta(prev_r.get("rtt_ms"), new_r.get("rtt_ms"))
        diff["changed"] = bool(diff["ok_changed"] or diff["peer_changed"] or diff["rtt_ms_delta"])
    elif kind == "tls":
        prev_leaf = prev_r.get("leaf") if isinstance(prev_r.get("leaf"), dict) else {}
        new_leaf = new_r.get("leaf") if isinstance(new_r.get("leaf"), dict) else {}
        diff["cert_changed"] = (prev_leaf.get("sha256") or None) != (new_leaf.get("sha256") or None)
        diff["ok_changed"] = (
            bool(prev_r.get("verified")) != bool(new_r.get("verified"))
            or prev_r.get("protocol") != new_r.get("protocol")
            or prev_r.get("hostname_matches") != new_r.get("hostname_matches")
        )
        diff["peer_changed"] = (prev_r.get("ip") or None) != (new_r.get("ip") or None)
        diff["changed"] = bool(diff["cert_changed"] or diff["ok_changed"] or diff["peer_changed"])
    elif kind == "http":
        diff["ok_changed"] = prev_ok != new_ok or prev_r.get("status") != new_r.get("status")
        diff["peer_changed"] = (prev_r.get("final_url") or None) != (new_r.get("final_url") or None)
        diff["path_changed"] = _http_path(prev_r) != _http_path(new_r)
        diff["rtt_ms_delta"] = _rtt_delta(prev_r.get("ttfb_ms"), new_r.get("ttfb_ms"))
        diff["changed"] = bool(diff["ok_changed"] or diff["peer_changed"] or diff["path_changed"])
    elif kind == "pmtu":
        diff["ok_changed"] = prev_ok != new_ok
        diff["path_changed"] = prev_r.get("path_mtu") != new_r.get("path_mtu")
        diff["changed"] = bool(diff["ok_changed"] or diff["path_changed"])
    elif kind == "ping":
        diff["ok_changed"] = prev_ok != new_ok
        diff["peer_changed"] = (prev_r.get("ip") or None) != (new_r.get("ip") or None)
        diff["rtt_ms_delta"] = _rtt_delta(prev_r.get("avg_ms"), new_r.get("avg_ms"))
        diff["changed"] = bool(diff["ok_changed"] or diff["peer_changed"])
    elif kind in SNAPSHOT_KINDS:
        diff["ok_changed"] = prev_ok != new_ok
        diff["path_changed"] = _hop_hosts(prev_r) != _hop_hosts(new_r) or _dest_asn(prev_r) != _dest_asn(new_r)
        diff["peer_changed"] = (prev_r.get("ip") or None) != (new_r.get("ip") or None)
        diff["rtt_ms_delta"] = _rtt_delta(_last_rtt(prev_r), _last_rtt(new_r))
        diff["changed"] = bool(diff["ok_changed"] or diff["path_changed"] or diff["peer_changed"])
    else:
        diff["ok_changed"] = prev_ok != new_ok
    changes, truncated = result_changes(previous, current)
    diff["changes"] = changes
    if truncated:
        diff["truncated"] = True
    if kind not in SNAPSHOT_KINDS:
        diff["changed"] = bool(diff["ok_changed"] or changes)
    return diff


def _attach_diff(kind: str, query: str, payload: Dict[str, Any]) -> None:
    cap = snapshot_cap()
    if cap == 0:
        return
    target = snapshot_query(kind, query, payload)
    if not target:
        return
    prev_ids = [item for item in (_load_index(kind, target).get("ids") or []) if item]
    if not prev_ids:
        return
    previous = _load_payload(prev_ids[0])
    if previous is None:
        return
    payload["prev_id"] = prev_ids[0]
    payload["diff"] = compute_diff(kind, previous, payload)


def _commit_snapshot(kind: str, query: str, ident: str, payload: Dict[str, Any]) -> None:
    cap = snapshot_cap()
    if cap == 0:
        return
    target = snapshot_query(kind, query, payload)
    if not target:
        return
    prev_ids = [item for item in (_load_index(kind, target).get("ids") or []) if item and item != ident]
    ids = [ident] + prev_ids
    dropped: List[str] = []
    if cap > 0:
        dropped = ids[cap:]
        ids = ids[:cap]
    _save_index(kind, target, ids)
    for old in dropped:
        try:
            os.remove(_record_path(old))
        except OSError:
            continue


def append(
    user: str,
    *,
    path: str,
    kind: str,
    query: str,
    payload: Dict[str, Any],
    visitor: str = "",
) -> Optional[str]:
    if not isinstance(payload, dict):
        return None
    try:
        from ..observe import attach_observation

        attach_observation(payload)
    except Exception:
        pass
    now = time.time()
    ident = f"{int(now * 1000):013d}-{secrets.token_hex(16)}"
    who = str(visitor or payload.get("visitor") or "")
    intel = None
    try:
        from ..http.weblog import compact_intel

        intel = compact_intel(who)
    except Exception:
        intel = None
    try:
        _attach_diff(str(kind or ""), str(query or ""), payload)
    except OSError:
        pass
    payload["id"] = ident
    payload["history"] = f"/history/{ident}"
    record = {
        "id": ident,
        "ts": now,
        "user": str(user or ""),
        "visitor": who,
        "intel": intel,
        "path": str(path or "/"),
        "kind": str(kind or ""),
        "query": str(query or ""),
        "payload": payload,
    }
    try:
        save_json_cache(os.path.join(_root(), f"{ident}.json"), record)
        _commit_snapshot(str(kind or ""), str(query or ""), ident, payload)
        _trim()
    except OSError:
        payload.pop("id", None)
        payload.pop("history", None)
        return None
    return ident


def _row(data: Dict[str, Any], fallback_id: str) -> Dict[str, Any]:
    payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
    visitor = str(data.get("visitor") or payload.get("visitor") or "")
    intel = data.get("intel") if isinstance(data.get("intel"), dict) else None
    if not intel and visitor:
        try:
            from ..http.weblog import compact_intel

            intel = compact_intel(visitor)
        except Exception:
            intel = None
    return {
        "id": data.get("id") or fallback_id,
        "ts": data.get("ts"),
        "kind": data.get("kind") or "",
        "query": data.get("query") or "",
        "path": data.get("path") or "",
        "user": data.get("user") or "",
        "visitor": visitor,
        "intel": intel,
    }


def list_entries(user: str = "") -> List[Dict[str, Any]]:
    files = _iter_files()
    files.sort(key=lambda path: os.path.basename(path), reverse=True)
    rows: List[Dict[str, Any]] = []
    for path in files[:CAP]:
        data = load_json_cache(path)
        if not isinstance(data, dict):
            continue
        name = os.path.basename(path)
        rows.append(_row(data, name[:-5] if name.endswith(".json") else name))
    rows.sort(key=lambda row: (float(row.get("ts") or 0), str(row.get("id") or "")), reverse=True)
    return rows


def get_entry(user: str, ident: str) -> Optional[Dict[str, Any]]:
    safe = _safe_id(ident)
    if not safe:
        return None
    data = load_json_cache(os.path.join(_root(), f"{safe}.json"))
    if isinstance(data, dict):
        return _hydrate(data, safe)
    if user:
        data = load_json_cache(os.path.join(_root(), str(user), f"{safe}.json"))
        if isinstance(data, dict):
            return _hydrate(data, safe)
    try:
        names = os.listdir(_root())
    except OSError:
        names = []
    for name in names:
        if name == "targets":
            continue
        sub = os.path.join(_root(), name)
        if not os.path.isdir(sub):
            continue
        data = load_json_cache(os.path.join(sub, f"{safe}.json"))
        if isinstance(data, dict):
            return _hydrate(data, safe)
    return None


def _hydrate(data: Dict[str, Any], fallback_id: str) -> Dict[str, Any]:
    out = dict(data)
    out.update(_row(data, fallback_id))
    if isinstance(data.get("payload"), dict):
        out["payload"] = data["payload"]
    return out
