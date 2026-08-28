"""Allow/block lists stored in ~/.looking-glass/data/wall.json.

IPv4 and IPv6 CIDRs are canonicalized with ipaddress. Country codes are
ISO 3166-1 alpha-2. Mutations append JSON lines to wall.log next to the lists.
"""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple, Union

from ..intel.flags import canonical_country
from ..utility import atomic_write, get_data_dir

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

LIST_FILE = "wall.json"
LOG_FILE = "wall.log"

DEFAULT_LISTS: Dict[str, List[Any]] = {
    "allow_ips": [],
    "block_ips": [],
    "challenge_ips": [],
    "block_asns": [],
    "challenge_asns": [],
    "block_countries": [],
}

_IP_KEYS = ("allow_ips", "block_ips", "challenge_ips")
_ASN_KEYS = ("block_asns", "challenge_asns")
_COUNTRY_KEYS = ("block_countries",)

_KIND_KEYS = {
    "ip": _IP_KEYS,
    "asn": _ASN_KEYS,
    "country": _COUNTRY_KEYS,
}

_ACTION_KEY = {
    ("allow", "ip"): "allow_ips",
    ("block", "ip"): "block_ips",
    ("challenge", "ip"): "challenge_ips",
    ("block", "asn"): "block_asns",
    ("challenge", "asn"): "challenge_asns",
    ("block", "country"): "block_countries",
}


def default_lists_path() -> str:
    return os.path.join(get_data_dir(), LIST_FILE)


def actions_path(lists_path: Optional[str] = None) -> str:
    target = lists_path if lists_path is not None else default_lists_path()
    directory = os.path.dirname(target) or "."
    return os.path.join(directory, LOG_FILE)


def _lock_path(lists_path: Optional[str] = None) -> str:
    target = lists_path if lists_path is not None else default_lists_path()
    return target + ".lock"


@contextmanager
def _lists_lock(lists_path: Optional[str] = None) -> Iterator[None]:
    dest = _lock_path(lists_path)
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


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _compact(entry: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in entry.items():
        if value in (None, "", [], {}):
            continue
        out[key] = value
    return out


def _flock_open(path: str, exclusive: bool) -> int:
    flags = os.O_RDWR | os.O_CREAT if exclusive else os.O_RDONLY
    fd = os.open(path, flags, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    return fd


def _flock_close(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    os.close(fd)


def append_action(
    entry: Dict[str, Any], lists_path: Optional[str] = None
) -> Optional[str]:
    """Append one JSON object to the actions log. Never raises on disk errors."""
    if lists_path is None and entry.get("path"):
        lists_path = str(entry["path"])
    log_path = actions_path(lists_path)
    payload = _compact(dict(entry))
    payload.setdefault("ts", _utc_now())
    encoded = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        fd = _flock_open(log_path, exclusive=True)
        try:
            os.lseek(fd, 0, os.SEEK_END)
            os.write(fd, encoded)
        finally:
            _flock_close(fd)
    except OSError:
        return None
    return log_path


def read_actions(
    lists_path: Optional[str] = None, limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    log_path = actions_path(lists_path)
    if not os.path.isfile(log_path):
        return []
    try:
        fd = _flock_open(log_path, exclusive=False)
        try:
            size = os.fstat(fd).st_size
            raw = os.read(fd, size) if size else b""
        finally:
            _flock_close(fd)
    except OSError:
        return []
    rows: List[Dict[str, Any]] = []
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
    if limit is not None and limit >= 0:
        return rows[-limit:]
    return rows


def _log_mutation(
    *,
    event: str,
    kind: str,
    value: Any,
    path: str,
    source: str,
    changed: bool,
    extra: Optional[Dict[str, Any]] = None,
    removed_from: Optional[List[str]] = None,
) -> None:
    extra = dict(extra or {})
    append_action(
        {
            "event": event,
            "kind": kind,
            "value": value,
            "source": source,
            "trigger": extra.pop("trigger", "manual"),
            "changed": changed,
            "path": path,
            "removed_from": removed_from,
            **extra,
        },
        path,
    )


def normalize_ip_entry(value: Any) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError("empty IP")
    if "/" in text:
        net = ipaddress.ip_network(text, strict=False)
        if net.prefixlen == net.max_prefixlen:
            return str(net.network_address)
        return str(net)
    return str(ipaddress.ip_address(text))


def normalize_asn_entry(value: Any) -> int:
    text = str(value).strip().upper()
    if text.startswith("AS"):
        text = text[2:].strip()
    n = int(text)
    if n < 0 or n > 4_294_967_295:
        raise ValueError(f"ASN out of range: {value}")
    return n


def normalize_country_entry(value: Any) -> str:
    code = canonical_country(value)
    if not code:
        raise ValueError(f"not a country code: {value}")
    return code


def _normalize(kind: str, value: Any) -> Any:
    if kind == "ip":
        return normalize_ip_entry(value)
    if kind == "asn":
        return normalize_asn_entry(value)
    if kind == "country":
        return normalize_country_entry(value)
    raise ValueError(f"unknown kind: {kind}")


def as_networks(values: Iterable[Any]) -> Tuple[Set[str], List[Network]]:
    exact: Set[str] = set()
    nets: List[Network] = []
    for raw in values or []:
        text = str(raw).strip()
        if not text or text.startswith("#"):
            continue
        entry = normalize_ip_entry(text)
        if "/" in entry:
            nets.append(ipaddress.ip_network(entry, strict=False))
        else:
            exact.add(entry)
    return exact, nets


def as_asns(values: Iterable[Any]) -> Set[int]:
    out: Set[int] = set()
    for raw in values or []:
        text = str(raw).strip()
        if not text or text.startswith("#"):
            continue
        out.add(normalize_asn_entry(text))
    return out


def as_countries(values: Iterable[Any]) -> Set[str]:
    out: Set[str] = set()
    for raw in values or []:
        text = str(raw).strip()
        if not text or text.startswith("#"):
            continue
        out.add(normalize_country_entry(text))
    return out


def ip_in_net(ip: ipaddress._BaseAddress, net: Network) -> bool:
    if ip.version != net.version:
        return False
    return ip in net


def best_prefixlen(
    ip: ipaddress._BaseAddress, exact: Set[str], nets: Sequence[Network]
) -> Optional[int]:
    """Longest matching prefix length, or None if the IP is not listed."""
    best: Optional[int] = None
    if str(ip) in exact:
        best = ip.max_prefixlen
    for net in nets:
        if not ip_in_net(ip, net):
            continue
        if best is None or net.prefixlen > best:
            best = net.prefixlen
    return best


def best_entry(
    ip: ipaddress._BaseAddress, exact: Set[str], nets: Sequence[Network]
) -> Optional[str]:
    """Canonical list entry (host or CIDR) with the longest match."""
    best: Optional[str] = None
    best_len: Optional[int] = None
    if str(ip) in exact:
        best = str(ip)
        best_len = ip.max_prefixlen
    for net in nets:
        if not ip_in_net(ip, net):
            continue
        if best_len is None or net.prefixlen > best_len:
            best_len = net.prefixlen
            best = str(net)
    return best


def _safe_sorted(key: str, values: Iterable[Any]) -> List[Any]:
    out = []
    for raw in values or []:
        try:
            if key.endswith("_asns"):
                out.append(normalize_asn_entry(raw))
            elif key.endswith("_countries"):
                out.append(normalize_country_entry(raw))
            else:
                out.append(normalize_ip_entry(raw))
        except (TypeError, ValueError):
            continue
    if key.endswith("_asns"):
        return sorted(set(out))
    return sorted(set(out), key=str)


def _meta_key(list_key: str, value: Any) -> str:
    return f"{list_key}:{value}"


def _note_text(note: Any) -> Optional[str]:
    text = str(note or "").strip()
    return text or None


def _clean_meta_entry(raw: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    out: Dict[str, Any] = {}
    ts = raw.get("ts")
    if ts:
        out["ts"] = str(ts)
    note = _note_text(raw.get("note"))
    if note:
        out["note"] = note
    source = raw.get("source")
    if source:
        out["source"] = str(source)
    event = raw.get("event")
    if event:
        out["event"] = str(event)
    return out or None


def _known_meta_keys(lists: Dict[str, Any]) -> Set[str]:
    return {
        _meta_key(key, item)
        for key in DEFAULT_LISTS
        for item in lists.get(key) or []
    }


def _prune_meta(data: Dict[str, Any], lists: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    known = _known_meta_keys(lists)
    out: Dict[str, Dict[str, Any]] = {}
    for key, value in (data.get("meta") or {}).items():
        cleaned = _clean_meta_entry(value)
        if cleaned and str(key) in known:
            out[str(key)] = cleaned
    return out


def _set_list_meta(
    data: Dict[str, Any],
    kind: str,
    list_key: str,
    value: Any,
    *,
    event: str,
    source: str,
    note: Optional[str],
) -> None:
    meta = dict(data.get("meta") or {})
    for other in _KIND_KEYS[kind]:
        meta.pop(_meta_key(other, value), None)
    entry: Dict[str, Any] = {"ts": _utc_now(), "source": source, "event": event}
    if note:
        entry["note"] = note
    meta[_meta_key(list_key, value)] = entry
    data["meta"] = meta


def _kind_meta(data: Dict[str, Any], kind: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    meta = data.get("meta") or {}
    for list_key in _KIND_KEYS[kind]:
        for item in data.get(list_key) or []:
            cleaned = _clean_meta_entry(meta.get(_meta_key(list_key, item)))
            if cleaned:
                out[str(item)] = cleaned
    return out


def load_lists(path: Optional[str] = None) -> Dict[str, Any]:
    data: Dict[str, Any] = {key: list(vals) for key, vals in DEFAULT_LISTS.items()}
    data["reasons"] = {}
    data["meta"] = {}
    target = path if path is not None else default_lists_path()
    if not target or not os.path.isfile(target):
        return data
    with open(target, encoding="utf-8") as fh:
        loaded = json.load(fh)
    if not isinstance(loaded, dict):
        raise ValueError(f"{target} must be a JSON object")
    for key in DEFAULT_LISTS:
        if key in loaded and isinstance(loaded[key], list):
            data[key] = _safe_sorted(key, loaded[key])
    reasons = loaded.get("reasons")
    if isinstance(reasons, dict):
        data["reasons"] = {
            str(key): value for key, value in reasons.items() if isinstance(value, dict)
        }
    meta = loaded.get("meta")
    if isinstance(meta, dict):
        cleaned_meta: Dict[str, Dict[str, Any]] = {}
        for key, value in meta.items():
            cleaned = _clean_meta_entry(value)
            if cleaned:
                cleaned_meta[str(key)] = cleaned
        data["meta"] = cleaned_meta
    return data


def save_lists(data: Dict[str, Any], path: Optional[str] = None) -> str:
    target = path if path is not None else default_lists_path()
    if not target:
        raise ValueError("lists path is required")
    out: Dict[str, Any] = {key: _safe_sorted(key, data.get(key) or []) for key in DEFAULT_LISTS}
    known = {str(item) for key in DEFAULT_LISTS for item in out[key]}
    reasons = {}
    for key, value in (data.get("reasons") or {}).items():
        if str(key) in known and isinstance(value, dict):
            reasons[str(key)] = value
    if reasons:
        out["reasons"] = reasons
    meta = _prune_meta(data, out)
    if meta:
        out["meta"] = meta
    atomic_write(target, json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    return target


def _kind_snapshot(data: Dict[str, Any], kind: str) -> Dict[str, Any]:
    if kind == "ip":
        snap: Dict[str, Any] = {
            "allow": list(data.get("allow_ips") or []),
            "block": list(data.get("block_ips") or []),
            "challenge": list(data.get("challenge_ips") or []),
        }
    elif kind == "asn":
        snap = {
            "block": list(data.get("block_asns") or []),
            "challenge": list(data.get("challenge_asns") or []),
        }
    elif kind == "country":
        snap = {"block": list(data.get("block_countries") or [])}
    else:
        raise ValueError(f"unknown kind: {kind}")
    snap["meta"] = _kind_meta(data, kind)
    return snap


def _ip_prefixes(data: Dict[str, Any]) -> Dict[str, str]:
    """BGP/RIR prefix for listed host IPs. Covering CIDRs are left to the GUI."""
    hosts: List[str] = []
    seen: Set[str] = set()
    for key in _IP_KEYS:
        for item in data.get(key) or []:
            text = str(item or "").strip()
            if not text:
                continue
            try:
                if "/" in text:
                    net = ipaddress.ip_network(text, strict=False)
                    if net.prefixlen < net.max_prefixlen:
                        continue
                    host = str(net.network_address)
                else:
                    host = str(ipaddress.ip_address(text))
            except ValueError:
                continue
            if host in seen:
                continue
            seen.add(host)
            hosts.append(host)
    if not hosts:
        return {}
    try:
        from ..http.weblog import compact_intel
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for host in hosts:
        try:
            intel = compact_intel(host)
        except Exception:
            intel = None
        if isinstance(intel, dict) and intel.get("prefix"):
            out[host] = str(intel["prefix"])
    return out


def snapshot(kind: Optional[str] = None, path: Optional[str] = None) -> Dict[str, Any]:
    target = path if path is not None else default_lists_path()
    data = load_lists(target)
    out: Dict[str, Any] = {"ok": True, "path": target}
    prefixes = _ip_prefixes(data)
    if kind:
        out["kind"] = kind
        out.update(_kind_snapshot(data, kind))
        if kind == "ip":
            out["ip_prefix"] = prefixes
        return out
    out["ip"] = _kind_snapshot(data, "ip")
    out["asn"] = _kind_snapshot(data, "asn")
    out["country"] = _kind_snapshot(data, "country")
    out["ip_prefix"] = prefixes
    try:
        from ..intel.flags import supported_countries

        out["country_catalog"] = supported_countries()
    except Exception:
        out["country_catalog"] = []
    return out


def add(
    action: str,
    kind: str,
    value: Any,
    path: Optional[str] = None,
    *,
    source: str = "cli",
    note: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    key = _ACTION_KEY.get((action, kind))
    if key is None:
        raise ValueError(f"cannot {action} {kind}")
    extra = dict(extra or {})
    note = _note_text(note if note is not None else extra.pop("note", None))
    if note:
        extra["note"] = note
    target = path if path is not None else default_lists_path()
    with _lists_lock(target):
        data = load_lists(target)
        normalized = _normalize(kind, value)
        siblings = [k for k in _KIND_KEYS[kind] if k != key]
        changed = False
        bucket = list(data.get(key) or [])
        if normalized not in bucket:
            bucket.append(normalized)
            data[key] = bucket
            changed = True
        for other in siblings:
            items = list(data.get(other) or [])
            if normalized in items:
                items = [item for item in items if item != normalized]
                data[other] = items
                changed = True
        _set_list_meta(
            data, kind, key, normalized, event=action, source=source, note=note
        )
        save_lists(data, target)
        data = load_lists(target)
    _log_mutation(
        event=action,
        kind=kind,
        value=normalized,
        path=target,
        source=source,
        changed=changed,
        extra=extra,
    )
    return {
        "ok": True,
        "action": action,
        "kind": kind,
        "value": normalized,
        "changed": changed,
        "path": target,
        "source": source,
        **_kind_snapshot(data, kind),
    }


def remove(
    kind: str,
    value: Any,
    path: Optional[str] = None,
    *,
    source: str = "cli",
    note: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if kind not in _KIND_KEYS:
        raise ValueError(f"unknown kind: {kind}")
    extra = dict(extra or {})
    note = _note_text(note if note is not None else extra.pop("note", None))
    if note:
        extra["note"] = note
    target = path if path is not None else default_lists_path()
    with _lists_lock(target):
        data = load_lists(target)
        normalized = _normalize(kind, value)
        removed_from: List[str] = []
        for key in _KIND_KEYS[kind]:
            items = list(data.get(key) or [])
            if normalized in items:
                data[key] = [item for item in items if item != normalized]
                removed_from.append(key)
        save_lists(data, target)
        data = load_lists(target)
    _log_mutation(
        event="remove",
        kind=kind,
        value=normalized,
        path=target,
        source=source,
        changed=bool(removed_from),
        extra=extra,
        removed_from=removed_from,
    )
    return {
        "ok": True,
        "action": "remove",
        "kind": kind,
        "value": normalized,
        "changed": bool(removed_from),
        "removed_from": removed_from,
        "path": target,
        "source": source,
        **_kind_snapshot(data, kind),
    }


def reset(
    path: Optional[str] = None,
    *,
    source: str = "cli",
    note: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    extra = dict(extra or {})
    note = _note_text(note if note is not None else extra.pop("note", None))
    if note:
        extra["note"] = note
    target = path if path is not None else default_lists_path()
    with _lists_lock(target):
        data = load_lists(target)
        cleared = {key: len(data.get(key) or []) for key in DEFAULT_LISTS}
        for key in DEFAULT_LISTS:
            data[key] = []
        data["meta"] = {}
        data["reasons"] = {}
        save_lists(data, target)
        data = load_lists(target)
    extra["cleared"] = {key: n for key, n in cleared.items() if n}
    _log_mutation(
        event="reset",
        kind="all",
        value=None,
        path=target,
        source=source,
        changed=any(cleared.values()),
        extra=extra,
    )
    return {
        "ok": True,
        "action": "reset",
        "changed": any(cleared.values()),
        "cleared": cleared,
        "path": target,
        "source": source,
    }
