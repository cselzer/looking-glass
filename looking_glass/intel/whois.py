"""Registration lookup: RDAP by default, optional legacy WHOIS."""

from __future__ import annotations

import asyncio
import socket
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .rdap import format_when, timeline_from_dates


def parse_whois_path(path: str) -> str:
    text = urllib.parse.unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "whois" and not text.startswith("whois/"):
        raise ValueError("not a whois path")
    rest = "" if text == "whois" else text[len("whois/") :]
    if not rest:
        raise ValueError("whois path needs a target, e.g. /whois/example.com")
    return rest


def _query(server: str, question: str, timeout: float = 8.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall(question.encode("utf-8") + b"\r\n")
        chunks = []
        sock.settimeout(timeout)
        while True:
            buf = sock.recv(4096)
            if not buf:
                break
            chunks.append(buf)
    return b"".join(chunks).decode("utf-8", "replace")


_DATE_KEYS = {
    "registered": (
        "creation date",
        "created",
        "created on",
        "create date",
        "domain registration date",
        "registered",
        "registered on",
        "registration time",
        "domain_dateregistered",
    ),
    "expires": (
        "registry expiry date",
        "registrar registration expiration date",
        "expiration date",
        "expiry date",
        "expires on",
        "expires",
        "expire",
        "paid-till",
        "paid till",
        "registry expiration",
        "domain_datebilleduntil",
    ),
    "last_changed": (
        "updated date",
        "last updated on",
        "last updated",
        "last-modified",
        "last modified",
        "changed",
        "update date",
        "modified",
    ),
}
_NS_KEYS = {"name server", "nserver", "nameserver", "name servers"}
_STATUS_KEYS = {"domain status", "status", "state"}
_REGISTRAR_KEYS = {"registrar", "registrar name", "sponsoring registrar"}
_IANA_KEYS = {"registrar iana id", "iana id"}
_DNSSEC_KEYS = {"dnssec", "dnssec status"}
_NAME_KEYS = {"domain name", "domain"}
_ORG_KEYS = {"registrant organization", "registrant org", "org", "organisation", "organization"}
_COUNTRY_KEYS = {"registrant country", "country", "registrant country code"}


def _whois_pairs(text: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in {"%", "#", ">"}:
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not key or not value or key.startswith("http"):
            continue
        pairs.append((key, value))
    return pairs


def _first_key(pairs: List[Tuple[str, str]], names: Tuple[str, ...]) -> Optional[str]:
    want = set(names)
    for key, value in pairs:
        if key in want:
            return value
    return None


def _all_keys(pairs: List[Tuple[str, str]], names: set) -> List[str]:
    out: List[str] = []
    seen = set()
    for key, value in pairs:
        if key not in names:
            continue
        item = value.split()[0] if key == "nserver" else value
        item = item.rstrip(".").lower() if key in _NS_KEYS else value
        if key in _NS_KEYS:
            host = value.split()[0].rstrip(".").lower()
            if host and host not in seen:
                seen.add(host)
                out.append(host)
            continue
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def parse_whois_text(text: str, *, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Pull dates, nameservers, DNSSEC, and registrar from a port-43 dump."""
    pairs = _whois_pairs(text)
    dates = {
        slot: _first_key(pairs, keys)
        for slot, keys in _DATE_KEYS.items()
    }
    timeline = timeline_from_dates(
        {
            "registered": dates.get("registered"),
            "expires": dates.get("expires"),
            "last_changed": dates.get("last_changed"),
        },
        now=now,
    )
    nameservers = _all_keys(pairs, _NS_KEYS)
    statuses = []
    for value in _all_keys(pairs, _STATUS_KEYS):
        token = value.split()[0] if value else value
        if token and token.lower() not in {s.lower() for s in statuses}:
            statuses.append(token)
    dnssec_raw = _first_key(pairs, _DNSSEC_KEYS)
    signed = None
    label = "unknown"
    if dnssec_raw:
        low = dnssec_raw.strip().lower()
        if low in {"unsigned", "unsigneddelegation", "no", "false"} or low.startswith("unsigned"):
            signed, label = False, "unsigned"
        elif low in {"signed", "signeddelegation", "yes", "true"} or "signed" in low:
            signed, label = True, "signed"
    ds_rows = []
    for key, value in pairs:
        if key in {"ds record", "ds records", "dsrdata", "ds"}:
            parts = value.split()
            if len(parts) >= 4:
                ds_rows.append(
                    {
                        "key_tag": parts[0],
                        "algorithm": parts[1],
                        "digest_type": parts[2],
                        "digest": " ".join(parts[3:]),
                    }
                )
    if ds_rows and signed is None:
        signed, label = True, "signed"
    glue: Dict[str, Dict[str, List[str]]] = {}
    for key, value in pairs:
        if key != "nserver":
            continue
        bits = value.split()
        if len(bits) < 2:
            continue
        host = bits[0].rstrip(".").lower()
        row = glue.setdefault(host, {"v4": [], "v6": []})
        for addr in bits[1:]:
            if ":" in addr:
                row["v6"].append(addr)
            elif addr.replace(".", "").isdigit() or addr.count(".") == 3:
                row["v4"].append(addr)
    nameserver_details = []
    for host in nameservers:
        extra = glue.get(host) or {"v4": [], "v6": []}
        nameserver_details.append({"host": host, "v4": extra["v4"], "v6": extra["v6"]})
    iana_id = _first_key(pairs, _IANA_KEYS)
    registrar_name = _first_key(pairs, _REGISTRAR_KEYS)
    return {
        "name": _first_key(pairs, _NAME_KEYS),
        "registrar": (
            {"name": registrar_name, "iana_id": iana_id, "email": None, "url": None}
            if registrar_name or iana_id
            else None
        ),
        "registrant": {
            "org": _first_key(pairs, _ORG_KEYS),
            "country": _first_key(pairs, _COUNTRY_KEYS),
        },
        "status": statuses,
        "nameservers": nameservers,
        "nameserver_details": nameserver_details,
        "dates": {
            "registered": timeline["registered"] or format_when(dates.get("registered")),
            "expires": timeline["expires"] or format_when(dates.get("expires")),
            "last_changed": timeline["last_changed"] or format_when(dates.get("last_changed")),
            "transfer": None,
        },
        "registered_age": timeline["registered_age"],
        "registered_ago": timeline["registered_ago"],
        "expires_in": timeline["expires_in"],
        "timeline": timeline["summary"],
        "dnssec": {
            "present": dnssec_raw is not None or bool(ds_rows),
            "signed": signed,
            "delegation_signed": signed,
            "zone_signed": None,
            "ds": ds_rows,
            "keys": [],
            "label": label,
            "raw": dnssec_raw,
        },
    }


def _referral(text: str) -> Optional[str]:
    for line in text.splitlines():
        low = line.lower().strip()
        if low.startswith("refer:") or low.startswith("whois:"):
            value = line.split(":", 1)[-1].strip()
            if value and " " not in value:
                return value
        if low.startswith("registrar whois server:"):
            return line.split(":", 1)[-1].strip()
    return None


_IANA = "whois.iana.org"


def _norm_server(server: str) -> str:
    return str(server or "").strip().lower().rstrip(".")


def _is_iana(server: str) -> bool:
    return _norm_server(server) == _IANA


def _parent_tld(target: str) -> Optional[str]:
    host = str(target or "").strip().strip(".").lower()
    if not host or ":" in host:
        return None
    if host.replace(".", "").isdigit():
        return None
    if host.startswith("as") and host[2:].isdigit():
        return None
    labels = [part for part in host.split(".") if part]
    if len(labels) < 2:
        return None
    return labels[-1]


def lookup_whois_legacy(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    start = time.time()
    chain: List[Dict[str, Any]] = []
    server = _IANA
    body = ""
    kept = ""
    kept_server = server
    error = None
    visited = set()
    try:
        for _ in range(6):
            key = _norm_server(server)
            if not key or key in visited:
                break
            visited.add(key)
            body = _query(server, target, timeout=timeout)
            chain.append({"server": server, "bytes": len(body)})
            if body:
                if not (_is_iana(server) and kept and not _is_iana(kept_server)):
                    kept = body
                    kept_server = server
            nxt = _referral(body)
            nxt_key = _norm_server(nxt) if nxt else ""
            if nxt_key and nxt_key not in visited:
                server = nxt.strip()
                continue
            tld = _parent_tld(target) if _is_iana(server) else None
            if tld:
                tld_body = _query(_IANA, tld, timeout=timeout)
                chain.append({"server": _IANA, "bytes": len(tld_body), "query": tld})
                tld_ref = _referral(tld_body)
                tld_key = _norm_server(tld_ref) if tld_ref else ""
                if tld_key and tld_key not in visited:
                    server = tld_ref.strip()
                    continue
            break
        body = kept or body
    except Exception as exc:
        error = str(exc) or exc.__class__.__name__
        body = kept or body
    parsed = parse_whois_text(body) if body else {}
    result = {
        "query": target,
        "mode": "legacy",
        "server": kept_server if kept else (chain[-1]["server"] if chain else server),
        "chain": chain,
        "text": body,
    }
    result.update(parsed)
    return {
        "ok": error is None and bool(body),
        "result": result,
        "error": error,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }
    result.update(parsed)
    return {
        "ok": error is None and bool(body),
        "result": result,
        "error": error,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


def lookup_whois(target: str, *, legacy: bool = False, timeout: float = 8.0) -> Dict[str, Any]:
    if legacy:
        return lookup_whois_legacy(target, timeout=timeout)
    from .rdap import lookup_rdap

    start = time.time()
    payload = lookup_rdap(target)
    result = payload.get("result")
    if isinstance(result, dict):
        result = dict(result)
        result["mode"] = "rdap"
    return {
        "ok": bool(payload.get("ok")),
        "result": result,
        "error": payload.get("error"),
        "total_ms": payload.get("total_ms") or round((time.time() - start) * 1000.0, 3),
    }


async def lookup_whois_async(
    target: str, *, legacy: bool = False, timeout: float = 8.0
) -> Dict[str, Any]:
    if legacy:
        return await asyncio.to_thread(lookup_whois_legacy, target, timeout)
    from .rdap import lookup_rdap_async

    payload = await lookup_rdap_async(target)
    result = payload.get("result")
    if isinstance(result, dict):
        result = dict(result)
        result["mode"] = "rdap"
    return {
        "ok": bool(payload.get("ok")),
        "result": result,
        "error": payload.get("error"),
        "total_ms": payload.get("total_ms"),
    }
