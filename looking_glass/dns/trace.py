"""Iterative DNS walk from the root, like `dig +trace`."""

from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

ROOT_HINTS = (
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
)


def parse_dnstrace_path(path: str) -> Tuple[str, str]:
    text = urllib.parse.unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "dnstrace" and not text.startswith("dnstrace/"):
        raise ValueError("not a dnstrace path")
    rest = "" if text == "dnstrace" else text[len("dnstrace/") :]
    if not rest:
        raise ValueError("dnstrace path needs a name, e.g. /dnstrace/example.com")
    if "/" in rest:
        name, qtype = rest.split("/", 1)
        return name, (qtype or "A").upper()
    return rest, "A"


def _rr_rows(msg: Any, section: str) -> List[Dict[str, Any]]:
    import dns.rdatatype

    rows: List[Dict[str, Any]] = []
    rrsets = getattr(msg, section, None) or []
    for rrset in rrsets:
        rtype = dns.rdatatype.to_text(rrset.rdtype)
        for rr in rrset:
            rows.append(
                {
                    "name": rrset.name.to_text(),
                    "ttl": int(rrset.ttl),
                    "type": rtype,
                    "data": rr.to_text(),
                }
            )
    return rows


def _ns_addrs(msg: Any) -> List[str]:
    import dns.rdatatype

    addrs: List[str] = []
    extra = list(getattr(msg, "additional", None) or [])
    for rrset in extra:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for rr in rrset:
                addrs.append(str(rr))
    return addrs


def _ns_names(msg: Any) -> List[str]:
    import dns.rdatatype

    names: List[str] = []
    for rrset in list(getattr(msg, "authority", None) or []) + list(getattr(msg, "answer", None) or []):
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset:
                names.append(str(rr.target))
    return names


def _delegated_zone(msg: Any, fallback: str) -> str:
    """Owner of the NS RRset (the zone), not the NS hostname."""
    import dns.rdatatype

    for rrset in list(getattr(msg, "authority", None) or []) + list(getattr(msg, "answer", None) or []):
        if rrset.rdtype == dns.rdatatype.NS:
            return rrset.name.to_text()
    return fallback


async def _resolve_ns_host(name: str, timeout: float) -> List[str]:
    """Resolve an NS hostname like dig +trace (not only in-bailiwick glue)."""
    from .resolve import lookup_dns_async

    addrs: List[str] = []
    for qtype in ("A", "AAAA"):
        payload = await lookup_dns_async(name, qtype, timeout=timeout)
        for row in (payload.get("result") or {}).get("answers") or []:
            data = str(row.get("data") or "").strip()
            if data:
                addrs.append(data)
    return _v4_first(addrs)


def _v4_first(addrs: List[str]) -> List[str]:
    """Try IPv4 glue before IPv6 so a broken v6 path does not stall the walk."""
    v4: List[str] = []
    v6: List[str] = []
    seen = set()
    for addr in addrs:
        text = str(addr or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        if ":" in text:
            v6.append(text)
        else:
            v4.append(text)
    return v4 + v6


def _query_error(exc: BaseException, timeout: float) -> str:
    text = str(exc) or exc.__class__.__name__
    if "timed out" in text.lower():
        return f"timed out after {timeout:.0f}s"
    return text


async def _query(server: str, name: str, rdtype: str, timeout: float) -> Tuple[Optional[Any], Optional[str]]:
    try:
        import dns.asyncquery
        import dns.message
        import dns.rdatatype
    except ImportError:
        return None, "dnspython is required"
    try:
        import dns.flags

        query = dns.message.make_query(name, dns.rdatatype.from_text(rdtype), want_dnssec=False)
        query.flags &= ~dns.flags.RD
        response, _trunc = await dns.asyncquery.udp_with_fallback(
            query, server, timeout=timeout, port=53
        )
        return response, None
    except Exception as exc:
        return None, _query_error(exc, timeout)


async def trace_dns_async(
    name: str, qtype: str = "A", timeout: float = 8.0
) -> Dict[str, Any]:
    start = time.time()
    qtype = (qtype or "A").upper()
    hops: List[Dict[str, Any]] = []
    servers = list(ROOT_HINTS)
    zone = "."
    seen = 0
    final = None
    error = None
    while servers and seen < 12:
        seen += 1
        server = servers[0]
        msg, err = await _query(server, name, qtype, timeout)
        hop = {
            "zone": zone,
            "server": server,
            "error": err,
            "rcode": None,
            "answers": [],
            "authority": [],
            "additional": [],
        }
        if msg is None:
            hops.append(hop)
            if len(servers) > 1:
                servers = servers[1:]
                seen -= 1
                continue
            error = err or "no response"
            break
        import dns.rcode

        hop["rcode"] = dns.rcode.to_text(msg.rcode())
        hop["answers"] = _rr_rows(msg, "answer")
        hop["authority"] = _rr_rows(msg, "authority")
        hop["additional"] = _rr_rows(msg, "additional")
        hops.append(hop)
        if hop["answers"]:
            final = hop
            break
        addrs = _ns_addrs(msg)
        names = _ns_names(msg)
        zone = _delegated_zone(msg, zone)
        if addrs:
            servers = _v4_first(addrs)
            continue
        if names:
            servers = []
            glue_err = None
            for ns_name in names:
                glue_msg, glue_err = await _query(server, ns_name, "A", timeout)
                if glue_msg is not None:
                    servers.extend(
                        row["data"]
                        for row in _rr_rows(glue_msg, "answer")
                        if row["type"] == "A"
                    )
                extra = await _resolve_ns_host(ns_name, timeout)
                servers.extend(extra)
                servers = _v4_first(servers)
                if servers:
                    break
            if not servers:
                error = glue_err or f"no glue for {names[0]}"
                break
            continue
        error = hop["rcode"] or "no referral"
        break
    return {
        "ok": final is not None or not error,
        "result": {
            "name": name if str(name).endswith(".") else f"{name}.",
            "qtype": qtype,
            "hops": hops,
            "answer": (final or {}).get("answers") if final else [],
            "error": error,
        },
        "error": None if final is not None or not error else error,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


def trace_dns(name: str, qtype: str = "A", timeout: float = 8.0) -> Dict[str, Any]:
    return asyncio.run(trace_dns_async(name, qtype=qtype, timeout=timeout))
