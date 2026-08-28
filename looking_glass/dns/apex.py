"""Apex: zone and mail health. Parent, NS, SOA, MX, WWW, and SMTP.

Named for the zone apex. Coverage matches a classic intoDNS report and cites
the same RFCs on each check. Queries the parent for glue, then each
authoritative nameserver — not only a public recursor.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import sys
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote

from ..net.mail import is_null_mx
from .resolve import normalize_qname, records_from_section, resolver_targets

_EDNS_PAYLOAD = 4096
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_SERIAL_YMD = re.compile(r"^(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{2}$")

QueryFn = Callable[..., Awaitable[Tuple[Optional[Any], Optional[str]]]]
SmtpFn = Callable[..., Awaitable[Dict[str, Any]]]
PingFn = Callable[..., Awaitable[Optional[bool]]]
AsnFn = Callable[..., Awaitable[Optional[int]]]

STANDARDS: List[Dict[str, Any]] = [
    {
        "rfc": 974,
        "title": "Mail Routing and the Domain System",
        "why": "MX targets must be canonical hosts, never CNAMEs.",
        "sections": ["entire"],
    },
    {
        "rfc": 1034,
        "title": "Domain Names — Concepts and Facilities",
        "why": "Delegation, CNAME rules, NS/MX as domain names.",
        "sections": ["3.6.2"],
    },
    {
        "rfc": 1035,
        "title": "Domain Names — Implementation and Specification",
        "why": "SOA, hostnames, UDP and TCP on port 53.",
        "sections": ["3.3.13", "4.2"],
    },
    {
        "rfc": 1123,
        "title": "Requirements for Internet Hosts — Application and Support",
        "why": "Hostname syntax; SMTP mailers must use MX.",
        "sections": ["2.1", "5.3.7"],
    },
    {
        "rfc": 1912,
        "title": "Common DNS Operational and Configuration Errors",
        "why": "Glue, CNAME coexistence, SOA timers, PTRs for mail hosts.",
        "sections": ["2.1", "2.2", "2.3", "2.4"],
    },
    {
        "rfc": 1918,
        "title": "Address Allocation for Private Internets",
        "why": "Private addresses must not appear in public DNS.",
        "sections": ["3"],
    },
    {
        "rfc": 1982,
        "title": "Serial Number Arithmetic",
        "why": "How SOA serial numbers compare and wrap.",
        "sections": ["3"],
    },
    {
        "rfc": 2181,
        "title": "Clarifications to the DNS Specification",
        "why": "Consistent NS sets; NS and MX must not be aliases.",
        "sections": ["5.4.1", "10.3"],
    },
    {
        "rfc": 2182,
        "title": "Selection and Operation of Secondary DNS Servers",
        "why": "At least three nameservers, diversity of network and AS.",
        "sections": ["3", "5"],
    },
    {
        "rfc": 2308,
        "title": "Negative Caching of DNS Queries (DNS NCACHE)",
        "why": "SOA MINIMUM is the negative-cache TTL; 1–3 hours recommended.",
        "sections": ["4", "5"],
    },
    {
        "rfc": 3596,
        "title": "DNS Extensions to Support IP Version 6",
        "why": "AAAA addresses for nameservers, mail, and WWW.",
        "sections": ["2"],
    },
    {
        "rfc": 5321,
        "title": "Simple Mail Transfer Protocol",
        "why": "Mail exchangers must speak SMTP.",
        "sections": ["2.3.5", "5"],
    },
    {
        "rfc": 7505,
        "title": "A 'Null MX' No Service Resource Record for Domains That Accept No Mail",
        "why": "MX 0 . means the domain does not accept mail; do not require A/AAAA or SMTP.",
        "sections": ["3"],
    },
    {
        "rfc": 5358,
        "title": "Preventing Use of Recursive Nameservers in Reflector Attacks",
        "why": "Authoritative nameservers must not recurse for the public.",
        "sections": ["4"],
    },
    {
        "rfc": 7766,
        "title": "DNS Transport over TCP — Implementation Requirements",
        "why": "Nameservers must answer DNS over TCP, not only UDP.",
        "sections": ["5", "6"],
    },
]
_BY_RFC = {row["rfc"]: row for row in STANDARDS}


def rfc_ref(number: int, section: Optional[str] = None) -> Dict[str, Any]:
    meta = _BY_RFC[number]
    out: Dict[str, Any] = {
        "rfc": number,
        "title": meta["title"],
        "url": f"https://www.rfc-editor.org/rfc/rfc{number}",
    }
    if section:
        out["section"] = section
    return out


def parse_apex_path(path: str) -> str:
    """Parse /apex/<domain> into a domain name."""
    text = unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "apex" and not text.startswith("apex/"):
        raise ValueError("not an apex path")
    rest = "" if text == "apex" else text[len("apex/") :]
    if not rest or "/" in rest:
        raise ValueError("apex path needs a domain, e.g. /apex/example.com")
    return rest


def fqdn(name: str) -> str:
    text = str(name or "").strip().rstrip(".").lower()
    return f"{text}." if text else "."


def parent_zone(zone: str) -> str:
    labels = fqdn(zone).rstrip(".").split(".")
    if len(labels) <= 1:
        return "."
    return ".".join(labels[1:]) + "."


def in_bailiwick(ns: str, zone: str) -> bool:
    host = fqdn(ns).rstrip(".").lower()
    apex = fqdn(zone).rstrip(".").lower()
    return host == apex or host.endswith("." + apex)


def hostname_ok(name: str) -> bool:
    text = fqdn(name).rstrip(".")
    if not text or len(text) > 253:
        return False
    return all(_HOST_LABEL.match(label or "") for label in text.split("."))


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(ip.is_global) and not ip.is_multicast and not ip.is_unspecified


def looks_like_ip(name: str) -> bool:
    text = str(name or "").strip().rstrip(".")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def ns_count_status(count: int) -> Tuple[str, str]:
    if count <= 0:
        return "fail", "No nameservers found. A zone needs nameservers."
    if count == 1:
        return (
            "fail",
            "Only one nameserver. You need at least two; RFC 2182 section 5 asks for three to seven.",
        )
    if count == 2:
        return (
            "pass",
            "Two nameservers. RFC 2182 section 5 asks for at least three and no more than seven; two is accepted here.",
        )
    if count <= 7:
        return (
            "pass",
            f"{count} nameservers. RFC 2182 section 5 wants at least three and no more than seven.",
        )
    return (
        "warn",
        f"{count} nameservers. RFC 2182 section 5 recommends no more than seven.",
    )


def soa_refresh_status(value: int) -> Tuple[str, str]:
    if 1200 <= value <= 86400:
        return "pass", f"SOA REFRESH is {value} seconds. That is OK."
    return (
        "warn",
        f"SOA REFRESH is {value} seconds. RFC 1912 typically wants about 20 minutes to a few hours.",
    )


def soa_retry_status(value: int, refresh: int) -> Tuple[str, str]:
    if value >= refresh:
        return (
            "warn",
            f"SOA RETRY is {value}, not less than REFRESH {refresh}. RFC 1912 wants retry shorter than refresh.",
        )
    if 180 <= value <= 7200:
        return "pass", f"SOA RETRY is {value} seconds. Looks ok."
    return "warn", f"SOA RETRY is {value} seconds. Typical values are a few minutes."


def soa_expire_status(value: int) -> Tuple[str, str]:
    weeks = value / 604800.0
    if 1_209_600 <= value <= 2_419_200:
        return "pass", f"SOA EXPIRE is {value} ({weeks:.0f} weeks). RFC 1912 recommends 2–4 weeks."
    if 604_800 <= value <= 3_628_800:
        return "pass", f"SOA EXPIRE is {value} ({weeks:.0f} weeks). Looks ok."
    return (
        "warn",
        f"SOA EXPIRE is {value}. RFC 1912 recommends 2–4 weeks (1209600–2419200 seconds).",
    )


def soa_minimum_status(value: int) -> Tuple[str, str]:
    if 3600 <= value <= 10800:
        return (
            "pass",
            f"SOA MINIMUM TTL is {value}. RFC 2308 recommends 1–3 hours for negative caching.",
        )
    if 300 <= value <= 86400:
        return (
            "pass",
            f"SOA MINIMUM TTL is {value}. RFC 2308 recommends 1–3 hours; this value is still OK.",
        )
    return (
        "warn",
        f"SOA MINIMUM TTL is {value}. RFC 2308 recommends 1–3 hours (3600–10800).",
    )


def summarize(sections: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    out = {"pass": 0, "warn": 0, "fail": 0, "info": 0}
    for section in sections:
        for check in section.get("checks") or []:
            status = str(check.get("status") or "info")
            if status not in out:
                status = "info"
            out[status] += 1
    out["total"] = sum(out.values())
    return out


def _item(
    ident: str,
    title: str,
    status: str,
    detail: str,
    rfcs: Optional[Sequence[Dict[str, Any]]] = None,
    data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "id": ident,
        "title": title,
        "status": status,
        "detail": detail,
        "rfcs": list(rfcs or []),
        "data": data or {},
    }


def _section(ident: str, title: str, checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"id": ident, "title": title, "checks": checks}


def _owner(name: Any) -> str:
    return str(name).rstrip(".").lower()


def _addresses(msg: Any) -> Tuple[List[str], List[str], List[str]]:
    v4: List[str] = []
    v6: List[str] = []
    cnames: List[str] = []
    if msg is None:
        return v4, v6, cnames
    for row in records_from_section(getattr(msg, "answer", None)):
        kind = str(row.get("type") or "").upper()
        data = str(row.get("data") or "").strip()
        if kind == "A":
            v4.append(data)
        elif kind == "AAAA":
            v6.append(data)
        elif kind == "CNAME":
            cnames.append(fqdn(data))
    return v4, v6, cnames


def _glue_map(msg: Any) -> Dict[str, Dict[str, List[str]]]:
    out: Dict[str, Dict[str, List[str]]] = {}
    if msg is None:
        return out
    for row in records_from_section(getattr(msg, "additional", None)):
        host = _owner(row.get("name"))
        kind = str(row.get("type") or "").upper()
        data = str(row.get("data") or "").strip()
        slot = out.setdefault(host, {"A": [], "AAAA": []})
        if kind in {"A", "AAAA"} and data not in slot[kind]:
            slot[kind].append(data)
    return out


def _ns_from_msg(msg: Any) -> Tuple[List[str], Optional[int]]:
    names: List[str] = []
    ttl: Optional[int] = None
    if msg is None:
        return names, ttl
    for section in ("answer", "authority"):
        for row in records_from_section(getattr(msg, section, None)):
            if str(row.get("type") or "").upper() != "NS":
                continue
            names.append(fqdn(row.get("data") or ""))
            if ttl is None:
                try:
                    ttl = int(row.get("ttl") or 0)
                except (TypeError, ValueError):
                    ttl = None
        if names:
            break
    # unique, stable
    seen = set()
    uniq: List[str] = []
    for name in names:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        uniq.append(name)
    return uniq, ttl


def _soa_from_msg(msg: Any) -> Optional[Dict[str, Any]]:
    if msg is None:
        return None
    try:
        import dns.rdatatype
    except ImportError:
        return None
    for rrset in getattr(msg, "answer", None) or []:
        if rrset.rdtype != dns.rdatatype.SOA:
            continue
        rr = next(iter(rrset), None)
        if rr is None:
            continue
        return {
            "mname": fqdn(rr.mname),
            "rname": str(rr.rname).rstrip("."),
            "serial": int(rr.serial),
            "refresh": int(rr.refresh),
            "retry": int(rr.retry),
            "expire": int(rr.expire),
            "minimum": int(rr.minimum),
            "ttl": int(rrset.ttl),
        }
    return None


def _mx_from_msg(msg: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if msg is None:
        return rows
    try:
        import dns.rdatatype
    except ImportError:
        return rows
    for rrset in getattr(msg, "answer", None) or []:
        if rrset.rdtype != dns.rdatatype.MX:
            continue
        for rr in rrset:
            rows.append(
                {
                    "preference": int(rr.preference),
                    "exchange": fqdn(rr.exchange),
                    "ttl": int(rrset.ttl),
                }
            )
    rows.sort(key=lambda row: (row["preference"], row["exchange"]))
    return rows


def _aa(msg: Any) -> bool:
    try:
        import dns.flags

        return bool(msg) and bool(msg.flags & dns.flags.AA)
    except Exception:
        return False


def _class_in(msg: Any) -> bool:
    if msg is None:
        return True
    try:
        import dns.rdataclass
    except ImportError:
        return True
    for rrset in list(getattr(msg, "answer", None) or []) + list(
        getattr(msg, "authority", None) or []
    ):
        if rrset.rdclass != dns.rdataclass.IN:
            return False
    return True


async def _query_at(
    server: str,
    qname: str,
    rdtype: str,
    *,
    timeout: float = 4.0,
    rd: bool = True,
    tcp: bool = False,
    port: int = 53,
) -> Tuple[Optional[Any], Optional[str]]:
    try:
        import dns.asyncquery
        import dns.exception
        import dns.flags
        import dns.message
        import dns.rdatatype
    except ImportError:
        return None, "dnspython is required"
    try:
        q = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
        q.use_edns(edns=0, payload=_EDNS_PAYLOAD)
        if not rd:
            q.flags &= ~dns.flags.RD
        if tcp:
            response = await dns.asyncquery.tcp(q, server, timeout=timeout, port=port)
        else:
            response, _truncated = await dns.asyncquery.udp_with_fallback(
                q, server, timeout=timeout, port=port
            )
        return response, None
    except (dns.exception.Timeout, asyncio.TimeoutError):
        return None, "timeout"
    except OSError as exc:
        return None, str(exc) or "network error"
    except Exception as exc:
        return None, str(exc) or exc.__class__.__name__


async def _query_public(
    qname: str,
    rdtype: str,
    timeout: float,
    query: QueryFn,
) -> Tuple[Optional[Any], Optional[str]]:
    last: Optional[str] = None
    for host, ns_port in resolver_targets(None, None):
        msg, err = await query(
            host, qname, rdtype, timeout=timeout, rd=True, tcp=False, port=ns_port
        )
        if msg is not None:
            return msg, None
        last = err
    return None, last or "no nameservers"


async def _host_ips(
    name: str,
    timeout: float,
    query: QueryFn,
    glue: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, List[str]]:
    out = {"A": list((glue or {}).get("A") or []), "AAAA": list((glue or {}).get("AAAA") or [])}
    for rdtype in ("A", "AAAA"):
        if out[rdtype]:
            continue
        msg, _err = await _query_public(name, rdtype, timeout, query)
        v4, v6, _cnames = _addresses(msg)
        out[rdtype] = v4 if rdtype == "A" else v6
    return out


async def _smtp_probe(host: str, ip: str, *, timeout: float = 4.0) -> Dict[str, Any]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, 25), timeout=timeout
        )
    except Exception as exc:
        return {
            "host": host,
            "ip": ip,
            "ok": False,
            "banner": None,
            "error": str(exc) or exc.__class__.__name__,
        }
    banner = None
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        banner = line.decode("utf-8", "replace").strip()
    except Exception:
        banner = None
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    ok = bool(banner) and banner.startswith("2")
    return {"host": host, "ip": ip, "ok": ok, "banner": banner, "error": None if ok else "no SMTP banner"}


async def _ping_host(ip: str, *, timeout: float = 1.2) -> Optional[bool]:
    wait = ["-W", "1000"] if sys.platform == "darwin" else ["-W", "1"]
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping",
            "-c",
            "1",
            *wait,
            ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=timeout)
        return rc == 0
    except Exception:
        return None


async def _asn_for_ip(ip: str) -> Optional[int]:
    try:
        from ..intel_server.client import lookup_json_async

        data = await lookup_json_async(ip, timeout=0.45)
        result = (data or {}).get("result") or {}
        asn = result.get("asn")
        if isinstance(asn, int) and asn > 0:
            return asn
    except Exception:
        pass
    try:
        from ..intel import asn as asn_mod

        origin = asn_mod.find_origin(ip)
        asn = (origin or {}).get("asn")
        if asn not in (None, False):
            return int(asn)
    except Exception:
        return None
    return None


def _private_list(ips: Sequence[str]) -> List[str]:
    return [ip for ip in ips if not is_public_ip(ip)]


def _v4_subnets(ips: Sequence[str]) -> List[str]:
    nets = []
    seen = set()
    for ip in ips:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        net = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        if net not in seen:
            seen.add(net)
            nets.append(net)
    return nets


async def check_apex_async(
    name: str,
    *,
    timeout: float = 4.0,
    query: Optional[QueryFn] = None,
    smtp: Optional[SmtpFn] = None,
    ping: Optional[PingFn] = None,
    asn: Optional[AsnFn] = None,
) -> Dict[str, Any]:
    """Run the full Apex report for `name`."""
    start = time.time()
    query = query or _query_at
    smtp = smtp or _smtp_probe
    ping = ping or _ping_host
    asn = asn or _asn_for_ip
    qname = normalize_qname(name, qtype="A")
    zone = fqdn(qname)
    parent = parent_zone(zone)

    parent_ns_msg, parent_ns_err = await _query_public(parent, "NS", timeout, query)
    parent_ns_names, _ = _ns_from_msg(parent_ns_msg)
    parent_ns_ips: List[str] = []
    parent_ns_used: Optional[str] = None
    for ns_name in parent_ns_names:
        ips = await _host_ips(ns_name, timeout, query)
        parent_ns_ips.extend(ips.get("A") or [])
        parent_ns_ips.extend(ips.get("AAAA") or [])
    parent_ns_ips = list(dict.fromkeys(parent_ns_ips))

    parent_msg = None
    parent_err = parent_ns_err
    for ip in parent_ns_ips:
        msg, err = await query(ip, zone, "NS", timeout=timeout, rd=False, tcp=False)
        if msg is not None:
            parent_msg = msg
            parent_ns_used = ip
            parent_err = None
            break
        parent_err = err

    parent_ns, parent_ttl = _ns_from_msg(parent_msg)
    parent_glue = _glue_map(parent_msg)
    parent_sent_glue = any(parent_glue.get(_owner(ns)) for ns in parent_ns)

    # Child NS from each parent-listed server (or public if parent failed).
    ns_targets = list(parent_ns)
    child_by_server: Dict[str, Dict[str, Any]] = {}
    child_ns_set: List[str] = []
    soa_by_server: Dict[str, Dict[str, Any]] = {}
    mx_by_server: Dict[str, List[Dict[str, Any]]] = {}
    responded: List[str] = []
    silent: List[str] = []
    recursive: List[str] = []
    tcp_ok: List[str] = []
    tcp_fail: List[str] = []
    class_ok = True
    ns_ips: Dict[str, Dict[str, List[str]]] = {}

    async def _resolve_ns_host(ns_name: str) -> Dict[str, List[str]]:
        glue = parent_glue.get(_owner(ns_name)) or {}
        return await _host_ips(ns_name, timeout, query, glue)

    if ns_targets:
        resolved = await asyncio.gather(*[_resolve_ns_host(ns) for ns in ns_targets])
        for ns_name, ips in zip(ns_targets, resolved):
            ns_ips[ns_name] = ips
    else:
        # Fall back to public NS of the zone so later checks still run.
        fallback, _ = await _query_public(zone, "NS", timeout, query)
        ns_targets, _ = _ns_from_msg(fallback)
        resolved = await asyncio.gather(*[_resolve_ns_host(ns) for ns in ns_targets]) if ns_targets else []
        for ns_name, ips in zip(ns_targets, resolved):
            ns_ips[ns_name] = ips

    async def probe_ns(ns_name: str) -> None:
        nonlocal class_ok
        ips = (ns_ips.get(ns_name) or {}).get("A") or (ns_ips.get(ns_name) or {}).get("AAAA") or []
        if not ips:
            silent.append(ns_name)
            return
        ip = ips[0]
        ns_msg, ns_err = await query(ip, zone, "NS", timeout=timeout, rd=False, tcp=False)
        soa_msg, _soa_err = await query(ip, zone, "SOA", timeout=timeout, rd=False, tcp=False)
        mx_msg, _mx_err = await query(ip, zone, "MX", timeout=timeout, rd=False, tcp=False)
        tcp_msg, _tcp_err = await query(ip, zone, "SOA", timeout=timeout, rd=False, tcp=True)
        rec_msg, _rec_err = await query(
            ip, "dns.google.", "A", timeout=min(timeout, 3.0), rd=True, tcp=False
        )
        if ns_msg is None and soa_msg is None:
            silent.append(ns_name)
            child_by_server[ns_name] = {"error": ns_err or "no response", "ip": ip}
            return
        responded.append(ns_name)
        names, _ttl = _ns_from_msg(ns_msg or soa_msg)
        child_by_server[ns_name] = {"ip": ip, "ns": names, "aa": _aa(ns_msg or soa_msg)}
        if names:
            child_ns_set.extend(names)
        soa = _soa_from_msg(soa_msg)
        if soa:
            soa_by_server[ns_name] = soa
        mx_by_server[ns_name] = _mx_from_msg(mx_msg)
        if not _class_in(ns_msg or soa_msg):
            class_ok = False
        if tcp_msg is not None:
            tcp_ok.append(ns_name)
        else:
            tcp_fail.append(ns_name)
        rec_v4, rec_v6, _rec_c = _addresses(rec_msg)
        if rec_v4 or rec_v6:
            recursive.append(ns_name)

    if ns_targets:
        await asyncio.gather(*(probe_ns(ns) for ns in ns_targets))

    child_ns: List[str] = []
    seen_ns = set()
    for name_ns in child_ns_set:
        key = name_ns.lower()
        if key in seen_ns:
            continue
        seen_ns.add(key)
        child_ns.append(name_ns)
    if not child_ns:
        child_ns = list(ns_targets)

    parent_set = {fqdn(n).lower() for n in parent_ns}
    child_set = {fqdn(n).lower() for n in child_ns}
    missing_at_child = sorted(parent_set - child_set)
    missing_at_parent = sorted(child_set - parent_set)

    # Glue comparison for nameservers present on both sides.
    glue_mismatch: List[Dict[str, Any]] = []
    same_glue = True
    for ns_name in parent_ns:
        key = _owner(ns_name)
        parent_a = list((parent_glue.get(key) or {}).get("A") or [])
        child_a = list((ns_ips.get(ns_name) or {}).get("A") or [])
        if parent_a and child_a and set(parent_a) != set(child_a):
            same_glue = False
            glue_mismatch.append({"ns": ns_name, "parent": parent_a, "child": child_a})

    all_ns_ips: List[str] = []
    for ips in ns_ips.values():
        all_ns_ips.extend(ips.get("A") or [])
        all_ns_ips.extend(ips.get("AAAA") or [])
    all_ns_ips = list(dict.fromkeys(all_ns_ips))
    private_ns = _private_list(all_ns_ips)
    subnets = _v4_subnets([ip for ip in all_ns_ips if ":" not in ip])

    asns: Dict[str, Optional[int]] = {}
    unique_v4 = [ip for ip in all_ns_ips if ":" not in ip][:8]
    if unique_v4:
        asn_vals = await asyncio.gather(*(asn(ip) for ip in unique_v4))
        for ip, value in zip(unique_v4, asn_vals):
            asns[ip] = value
    asn_numbers = sorted({v for v in asns.values() if isinstance(v, int)})

    invalid_ns_names = [n for n in child_ns + parent_ns if not hostname_ok(n)]
    cname_ns: List[str] = []
    for ns_name in dict.fromkeys(parent_ns + child_ns):
        cmsg, _ = await _query_public(ns_name, "CNAME", timeout, query)
        _v4, _v6, cnames = _addresses(cmsg)
        if cnames:
            cname_ns.append(ns_name)

    ping_ok: List[str] = []
    ping_fail: List[str] = []
    ping_unknown = False
    ping_ips = [ip for ip in all_ns_ips if ":" not in ip][:8]
    if ping_ips:
        ping_vals = await asyncio.gather(*(ping(ip) for ip in ping_ips))
        for ip, value in zip(ping_ips, ping_vals):
            if value is True:
                ping_ok.append(ip)
            elif value is False:
                ping_fail.append(ip)
            else:
                ping_unknown = True

    soa = next(iter(soa_by_server.values()), None)
    serials = {row["serial"] for row in soa_by_server.values()}
    mname_listed = False
    if soa:
        mname_listed = fqdn(soa["mname"]).lower() in child_set or fqdn(soa["mname"]).lower() in parent_set

    # MX from the most talkative server, else public.
    mx_records = next((rows for rows in mx_by_server.values() if rows), [])
    if not mx_records:
        mx_msg, _ = await _query_public(zone, "MX", timeout, query)
        mx_records = _mx_from_msg(mx_msg)

    mx_sets = []
    for rows in mx_by_server.values():
        mx_sets.append(tuple((row["preference"], row["exchange"].lower()) for row in rows))
    mx_consistent = len(set(mx_sets)) <= 1

    mx_hosts = [row["exchange"] for row in mx_records]
    null_mx = is_null_mx(mx_records)
    mx_cname: Dict[str, List[str]] = {}
    mx_addr: Dict[str, Dict[str, List[str]]] = {}
    for host in mx_hosts:
        if null_mx:
            mx_addr[host] = {"A": [], "AAAA": []}
            continue
        if looks_like_ip(host):
            mx_addr[host] = {"A": [host.rstrip(".")], "AAAA": []}
            continue
        a_msg, _ = await _query_public(host, "A", timeout, query)
        aaaa_msg, _ = await _query_public(host, "AAAA", timeout, query)
        c_msg, _ = await _query_public(host, "CNAME", timeout, query)
        v4, _v6a, c1 = _addresses(a_msg)
        _v4b, v6, c2 = _addresses(aaaa_msg)
        _v4c, _v6c, c3 = _addresses(c_msg)
        cnames = list(dict.fromkeys(c1 + c2 + c3))
        if cnames:
            mx_cname[host] = cnames
        mx_addr[host] = {"A": v4, "AAAA": v6}

    mx_ips: List[str] = []
    for host in mx_hosts:
        mx_ips.extend((mx_addr.get(host) or {}).get("A") or [])
        mx_ips.extend((mx_addr.get(host) or {}).get("AAAA") or [])
    mx_ips = list(dict.fromkeys(mx_ips))
    private_mx = _private_list(mx_ips)
    mx_ip_literal = [h for h in mx_hosts if looks_like_ip(h)]
    mx_no_addr = [
        h
        for h in mx_hosts
        if not null_mx
        and not looks_like_ip(h)
        and not ((mx_addr.get(h) or {}).get("A") or (mx_addr.get(h) or {}).get("AAAA"))
    ]

    ip_to_mx: Dict[str, List[str]] = {}
    for host in mx_hosts:
        for ip in (mx_addr.get(host) or {}).get("A") or []:
            ip_to_mx.setdefault(ip, []).append(host)
    dup_mx = {ip: hosts for ip, hosts in ip_to_mx.items() if len(set(hosts)) > 1}

    ptr_map: Dict[str, List[str]] = {}
    for ip in mx_ips[:12]:
        try:
            import dns.reversename

            ptr_name = str(dns.reversename.from_address(ip))
        except Exception:
            continue
        ptr_msg, _ = await _query_public(ptr_name, "PTR", timeout, query)
        ptrs = [_owner(row.get("data")) for row in records_from_section(getattr(ptr_msg, "answer", None) or []) if str(row.get("type")) == "PTR"]
        # records_from_section stores rdata in data; PTR data is the target name
        if not ptrs:
            ptrs = [
                fqdn(row["data"]).rstrip(".")
                for row in records_from_section(getattr(ptr_msg, "answer", None) or [])
                if str(row.get("type") or "").upper() == "PTR"
            ]
        ptr_map[ip] = ptrs
    missing_ptr = [ip for ip in mx_ips if ip in ptr_map and not ptr_map[ip]]

    www_name = f"www.{zone}" if not _owner(zone).startswith("www.") else zone
    www_a, _ = await _query_public(www_name, "A", timeout, query)
    www_aaaa, _ = await _query_public(www_name, "AAAA", timeout, query)
    www_c, _ = await _query_public(www_name, "CNAME", timeout, query)
    www_v4, _x, www_c1 = _addresses(www_a)
    _y, www_v6, www_c2 = _addresses(www_aaaa)
    _z, _w, www_c3 = _addresses(www_c)
    www_cnames = list(dict.fromkeys(www_c1 + www_c2 + www_c3))
    www_ips = list(dict.fromkeys(www_v4 + www_v6))
    private_www = _private_list(www_ips)

    mail_probes: List[Dict[str, Any]] = []
    smtp_targets = []
    for host in mx_hosts[:6]:
        for ip in ((mx_addr.get(host) or {}).get("A") or [])[:2]:
            smtp_targets.append((host, ip))
    if smtp_targets:
        mail_probes = list(await asyncio.gather(*(smtp(host, ip) for host, ip in smtp_targets)))

    # ---- Parent ----
    parent_checks: List[Dict[str, Any]] = []
    if parent_ns:
        listing = ", ".join(
            f"{n.rstrip('.')} {((parent_glue.get(_owner(n)) or {}).get('A') or (parent_glue.get(_owner(n)) or {}).get('AAAA') or ['(no glue)'])}"
            + (f" [TTL={parent_ttl}]" if parent_ttl is not None else "")
            for n in parent_ns
        )
        extra = f" Parent server {parent_ns_used} answered." if parent_ns_used else ""
        parent_checks.append(
            _item(
                "parent_ns",
                "Domain NS records",
                "pass",
                f"Nameserver records returned by the parent servers are: {listing}.{extra}",
                [rfc_ref(1034), rfc_ref(1035)],
                {"ns": parent_ns, "glue": parent_glue, "ttl": parent_ttl, "parent": parent, "via": parent_ns_used},
            )
        )
    else:
        parent_checks.append(
            _item(
                "parent_ns",
                "Domain NS records",
                "fail",
                f"Could not read NS from the parent zone {parent.rstrip('.')}. {parent_err or 'no response'}",
                [rfc_ref(1034), rfc_ref(2181, "5.4.1")],
                {"error": parent_err, "parent": parent},
            )
        )
    parent_checks.append(
        _item(
            "tld_parent",
            "TLD parent check",
            "pass" if parent_ns_names else "fail",
            (
                f"Parent zone {parent.rstrip('.')} has nameservers: "
                + ", ".join(n.rstrip(".") for n in parent_ns_names)
                if parent_ns_names
                else f"Could not find nameservers for parent zone {parent.rstrip('.')}."
            ),
            [rfc_ref(1034)],
            {"parent": parent, "parent_ns": parent_ns_names},
        )
    )
    parent_checks.append(
        _item(
            "listed_at_parent",
            "Your nameservers are listed",
            "pass" if parent_ns else "fail",
            "The parent listed nameservers for this zone." if parent_ns else "The parent did not list nameservers for this zone.",
            [rfc_ref(1034), rfc_ref(2181, "5.4.1")],
        )
    )
    if parent_sent_glue:
        parent_checks.append(
            _item(
                "parent_glue",
                "DNS Parent sent Glue",
                "pass",
                "Good. The parent nameserver sent GLUE: your nameservers and their addresses. Glue records are A/AAAA associated with NS to bootstrap resolution.",
                [rfc_ref(1912, "2.3")],
                {"glue": parent_glue},
            )
        )
    elif parent_ns:
        in_zone = [n for n in parent_ns if in_bailiwick(n, zone)]
        status = "fail" if in_zone else "info"
        parent_checks.append(
            _item(
                "parent_glue",
                "DNS Parent sent Glue",
                status,
                (
                    "The parent is not sending glue for every nameserver. That is OK when nameservers live in another TLD, but in-bailiwick NS need glue or resolution can loop."
                    if in_zone
                    else "The parent did not send glue. That is OK when nameservers are out of bailiwick; it costs an extra A/AAAA lookup."
                ),
                [rfc_ref(1912, "2.3")],
                {"glue": parent_glue, "in_bailiwick": in_zone},
            )
        )
    glue_hosts = []
    for ns_name in parent_ns:
        addrs = (parent_glue.get(_owner(ns_name)) or {})
        glue_hosts.append({"ns": ns_name, "A": addrs.get("A") or [], "AAAA": addrs.get("AAAA") or []})
    parent_checks.append(
        _item(
            "parent_ns_a",
            "Nameservers A records",
            "pass" if any((g["A"] or g["AAAA"]) for g in glue_hosts) else "info",
            "Parent glue A/AAAA: "
            + (
                "; ".join(
                    f"{g['ns'].rstrip('.')} A={g['A'] or '—'} AAAA={g['AAAA'] or '—'}"
                    for g in glue_hosts
                )
                or "none"
            ),
            [rfc_ref(1034), rfc_ref(3596)],
            {"glue": glue_hosts},
        )
    )

    # ---- NS ----
    ns_to_eval = bool(parent_ns or child_ns or all_ns_ips)
    ns_empty = "No nameservers to evaluate."
    ns_checks: List[Dict[str, Any]] = []
    ns_checks.append(
        _item(
            "child_ns",
            "NS records from your nameservers",
            "pass" if child_ns else "fail",
            (
                "NS records from your nameservers listed at the parent: "
                + ", ".join(
                    f"{n.rstrip('.')} {(ns_ips.get(n) or {}).get('A') or (ns_ips.get(n) or {}).get('AAAA') or []}"
                    for n in child_ns
                )
                if child_ns
                else "Your nameservers did not return NS records."
            ),
            [rfc_ref(1034), rfc_ref(1035)],
            {"ns": child_ns, "ips": ns_ips},
        )
    )
    if missing_at_child or missing_at_parent:
        ns_checks.append(
            _item(
                "same_glue",
                "Same Glue",
                "info" if not ns_to_eval else (
                    "fail" if glue_mismatch or missing_at_child or missing_at_parent else "pass"
                ),
                ns_empty if not ns_to_eval else (
                    "Parent and child NS sets differ. The parent and the zone must publish the same NS set."
                ),
                [rfc_ref(2181, "5.4.1"), rfc_ref(1034)],
                {"missing_at_child": missing_at_child, "missing_at_parent": missing_at_parent, "mismatch": glue_mismatch},
            )
        )
    else:
        ns_checks.append(
            _item(
                "same_glue",
                "Same Glue",
                "info" if not ns_to_eval else ("pass" if same_glue else "warn"),
                (
                    ns_empty
                    if not ns_to_eval
                    else (
                        "The A records (the GLUE) from the parent match the ones from your nameservers."
                        if same_glue
                        else "Glue A records at the parent do not match A records from your nameservers."
                    )
                ),
                [rfc_ref(1912, "2.3"), rfc_ref(2181, "5.4.1")],
                {"mismatch": glue_mismatch},
            )
        )
    if missing_at_child:
        ns_checks.append(
            _item(
                "missing_at_child",
                "Missing nameservers reported by parent",
                "fail",
                "These nameservers are listed at the parent but not at your nameservers: "
                + ", ".join(n.rstrip(".") for n in missing_at_child)
                + ". RFC 2181 section 5.4.1: the NS set must be consistent.",
                [rfc_ref(2181, "5.4.1")],
                {"ns": missing_at_child},
            )
        )
    if missing_at_parent:
        ns_checks.append(
            _item(
                "missing_at_parent",
                "Missing nameservers reported by your nameservers",
                "fail",
                "These nameservers are in the zone but not at the parent (stealth NS): "
                + ", ".join(n.rstrip(".") for n in missing_at_parent)
                + ". They will not be used by resolvers that only follow the parent delegation.",
                [rfc_ref(2181, "5.4.1")],
                {"ns": missing_at_parent},
            )
        )
    count_status, count_detail = ns_count_status(len(dict.fromkeys(parent_ns or child_ns)))
    ns_checks.append(
        _item(
            "multiple_ns",
            "Multiple Nameservers",
            count_status,
            count_detail,
            [rfc_ref(2182, "5")],
            {"count": len(dict.fromkeys(parent_ns or child_ns))},
        )
    )
    glue_needed = [n for n in (parent_ns or child_ns) if in_bailiwick(n, zone)]
    glue_ok = all(
        ((parent_glue.get(_owner(n)) or {}).get("A") or (parent_glue.get(_owner(n)) or {}).get("AAAA") or (ns_ips.get(n) or {}).get("A") or (ns_ips.get(n) or {}).get("AAAA"))
        for n in glue_needed
    ) if glue_needed else True
    ns_checks.append(
        _item(
            "glue_for_ns",
            "Glue for NS records",
            "info" if not ns_to_eval else ("pass" if glue_ok else "fail"),
            (
                ns_empty
                if not ns_to_eval
                else (
                    "OK. In-bailiwick nameservers have address records."
                    if glue_ok
                    else "In-bailiwick nameservers are missing A/AAAA glue. RFC 1912 section 2.3: glue is required to bootstrap those names."
                )
            ),
            [rfc_ref(1912, "2.3")],
            {"needed": glue_needed, "glue": parent_glue},
        )
    )
    ns_checks.append(
        _item(
            "ns_public",
            "NS IPs are public",
            "info" if not ns_to_eval else ("fail" if private_ns else "pass"),
            (
                ns_empty
                if not ns_to_eval
                else (
                    "ERROR. These nameserver addresses are not public: " + ", ".join(private_ns)
                    if private_ns
                    else "OK. Nameserver addresses appear to be public."
                )
            ),
            [rfc_ref(1918), rfc_ref(1912)],
            {"private": private_ns, "ips": all_ns_ips},
        )
    )
    ns_checks.append(
        _item(
            "ns_cname",
            "NS is not CNAME",
            "info" if not ns_to_eval else ("fail" if cname_ns else "pass"),
            (
                ns_empty
                if not ns_to_eval
                else (
                    "ERROR. These nameservers are aliases: "
                    + ", ".join(n.rstrip(".") for n in cname_ns)
                    + ". RFC 2181 section 10.3: NS targets must not be CNAMEs."
                    if cname_ns
                    else "OK. Nameserver names are not CNAMEs."
                )
            ),
            [rfc_ref(2181, "10.3"), rfc_ref(1912, "2.4"), rfc_ref(1034, "3.6.2")],
            {"cname": cname_ns},
        )
    )
    ns_checks.append(
        _item(
            "ns_hostname",
            "Name of nameservers are valid",
            "info" if not ns_to_eval else ("fail" if invalid_ns_names else "pass"),
            (
                ns_empty
                if not ns_to_eval
                else (
                    "ERROR. These nameserver hostnames are not valid Internet host names: "
                    + ", ".join(n.rstrip(".") for n in invalid_ns_names)
                    if invalid_ns_names
                    else "OK. Nameserver names follow RFC 1035 / RFC 1123 host syntax."
                )
            ),
            [rfc_ref(1035), rfc_ref(1123), rfc_ref(1912)],
            {"invalid": invalid_ns_names},
        )
    )
    if len(subnets) >= 2:
        subnet_status, subnet_detail = "pass", f"OK. Nameservers are on {len(subnets)} different /24 subnets."
    elif len(subnets) == 1 and len([i for i in all_ns_ips if ":" not in i]) >= 2:
        subnet_status, subnet_detail = (
            "warn",
            "All IPv4 nameservers share one /24. RFC 2182 wants topological diversity.",
        )
    else:
        subnet_status, subnet_detail = "info", "Not enough IPv4 nameserver addresses to judge subnet diversity."
    ns_checks.append(
        _item(
            "subnets",
            "Different subnets",
            subnet_status,
            subnet_detail,
            [rfc_ref(2182, "3")],
            {"subnets": subnets},
        )
    )
    if len(asn_numbers) >= 2:
        as_status, as_detail = "pass", f"OK. Nameservers are in {len(asn_numbers)} autonomous systems ({', '.join('AS' + str(a) for a in asn_numbers)}). That avoids a single-AS failure."
    elif len(asn_numbers) == 1 and len(unique_v4) >= 2:
        as_status, as_detail = (
            "warn",
            f"All probed nameservers are in AS{asn_numbers[0]}. RFC 2182 asks you to spread secondaries across locations.",
        )
    elif not asn_numbers:
        as_status, as_detail = "info", "Could not map nameserver IPs to ASNs (intel server or pyasn DB unavailable)."
    else:
        as_status, as_detail = "info", "Not enough ASN data to judge diversity."
    ns_checks.append(
        _item(
            "asns",
            "Different autonomous systems",
            as_status,
            as_detail,
            [rfc_ref(2182, "3")],
            {"asns": asns},
        )
    )
    ns_checks.append(
        _item(
            "responded",
            "DNS servers responded",
            "fail" if silent else "pass" if responded else "fail",
            (
                "Good. All nameservers responded."
                if responded and not silent
                else f"These nameservers did not answer: {', '.join(n.rstrip('.') for n in silent)}"
                if silent
                else "No nameserver responded."
            ),
            [rfc_ref(1034), rfc_ref(1035)],
            {"ok": responded, "silent": silent},
        )
    )
    ns_checks.append(
        _item(
            "recursive",
            "Recursive Queries",
            "info" if not ns_to_eval else ("fail" if recursive else "pass"),
            (
                ns_empty
                if not ns_to_eval
                else (
                    "ERROR. These nameservers recurse for outsiders: "
                    + ", ".join(n.rstrip(".") for n in recursive)
                    + ". Authoritative servers must not be open resolvers (RFC 5358)."
                    if recursive
                    else "Good. Your nameservers do not report that they allow recursive queries for anyone."
                )
            ),
            [rfc_ref(5358), rfc_ref(1034)],
            {"open": recursive},
        )
    )
    ns_checks.append(
        _item(
            "tcp",
            "DNS servers allow TCP connection",
            "fail" if tcp_fail and not tcp_ok else "warn" if tcp_fail else "pass" if tcp_ok else "info",
            (
                "OK. All DNS servers allow TCP connections. Required for large answers and by RFC 7766."
                if tcp_ok and not tcp_fail
                else f"These nameservers did not answer over TCP/53: {', '.join(n.rstrip('.') for n in tcp_fail)}"
                if tcp_fail
                else "Could not test DNS over TCP."
            ),
            [rfc_ref(7766), rfc_ref(1035, "4.2")],
            {"ok": tcp_ok, "fail": tcp_fail},
        )
    )
    ns_checks.append(
        _item(
            "same_class",
            "Same class",
            "info" if not ns_to_eval else ("pass" if class_ok else "fail"),
            (
                ns_empty
                if not ns_to_eval
                else ("OK. NS records are class IN." if class_ok else "ERROR. Not all NS records are class IN.")
            ),
            [rfc_ref(1035)],
        )
    )
    if ping_unknown and not ping_ok and not ping_fail:
        ping_status, ping_detail = "info", "ICMP ping was not available from this host (often filtered)."
    elif ping_fail and not ping_ok:
        ping_status, ping_detail = "info", f"Nameservers did not answer ICMP ping: {', '.join(ping_fail)}. Ping is optional; DNS over UDP/TCP is what matters."
    elif ping_fail:
        ping_status, ping_detail = "info", f"Some nameservers ignore ping ({', '.join(ping_fail)}); others replied ({', '.join(ping_ok)})."
    elif ping_ok:
        ping_status, ping_detail = "pass", f"ICMP ping reached nameserver addresses: {', '.join(ping_ok)}."
    else:
        ping_status, ping_detail = "info", "No IPv4 nameserver addresses to ping."
    ns_checks.append(
        _item(
            "ping",
            "Is ping nameservers work",
            ping_status,
            ping_detail,
            [],
            {"ok": ping_ok, "fail": ping_fail},
        )
    )

    # ---- SOA ----
    soa_checks: List[Dict[str, Any]] = []
    if soa:
        soa_checks.append(
            _item(
                "soa_record",
                "SOA record",
                "pass",
                (
                    f"Primary nameserver: {soa['mname'].rstrip('.')}  "
                    f"Hostmaster: {soa['rname']}  "
                    f"Serial: {soa['serial']}  Refresh: {soa['refresh']}  "
                    f"Retry: {soa['retry']}  Expire: {soa['expire']}  "
                    f"Minimum: {soa['minimum']}"
                ),
                [rfc_ref(1035, "3.3.13"), rfc_ref(1912, "2.2")],
                soa,
            )
        )
        if len(serials) <= 1:
            soa_checks.append(
                _item(
                    "soa_serial_same",
                    "NSs have same SOA serial",
                    "pass",
                    f"OK. All nameservers agree that the SOA serial is {soa['serial']}.",
                    [rfc_ref(1034), rfc_ref(1982)],
                    {"serial": soa["serial"], "serials": sorted(serials)},
                )
            )
        else:
            soa_checks.append(
                _item(
                    "soa_serial_same",
                    "NSs have same SOA serial",
                    "fail",
                    f"Nameservers disagree on SOA serial: {sorted(serials)}. Zone transfers or NOTIFY may be broken.",
                    [rfc_ref(1034), rfc_ref(1982)],
                    {"serials": sorted(serials)},
                )
            )
        soa_checks.append(
            _item(
                "soa_mname",
                "SOA MNAME entry",
                "pass" if mname_listed else "warn",
                (
                    f"OK. Primary {soa['mname'].rstrip('.')} is listed in the NS set."
                    if mname_listed
                    else f"SOA MNAME {soa['mname'].rstrip('.')} is not in the NS set. RFC 1912 expects the primary to be a listed nameserver."
                ),
                [rfc_ref(1035), rfc_ref(1912, "2.2")],
                {"mname": soa["mname"], "listed": mname_listed},
            )
        )
        serial_txt = str(soa["serial"])
        if _SERIAL_YMD.match(serial_txt):
            soa_checks.append(
                _item(
                    "soa_serial",
                    "SOA Serial",
                    "pass",
                    f"SOA serial {serial_txt} looks like YYYYMMDDnn (RFC 1912).",
                    [rfc_ref(1912, "2.2"), rfc_ref(1982)],
                    {"serial": soa["serial"]},
                )
            )
        else:
            soa_checks.append(
                _item(
                    "soa_serial",
                    "SOA Serial",
                    "info",
                    f"SOA serial is {serial_txt}. YYYYMMDDnn is the usual convention; this can be ok if you know what you are doing.",
                    [rfc_ref(1912, "2.2"), rfc_ref(1982)],
                    {"serial": soa["serial"]},
                )
            )
        st, detail = soa_refresh_status(int(soa["refresh"]))
        soa_checks.append(_item("soa_refresh", "SOA REFRESH", st, detail, [rfc_ref(1912, "2.2")], {"refresh": soa["refresh"]}))
        st, detail = soa_retry_status(int(soa["retry"]), int(soa["refresh"]))
        soa_checks.append(_item("soa_retry", "SOA RETRY", st, detail, [rfc_ref(1912, "2.2")], {"retry": soa["retry"]}))
        st, detail = soa_expire_status(int(soa["expire"]))
        soa_checks.append(_item("soa_expire", "SOA EXPIRE", st, detail, [rfc_ref(1912, "2.2")], {"expire": soa["expire"]}))
        st, detail = soa_minimum_status(int(soa["minimum"]))
        soa_checks.append(
            _item(
                "soa_minimum",
                "SOA MINIMUM TTL",
                st,
                detail + " MINIMUM used to be a default TTL; RFC 2308 uses it for negative caching.",
                [rfc_ref(2308)],
                {"minimum": soa["minimum"]},
            )
        )
    else:
        soa_checks.append(
            _item(
                "soa_record",
                "SOA record",
                "fail",
                "No SOA record from the nameservers. A zone must have exactly one SOA.",
                [rfc_ref(1035, "3.3.13")],
            )
        )

    # ---- MX ----
    mx_checks: List[Dict[str, Any]] = []
    if mx_records:
        listing = "; ".join(
            f"{row['preference']} {row['exchange'].rstrip('.')} "
            f"{(mx_addr.get(row['exchange']) or {}).get('A') or []} "
            f"{'(CNAME) ' if row['exchange'] in mx_cname else ''}"
            f"{'(no glue)' if not in_bailiwick(row['exchange'], zone) else ''}"
            for row in mx_records
        )
        mx_checks.append(
            _item(
                "mx_records",
                "MX Records",
                "pass",
                f"MX records from your nameservers: {listing}",
                [rfc_ref(1035), rfc_ref(5321), rfc_ref(974)],
                {"mx": mx_records, "addresses": mx_addr},
            )
        )
    else:
        mx_checks.append(
            _item(
                "mx_records",
                "MX Records",
                "info",
                "No MX records. Mail may still fall back to the apex A/AAAA; RFC 5321 and RFC 1123 expect MX.",
                [rfc_ref(5321), rfc_ref(1123, "5.3.7"), rfc_ref(1912, "2.5")],
            )
        )
    mx_checks.append(
        _item(
            "mx_count",
            "MX count",
            "pass" if len(mx_records) >= 2 else "info" if mx_records else "info",
            (
                f"{len(mx_records)} mail exchangers."
                + (" Redundancy looks good." if len(mx_records) >= 2 else " A second MX is safer." if mx_records else "")
            ),
            [rfc_ref(5321)],
            {"count": len(mx_records)},
        )
    )
    mx_checks.append(
        _item(
            "mx_consistent",
            "Different MX records at nameservers",
            "info" if not mx_records else ("pass" if mx_consistent else "fail"),
            (
                "No MX to compare."
                if not mx_records
                else "Good. Nameservers publish the same MX set."
                if mx_consistent
                else "Nameservers disagree on MX records."
            ),
            [rfc_ref(1034), rfc_ref(2181, "5.4.1")],
            {"sets": [list(s) for s in mx_sets]},
        )
    )
    mx_checks.append(
        _item(
            "mx_cname",
            "MX CNAME Check",
            "info" if not mx_records else ("fail" if mx_cname else "pass"),
            (
                "No MX to check."
                if not mx_records
                else (
                    "WARNING: CNAME was returned for MX hosts: "
                    + ", ".join(f"{h.rstrip('.')} → {mx_cname[h]}" for h in mx_cname)
                    + ". This is not ok per RFC 974, RFC 1034 §3.6.2, RFC 1912 §2.4, and RFC 2181 §10.3. Mail can be lost."
                    if mx_cname
                    else "OK. MX hosts are not CNAMEs."
                )
            ),
            [rfc_ref(974), rfc_ref(1034, "3.6.2"), rfc_ref(1912, "2.4"), rfc_ref(2181, "10.3")],
            {"cname": mx_cname},
        )
    )
    mx_checks.append(
        _item(
            "mx_not_ip",
            "MX is not IP",
            "fail" if mx_ip_literal else "pass" if mx_records else "info",
            (
                "ERROR. MX must be a hostname, not an address: " + ", ".join(mx_ip_literal)
                if mx_ip_literal
                else "OK. MX values are hostnames."
                if mx_records
                else "No MX to check."
            ),
            [rfc_ref(1035), rfc_ref(2181, "10.3")],
            {"literal": mx_ip_literal},
        )
    )
    if null_mx:
        mx_checks.append(
            _item(
                "mx_name",
                "MX A records",
                "info",
                "Null MX (RFC 7505): this domain does not accept mail, so MX needs no A/AAAA.",
                [rfc_ref(7505)],
                {"missing": []},
            )
        )
    else:
        mx_checks.append(
            _item(
                "mx_name",
                "MX A records",
                "fail" if mx_no_addr else "pass" if mx_records else "info",
                (
                    "ERROR. These MX hosts have no A/AAAA: " + ", ".join(h.rstrip(".") for h in mx_no_addr)
                    if mx_no_addr
                    else "OK. MX hosts resolve to addresses."
                    if mx_records
                    else "No MX to resolve."
                ),
                [rfc_ref(1035), rfc_ref(2181, "10.3"), rfc_ref(3596)],
                {"missing": mx_no_addr},
            )
        )
    mx_checks.append(
        _item(
            "mx_public",
            "MX IPs are public",
            "fail" if private_mx else "pass" if mx_ips else "info",
            (
                "ERROR. Private or non-global MX addresses: " + ", ".join(private_mx)
                if private_mx
                else "OK. MX addresses appear public."
                if mx_ips
                else "No MX addresses."
            ),
            [rfc_ref(1918)],
            {"private": private_mx, "ips": mx_ips},
        )
    )
    mx_checks.append(
        _item(
            "mx_duplicate_a",
            "Duplicate MX A",
            "warn" if dup_mx else "pass" if mx_records else "info",
            (
                "These IPs are shared by more than one MX hostname: "
                + "; ".join(f"{ip} → {hosts}" for ip, hosts in dup_mx.items())
                if dup_mx
                else "OK. MX hostnames do not collapse to the same IP."
                if mx_records
                else "No MX to compare."
            ),
            [rfc_ref(1912)],
            {"duplicates": dup_mx},
        )
    )
    mx_checks.append(
        _item(
            "mx_ptr",
            "Reverse MX A (PTR)",
            "fail" if missing_ptr else "pass" if mx_ips else "info",
            (
                "ERROR. No PTR for MX IPs: " + ", ".join(missing_ptr)
                if missing_ptr
                else "OK. MX IPs have PTR records."
                if mx_ips
                else "No MX IPs to reverse."
            )
            + (" RFC 1912 section 2.1: hosts that send mail should have PTRs." if mx_ips else ""),
            [rfc_ref(1912, "2.1"), rfc_ref(1912, "2.6.1")],
            {"ptr": ptr_map, "missing": missing_ptr},
        )
    )

    # ---- WWW ----
    www_checks: List[Dict[str, Any]] = []
    if www_ips or www_cnames:
        chain = " → ".join([www_name.rstrip(".")] + [c.rstrip(".") for c in www_cnames] + ([str(www_ips)] if www_ips else []))
        www_checks.append(
            _item(
                "www_a",
                "WWW A Record",
                "pass",
                f"www A/AAAA: {chain}" + (" [Looks like you have CNAME's]" if www_cnames else ""),
                [rfc_ref(1034), rfc_ref(3596)],
                {"name": www_name, "A": www_v4, "AAAA": www_v6, "cname": www_cnames},
            )
        )
    else:
        www_checks.append(
            _item(
                "www_a",
                "WWW A Record",
                "info",
                f"No A/AAAA for {www_name.rstrip('.')}.",
                [rfc_ref(1034), rfc_ref(3596)],
            )
        )
    www_checks.append(
        _item(
            "www_public",
            "IPs are public",
            "fail" if private_www else "pass" if www_ips else "info",
            (
                "ERROR. WWW addresses are not public: " + ", ".join(private_www)
                if private_www
                else "OK. All WWW IPs appear to be public."
                if www_ips
                else "No WWW IPs."
            ),
            [rfc_ref(1918)],
            {"private": private_www},
        )
    )
    www_checks.append(
        _item(
            "www_cname",
            "WWW CNAME",
            "pass" if www_cnames else "info",
            (
                "OK. You have a CNAME for www. The answer also returned address records."
                if www_cnames and www_ips
                else "OK. You have a CNAME for www."
                if www_cnames
                else "No CNAME for www; a plain A/AAAA is fine. CNAMEs are allowed here (unlike NS and MX)."
            ),
            [rfc_ref(1034), rfc_ref(1912, "2.4")],
            {"cname": www_cnames},
        )
    )

    # ---- Mail ----
    mail_checks: List[Dict[str, Any]] = []
    if null_mx:
        mail_checks.append(
            _item(
                "smtp",
                "Mail servers report",
                "info",
                "Null MX (RFC 7505); this domain does not accept mail.",
                [rfc_ref(7505), rfc_ref(5321)],
            )
        )
    elif not smtp_targets:
        mail_checks.append(
            _item(
                "smtp",
                "Mail servers report",
                "info",
                "No MX addresses to probe on port 25.",
                [rfc_ref(5321), rfc_ref(1123, "5.3.7")],
            )
        )
    else:
        talking = [p for p in mail_probes if p.get("ok")]
        quiet = [p for p in mail_probes if not p.get("ok")]
        if talking and not quiet:
            status, detail = "pass", "All probed mail exchangers answered SMTP on port 25."
        elif talking:
            status, detail = (
                "warn",
                f"{len(talking)} MX answered SMTP; {len(quiet)} did not (outbound 25 is often filtered from this host).",
            )
        else:
            status, detail = (
                "info",
                "Could not complete an SMTP banner from this host. Many networks block outbound port 25; that is not necessarily a zone error.",
            )
        lines = []
        for probe in mail_probes:
            banner = probe.get("banner") or probe.get("error") or "no response"
            lines.append(f"{probe.get('host', '').rstrip('.')} {probe.get('ip')}: {banner}")
        mail_checks.append(
            _item(
                "smtp",
                "Mail servers report",
                status,
                detail + " " + " | ".join(lines),
                [rfc_ref(5321), rfc_ref(1123, "5.3.7")],
                {"probes": mail_probes},
            )
        )

    sections = [
        _section("parent", "Parent", parent_checks),
        _section("ns", "NS", ns_checks),
        _section("soa", "SOA", soa_checks),
        _section("mx", "MX", mx_checks),
        _section("www", "WWW", www_checks),
        _section("mail", "Mail", mail_checks),
    ]
    summary = summarize(sections)
    result = {
        "domain": zone.rstrip("."),
        "parent": parent.rstrip(".") or ".",
        "summary": summary,
        "sections": sections,
        "standards": [
            {
                **row,
                "url": f"https://www.rfc-editor.org/rfc/rfc{row['rfc']}",
            }
            for row in STANDARDS
        ],
        "nameservers": {
            "parent": parent_ns,
            "child": child_ns,
            "ips": {k: v for k, v in ns_ips.items()},
        },
        "soa": soa,
        "mx": mx_records,
        "www": {"A": www_v4, "AAAA": www_v6, "cname": www_cnames},
    }
    return {
        "ok": True,
        "result": result,
        "error": None,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


def check_apex(name: str, **kwargs: Any) -> Dict[str, Any]:
    """Sync wrapper. Do not call from a running event loop."""
    return asyncio.run(check_apex_async(name, **kwargs))
