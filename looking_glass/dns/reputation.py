"""RFC 5782 DNSBL checks for IP reputation.

Queries A and TXT in parallel. NXDOMAIN is allowed, 127.0.0.0/8 is a listing,
127.255.255.0/24 is a query error, and anything else is treated as DNS interference.

Status is a single string:
  drop     — Spamhaus DROP (do not route)
  blocked  — SBL / CSS / XBL / BCL, or any other DNSBL hit
  policy   — Spamhaus PBL only (end-user / dynamic range)
  allowed  — not listed
  unknown  — the query failed
  skipped  — zone does not apply (IPv4-only list vs IPv6)

Results are cached under ~/.looking-glass/data/cache/rbl for 24 hours. Pass force=True to bypass.
Spamhaus ZEN uses a DQS key when SPAMHAUS_DQS_KEY or LOOKING_GLASS_SPAMHAUS_DQS_KEY is set.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import sys
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..cache import layout_dir
from ..utility import load_json_cache, save_json_cache
from .resolve import system_resolver_targets

LISTED_NET = ipaddress.ip_network("127.0.0.0/8")
ERROR_NET = ipaddress.ip_network("127.255.255.0/24")
CACHE_TTL_S = 24 * 60 * 60

QUERY_ERROR_CODES: Dict[str, str] = {
    "127.255.255.250": "DQS key disabled",
    "127.255.255.251": "DQS key used incorrectly",
    "127.255.255.252": "DNSBL name error",
    "127.255.255.254": "query via public resolver; use a recursive resolver or a Spamhaus DQS key",
    "127.255.255.255": "excessive queries",
}

# Highest first. DROP outranks a generic block; PBL alone is policy, not blocked.
STATUS_RANK = {
    "drop": 5,
    "blocked": 4,
    "policy": 3,
    "unknown": 2,
    "allowed": 1,
    "skipped": 0,
}

FLAG_STATUS: Dict[str, str] = {
    "DROP": "drop",
    "SBL": "blocked",
    "CSS": "blocked",
    "XBL": "blocked",
    "BCL": "blocked",
    "PBL": "policy",
}

DOMAIN_PROVIDERS: List[Dict[str, Any]] = [
    {
        "name": "Spamhaus DBL",
        "dnsbl": "dbl.spamhaus.org",
        "dqs": "{key}.dbl.dq.spamhaus.net",
        "codes": {
            "127.0.1.2": "spam",
            "127.0.1.4": "phish",
            "127.0.1.5": "malware",
            "127.0.1.6": "botnet",
            "127.0.1.102": "abused legit spam",
            "127.0.1.103": "abused redirector",
            "127.0.1.104": "abused legit phish",
            "127.0.1.105": "abused legit malware",
            "127.0.1.106": "abused legit botnet",
        },
    },
    {
        "name": "SURBL multi",
        "dnsbl": "multi.surbl.org",
        "codes": {"127.0.0.2": "listed"},
    },
    {
        "name": "URIBL multi",
        "dnsbl": "multi.uribl.com",
        "codes": {
            "127.0.0.2": "black",
            "127.0.0.4": "grey",
            "127.0.0.8": "red",
        },
    },
    {
        "name": "Mailspike domain",
        "dnsbl": "dbl.mailspike.net",
        "codes": {"127.0.0.2": "listed"},
    },
]


RBL_PROVIDERS: List[Dict[str, Any]] = [
    {
        "name": "Spamhaus ZEN",
        "dnsbl": "zen.spamhaus.org",
        "dqs": "{key}.zen.dq.spamhaus.net",
        "ip_versions": (4, 6),
        "codes": {
            "127.0.0.2": "SBL",
            "127.0.0.3": "CSS",
            "127.0.0.4": "XBL",
            "127.0.0.9": "DROP",
            "127.0.0.10": "PBL",
            "127.0.0.11": "PBL",
            "127.0.0.30": "BCL",
        },
    },
    {
        "name": "Barracuda BRBL",
        "dnsbl": "b.barracudacentral.org",
        "ip_versions": (4,),
        "codes": {"127.0.0.2": "listed"},
    },
    {
        "name": "SpamCop",
        "dnsbl": "bl.spamcop.net",
        "ip_versions": (4,),
        "codes": {"127.0.0.2": "listed"},
    },
    {
        "name": "Mailspike",
        "dnsbl": "bl.mailspike.net",
        "ip_versions": (4,),
        "codes": {
            "127.0.0.2": "listed",
            "127.0.0.10": "worst",
            "127.0.0.11": "bad",
            "127.0.0.12": "untrustworthy",
        },
    },
    {
        "name": "DroneBL",
        "dnsbl": "dnsbl.dronebl.org",
        "ip_versions": (4, 6),
        "codes": {
            "127.0.0.3": "IRC drone",
            "127.0.0.5": "bottler",
            "127.0.0.6": "unknown spam drone",
            "127.0.0.7": "DDoS drone",
            "127.0.0.8": "SOCKS proxy",
            "127.0.0.9": "HTTP proxy",
            "127.0.0.10": "proxychain",
            "127.0.0.13": "automated dictionary attack",
            "127.0.0.14": "FTPd abuse",
            "127.0.0.15": "relay",
            "127.0.0.17": "automated complaint",
            "127.0.0.19": "abusive DNS",
        },
    },
    {
        "name": "PSBL",
        "dnsbl": "psbl.surriel.com",
        "ip_versions": (4,),
        "codes": {"127.0.0.2": "listed"},
    },
    {
        "name": "SORBS",
        "dnsbl": "dnsbl.sorbs.net",
        "ip_versions": (4,),
        "codes": {
            "127.0.0.2": "http",
            "127.0.0.3": "socks",
            "127.0.0.4": "misc",
            "127.0.0.5": "smtp",
            "127.0.0.6": "spam",
            "127.0.0.7": "web",
            "127.0.0.8": "block",
            "127.0.0.9": "zombie",
            "127.0.0.10": "dul",
            "127.0.0.11": "badconf",
            "127.0.0.12": "noserver",
        },
    },
]


def spamhaus_dqs_key() -> Optional[str]:
    key = os.environ.get("LOOKING_GLASS_SPAMHAUS_DQS_KEY") or os.environ.get("SPAMHAUS_DQS_KEY")
    if key:
        key = key.strip()
    return key or None


def reverse_for_dnsbl(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    obj = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(ip)
    if obj.version == 4:
        return ".".join(reversed(obj.exploded.split(".")))
    return ".".join(reversed(obj.exploded.replace(":", "")))


def _zone_for_provider(provider: Mapping[str, Any]) -> str:
    template = provider.get("dqs")
    key = spamhaus_dqs_key()
    if template and key:
        return str(template).format(key=key).rstrip(".")
    return str(provider["dnsbl"]).rstrip(".")


def default_rbl_map(ip_version: int) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for provider in RBL_PROVIDERS:
        versions = tuple(provider.get("ip_versions") or (4, 6))
        if ip_version not in versions:
            continue
        out[str(provider["name"])] = _zone_for_provider(provider)
    return out


def _provider_zone_aliases(provider: Mapping[str, Any]) -> List[str]:
    names = [str(provider["dnsbl"]).rstrip(".").lower()]
    dqs = provider.get("dqs")
    if dqs:
        tail = str(dqs).split("}", 1)[-1].lstrip(".").rstrip(".").lower()
        if tail:
            names.append(tail)
    return names


def _codes_for_zone(zone: str) -> Dict[str, str]:
    needle = zone.lower().rstrip(".")
    for provider in (*RBL_PROVIDERS, *DOMAIN_PROVIDERS):
        for name in _provider_zone_aliases(provider):
            if needle == name or needle.endswith("." + name):
                return dict(provider.get("codes") or {})
    return {}


def default_domain_map() -> Dict[str, str]:
    out: Dict[str, str] = {}
    for provider in DOMAIN_PROVIDERS:
        out[str(provider["name"])] = _zone_for_provider(provider)
    return out


def classify_a_records(addresses: Sequence[str]) -> Tuple[str, List[str], Optional[str]]:
    """Return (dns_class, listing_addresses, error) for RFC 5782 A answers.

    dns_class is listed, clean, or error (not the public verdict string).
    A 127.255.255.0/24 query error outranks any listing code in the same answer.
    """
    listed: List[str] = []
    errors: List[str] = []
    hijack: List[str] = []
    for raw in addresses:
        try:
            addr = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            hijack.append(raw)
            continue
        if addr in ERROR_NET or str(addr) == "127.0.0.1":
            errors.append(str(addr))
        elif addr in LISTED_NET:
            listed.append(str(addr))
        else:
            hijack.append(str(addr))
    if hijack:
        return "error", [], f"non-127/8 DNSBL answer (interceptor?): {', '.join(hijack)}"
    if errors:
        reasons = [QUERY_ERROR_CODES.get(a, a) for a in errors]
        return "error", [], "; ".join(reasons)
    if listed:
        return "listed", listed, None
    return "clean", [], None


def query_error_from_txt(txt: Sequence[str] | None) -> Optional[str]:
    """Spamhaus (and similar) TXT that means the query failed, not a listing."""
    blob = " ".join(str(line) for line in (txt or [])).lower()
    if not blob:
        return None
    if "open resolver" in blob or "returnc/pub/" in blob:
        return "query via public resolver; use a recursive resolver or a Spamhaus DQS key"
    if "returnc/vol/" in blob:
        return "excessive queries"
    if "query refused" in blob or "uribl.com/refused" in blob:
        return "query refused"
    return None


def status_from_flags(flags: Sequence[str], *, query_status: str) -> str:
    """Map listing flags to drop / blocked / policy / allowed / unknown / skipped."""
    if query_status == "skipped":
        return "skipped"
    if query_status == "error":
        return "unknown"
    if query_status == "clean" or not flags:
        return "allowed"
    best = "blocked"
    best_rank = -1
    for flag in flags:
        token = str(flag).split()[0].upper()
        verdict = FLAG_STATUS.get(token, "blocked")
        rank = STATUS_RANK[verdict]
        if rank > best_rank:
            best, best_rank = verdict, rank
    return best


def overall_status(results: Mapping[str, Any]) -> str:
    best = "allowed"
    best_rank = STATUS_RANK[best]
    for info in results.values():
        if not isinstance(info, dict):
            continue
        verdict = str(info.get("status") or "unknown")
        rank = STATUS_RANK.get(verdict, STATUS_RANK["unknown"])
        if rank > best_rank:
            best, best_rank = verdict, rank
    return best


def explain(rbl: Mapping[str, Any] | None) -> str:
    """Human-readable ban reason from an RBL payload."""
    if not rbl:
        return "reputation"
    status = str(rbl.get("status") or "unknown")
    flags = [str(flag) for flag in (rbl.get("flags") or []) if flag]
    listed_on = [str(name) for name in (rbl.get("listed_on") or []) if name]
    txt = [str(line) for line in (rbl.get("txt") or []) if line]
    parts = [f"reputation {status}"]
    if flags:
        parts.append("flags " + ", ".join(flags))
    if listed_on:
        parts.append("on " + ", ".join(listed_on))
    if txt:
        parts.append(txt[0])
    return "; ".join(parts)


def verdict_action(rbl: Mapping[str, Any] | None) -> Optional[str]:
    """block / challenge when the IP is actually listed; otherwise None."""
    if not isinstance(rbl, dict) or not rbl.get("ok") or not rbl.get("listed"):
        return None
    if query_error_from_txt(rbl.get("txt") or []):
        return None
    status = str(rbl.get("status") or "")
    if status in {"drop", "blocked"}:
        return "block"
    if status == "policy":
        return "challenge"
    return None


def _cache_path(query: str, zones: Mapping[str, str]) -> str:
    blob = json.dumps({"q": query, "zones": dict(zones)}, sort_keys=True)
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]
    return os.path.join(layout_dir("rbl"), f"{digest}.json")


def _read_cache(path: str, now: float) -> Optional[Dict[str, Any]]:
    data = load_json_cache(path)
    if not isinstance(data, dict):
        return None
    expires = data.get("expires_at")
    payload = data.get("payload")
    if not isinstance(expires, (int, float)) or expires <= now:
        return None
    if not isinstance(payload, dict) or not payload.get("ok"):
        return None
    if query_error_from_txt(payload.get("txt") or []):
        return None
    out = dict(payload)
    out["cached"] = True
    return out


def _write_cache(path: str, payload: Dict[str, Any], now: float) -> None:
    save_json_cache(
        path,
        {
            "fetched_at": int(now),
            "expires_at": int(now + CACHE_TTL_S),
            "payload": payload,
        },
    )


async def _resolve_rr(
    name: str, rdtype: str, timeout: float, resolver: Any = None
) -> Tuple[List[str], Optional[str]]:
    try:
        import dns.asyncresolver
        import dns.exception
        import dns.resolver
    except ImportError:
        return [], "dnspython is required for RBL checks"

    if resolver is None:
        resolver = dns_resolver(timeout)
        if resolver is None:
            return [], "dnspython is required for RBL checks"
    try:
        answer = await resolver.resolve(name, rdtype, lifetime=timeout)
        texts = [rr.to_text().strip().strip('"') for rr in answer]
        return texts, None
    except dns.resolver.NXDOMAIN:
        return [], None
    except dns.resolver.NoAnswer:
        return [], None
    except dns.resolver.NoNameservers as exc:
        return [], str(exc) or "no nameservers"
    except (dns.exception.Timeout, asyncio.TimeoutError):
        return [], "timeout"
    except Exception as exc:
        return [], str(exc) or exc.__class__.__name__


def _empty_item(query: str, *, status: str, error: Optional[str] = None) -> Dict[str, Any]:
    return {
        "status": status,
        "listed": False,
        "flags": [],
        "addresses": [],
        "codes": [],
        "txt": [],
        "error": error,
        "query": query,
    }


async def _check_one(
    name: str,
    zone: str,
    rev: str,
    timeout: float,
    *,
    skip_reason: Optional[str] = None,
    resolver: Any = None,
) -> Dict[str, Any]:
    query = f"{rev}.{zone}".rstrip(".")
    if skip_reason:
        return _empty_item(query, status="skipped", error=skip_reason)

    (addrs, a_err), (txt, _txt_err) = await asyncio.gather(
        _resolve_rr(query, "A", timeout, resolver),
        _resolve_rr(query, "TXT", timeout, resolver),
    )
    item = _empty_item(query, status="allowed")
    item["txt"] = txt or []
    txt_err = query_error_from_txt(txt)
    if a_err:
        item["status"] = "unknown"
        item["error"] = a_err
        return item
    if txt_err:
        item["status"] = "unknown"
        item["error"] = txt_err
        return item

    dns_class, listed_addrs, class_err = classify_a_records(addrs)
    item["addresses"] = listed_addrs
    item["error"] = class_err
    if dns_class == "error":
        item["status"] = "unknown"
        return item
    if dns_class == "clean":
        item["status"] = "allowed"
        return item

    codes_map = _codes_for_zone(zone)
    codes = [{"address": addr, "reason": codes_map.get(addr) or "listed"} for addr in listed_addrs]
    flags = [c["reason"] for c in codes]
    item["listed"] = True
    item["codes"] = codes
    item["flags"] = flags
    item["status"] = status_from_flags(flags, query_status="listed")
    return item


async def check_rbls_async(
    ip: str,
    rbls: Mapping[str, str] | None = None,
    timeout: float = 2.0,
    resolver: Any = None,
) -> Dict[str, Any]:
    """Check an IPv4 or IPv6 address against DNSBLs (no cache)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "invalid ip", "ip": ip, "status": "unknown"}

    rev = reverse_for_dnsbl(ip_obj)
    auto = rbls is None or not rbls
    if auto:
        rbls = default_rbl_map(ip_obj.version)

    names: List[str] = []
    tasks = []
    for name, domain in rbls.items():
        names.append(name)
        tasks.append(_check_one(name, domain, rev, timeout, resolver=resolver))
    if auto:
        for provider in RBL_PROVIDERS:
            name = str(provider["name"])
            if name in rbls:
                continue
            versions = tuple(provider.get("ip_versions") or (4, 6))
            if ip_obj.version not in versions:
                names.append(name)
                tasks.append(
                    _check_one(
                        name,
                        str(provider["dnsbl"]),
                        rev,
                        timeout,
                        skip_reason="IPv4-only zone",
                        resolver=resolver,
                    )
                )

    resolved = await asyncio.gather(*tasks, return_exceptions=True)
    results: Dict[str, Any] = {}
    for name, res in zip(names, resolved):
        if isinstance(res, Exception):
            query = f"{rev}.{rbls.get(name, '')}".rstrip(".")
            results[name] = _empty_item(query, status="unknown", error=str(res))
        else:
            results[name] = res

    flags: List[str] = []
    txt: List[str] = []
    seen_txt = set()
    for info in results.values():
        for flag in info.get("flags") or []:
            if flag not in flags:
                flags.append(flag)
        for line in info.get("txt") or []:
            if line not in seen_txt:
                seen_txt.add(line)
                txt.append(line)

    listed_on = [name for name, info in results.items() if info.get("listed")]
    errors = sum(1 for info in results.values() if info.get("status") == "unknown")
    now = time.time()
    sender = await lookup_sender_score(str(ip_obj), timeout=timeout, resolver=resolver)
    return {
        "ok": True,
        "ip": str(ip_obj),
        "status": overall_status(results),
        "flags": flags,
        "txt": txt,
        "listed": bool(listed_on),
        "listed_on": listed_on,
        "errors": errors,
        "cached": False,
        "fetched_at": int(now),
        "expires_at": int(now + CACHE_TTL_S),
        "resolver": resolver_snapshot(),
        "sender_score": sender,
        "result": results,
    }


def _normalize_domain(name: str) -> str:
    from .resolve import normalize_qname

    return normalize_qname(name, qtype="A").rstrip(".")


def _summarize_lists(results: Mapping[str, Any]) -> Tuple[List[str], List[str], List[str], int]:
    flags: List[str] = []
    txt: List[str] = []
    seen_txt = set()
    for info in results.values():
        for flag in info.get("flags") or []:
            if flag not in flags:
                flags.append(flag)
        for line in info.get("txt") or []:
            if line not in seen_txt:
                seen_txt.add(line)
                txt.append(line)
    listed_on = [name for name, info in results.items() if info.get("listed")]
    errors = sum(1 for info in results.values() if info.get("status") == "unknown")
    return flags, txt, listed_on, errors


async def check_domain_async(
    name: str,
    rbls: Mapping[str, str] | None = None,
    timeout: float = 2.0,
    resolver: Any = None,
) -> Dict[str, Any]:
    """Check a domain against URI/domain blocklists (no cache)."""
    try:
        domain = _normalize_domain(name)
    except ValueError as e:
        return {"ok": False, "error": str(e), "domain": name, "status": "unknown"}

    if rbls is None or not rbls:
        rbls = default_domain_map()

    names: List[str] = []
    tasks = []
    for list_name, zone in rbls.items():
        names.append(list_name)
        tasks.append(_check_one(list_name, zone, domain, timeout, resolver=resolver))

    resolved = await asyncio.gather(*tasks, return_exceptions=True)
    results: Dict[str, Any] = {}
    for list_name, res in zip(names, resolved):
        if isinstance(res, Exception):
            query = f"{domain}.{rbls.get(list_name, '')}".rstrip(".")
            results[list_name] = _empty_item(query, status="unknown", error=str(res))
        else:
            results[list_name] = res

    flags, txt, listed_on, errors = _summarize_lists(results)
    now = time.time()
    return {
        "ok": True,
        "domain": domain,
        "status": overall_status(results),
        "flags": flags,
        "txt": txt,
        "listed": bool(listed_on),
        "listed_on": listed_on,
        "errors": errors,
        "cached": False,
        "fetched_at": int(now),
        "expires_at": int(now + CACHE_TTL_S),
        "resolver": resolver_snapshot(),
        "sender_score": None,
        "result": results,
    }


async def check_domain_cached_async(
    name: str,
    rbls: Mapping[str, str] | None = None,
    timeout: float = 2.0,
    *,
    force: bool = False,
    resolver: Any = None,
) -> Dict[str, Any]:
    try:
        domain = _normalize_domain(name)
    except ValueError as e:
        return {"ok": False, "domain": name, "error": str(e), "status": "unknown"}

    zones = dict(rbls) if rbls else default_domain_map()
    path = _cache_path(f"domain:{domain}", zones)
    now = time.time()
    if not force:
        cached = _read_cache(path, now)
        if cached is not None:
            return cached
    try:
        out = await check_domain_async(
            domain, rbls=rbls, timeout=timeout, resolver=resolver
        )
    except Exception as e:
        return {"ok": False, "domain": domain, "error": str(e), "status": "unknown"}
    if out.get("ok") and out.get("errors", 0) == 0:
        _write_cache(path, out, now)
    return out


def check_domain(
    name: str,
    rbls: Mapping[str, str] | None = None,
    timeout: float = 2.0,
    *,
    force: bool = False,
) -> Dict[str, Any]:
    try:
        domain = _normalize_domain(name)
    except ValueError as e:
        return {"ok": False, "domain": name, "error": str(e), "status": "unknown"}

    zones = dict(rbls) if rbls else default_domain_map()
    path = _cache_path(f"domain:{domain}", zones)
    now = time.time()
    if not force:
        cached = _read_cache(path, now)
        if cached is not None:
            return cached

    try:
        out = asyncio.run(check_domain_async(domain, rbls=rbls, timeout=timeout))
    except Exception as e:
        return {"ok": False, "domain": domain, "error": str(e), "status": "unknown"}

    if out.get("ok") and out.get("errors", 0) == 0:
        _write_cache(path, out, now)
    return out


def resolver_snapshot() -> List[str]:
    """Nameservers reputation queries actually use (resolv.conf, never a public fallback)."""
    return [f"{host}:{port}" for host, port in system_resolver_targets()]


async def lookup_sender_score(
    ip: str, timeout: float = 2.0, resolver: Any = None
) -> Dict[str, Any]:
    """Validity Sender Score (0–100) via score.senderscore.com, SpamAssassin-style."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "invalid ip", "score": None, "query": None}
    if ip_obj.version != 4:
        return {
            "ok": False,
            "error": "Sender Score is IPv4-only",
            "score": None,
            "query": None,
        }
    rev = reverse_for_dnsbl(ip_obj)
    query = f"{rev}.score.senderscore.com"
    addrs, err = await _resolve_rr(query, "A", timeout, resolver)
    if err:
        return {"ok": False, "error": err, "score": None, "query": query}
    for addr in addrs:
        try:
            parsed = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            continue
        if parsed.version == 4 and parsed in ERROR_NET:
            return {
                "ok": False,
                "error": "no score in answer",
                "score": None,
                "query": query,
                "answer": str(parsed),
            }
        if parsed.version == 4 and str(parsed).startswith("127.0.4."):
            score = int(str(parsed).rsplit(".", 1)[-1])
            if 0 <= score <= 100:
                return {
                    "ok": True,
                    "error": None,
                    "score": score,
                    "query": query,
                    "answer": str(parsed),
                }
            return {
                "ok": False,
                "error": "no score in answer",
                "score": None,
                "query": query,
                "answer": str(parsed),
            }
    return {"ok": False, "error": "no score in answer", "score": None, "query": query, "answers": addrs}


def dns_resolver(timeout: float = 2.0) -> Any:
    """Shared async resolver using resolv.conf. None if dnspython is missing."""
    try:
        import dns.asyncresolver
    except ImportError:
        return None
    resolver = dns.asyncresolver.Resolver(configure=True)
    targets = system_resolver_targets()
    if targets:
        nameservers: List[str] = []
        ports: Dict[str, int] = {}
        for host, ns_port in targets:
            if host not in ports:
                nameservers.append(host)
                ports[host] = ns_port
        resolver.nameservers = nameservers
        resolver.nameserver_ports = ports
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 2.0)
    return resolver


async def check_rbl_cached_async(
    ip: str,
    rbls: Mapping[str, str] | None = None,
    timeout: float = 2.0,
    *,
    force: bool = False,
    resolver: Any = None,
) -> Dict[str, Any]:
    """Cached RBL check for a single IP. Safe to call concurrently."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "ip": ip, "error": "invalid ip", "status": "unknown"}

    zones = dict(rbls) if rbls else default_rbl_map(ip_obj.version)
    path = _cache_path(str(ip_obj), zones)
    now = time.time()
    if not force:
        cached = _read_cache(path, now)
        if cached is not None:
            return cached
    try:
        out = await check_rbls_async(
            str(ip_obj), rbls=rbls, timeout=timeout, resolver=resolver
        )
    except Exception as e:
        return {"ok": False, "ip": str(ip_obj), "error": str(e), "status": "unknown"}
    if out.get("ok") and out.get("errors", 0) == 0:
        _write_cache(path, out, now)
    return out


def check_rbls(
    ip: str,
    rbls: Mapping[str, str] | None = None,
    timeout: float = 2.0,
    *,
    force: bool = False,
) -> Dict[str, Any]:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "ip": ip, "error": "invalid ip", "status": "unknown"}

    zones = dict(rbls) if rbls else default_rbl_map(ip_obj.version)
    path = _cache_path(str(ip_obj), zones)
    now = time.time()
    if not force:
        cached = _read_cache(path, now)
        if cached is not None:
            return cached

    try:
        out = asyncio.run(check_rbls_async(str(ip_obj), rbls=rbls, timeout=timeout))
    except Exception as e:
        return {"ok": False, "ip": str(ip_obj), "error": str(e), "status": "unknown"}

    if out.get("ok") and out.get("errors", 0) == 0:
        _write_cache(path, out, now)
    return out


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(prog="python -m looking_glass.dns.reputation")
    p.add_argument("ip", help="IP address to check (IPv4 or IPv6)")
    p.add_argument("--timeout", type=float, default=2.0, help="per-check DNS timeout seconds")
    p.add_argument("--force", action="store_true", help="bypass the 24-hour cache")
    args = p.parse_args(argv)

    out = check_rbls(args.ip, timeout=args.timeout, force=args.force)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if not out.get("ok"):
        raise SystemExit(2)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
