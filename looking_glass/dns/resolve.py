"""DNS lookup: IANA RR types plus a live query (dnspython).

`kdig +json` is not used. The public payload is a stable envelope with
answers/authority/additional records. Query types come from the IANA
dns-parameters registry (cached like the other datasets). Meta-types
(ANY, AXFR, OPT, …) are catalogued but rejected as lookups.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..net.host import reject_bogus_ipv4
from ..utility import (
    LogFn,
    ProgressFn,
    build_info,
    fetch_text,
    get_cache_path,
    load_json_cache,
    save_json_cache,
    safe_csv_rows,
)

IANA_DNS_TYPES_CSV = (
    "https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv"
)
CACHE_NAME = "dns_types.json"

# RFC 6895 meta-types plus the historic MAILB/MAILA names. Not lookups.
_META_NAMES = {
    "OPT",
    "TKEY",
    "TSIG",
    "IXFR",
    "AXFR",
    "MAILB",
    "MAILA",
    "ANY",
    "*",
}
_META_VALUES = {41, 249, 250, 251, 252, 253, 254, 255}
_EDNS_PAYLOAD = 4096
_DNSSEC_QTYPES = {
    "DS",
    "DNSKEY",
    "RRSIG",
    "NSEC",
    "NSEC3",
    "NSEC3PARAM",
    "CDS",
    "CDNSKEY",
    "TA",
    "DLV",
}

# Public names that currently publish these types. Tests and CLI help use them.
# DS/DNSKEY live at the zone apex, not at www.
DNS_TYPE_EXAMPLES: Dict[str, str] = {
    "A": "example.com",
    "AAAA": "example.com",
    "NS": "example.com",
    "MX": "example.com",
    "TXT": "example.com",
    "SOA": "example.com",
    "CNAME": "www.iana.org",
    "PTR": "1.1.1.1",
    "CAA": "cloudflare.com",
    "HTTPS": "cloudflare.com",
    "SVCB": "cloudflare.com",
    "DS": "example.com",
    "DNSKEY": "example.com",
    "NSEC": "example.com",
    "SRV": "_caldavs._tcp.google.com",
    "TLSA": "_443._tcp.www.cloudflare.com",
    "SSHFP": "gitlab.com",
    "NAPTR": "sip2sip.info",
}

_TYPE_NUM = re.compile(r"^TYPE(\d+)$")
_LABEL_OK = re.compile(r"^[A-Za-z0-9_*](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9*])?$")

_entries: List[Dict[str, Any]] = []
_by_name: Dict[str, Dict[str, Any]] = {}
_by_value: Dict[int, Dict[str, Any]] = {}
_fetched_at: int = 0
_built: bool = False


def _cache_path() -> str:
    return get_cache_path(CACHE_NAME)


def parse_dns_types_csv(text: str, source: str = IANA_DNS_TYPES_CSV) -> List[Dict[str, Any]]:
    """Parse IANA dns-parameters-4.csv into lookup-type entries."""
    rows = list(safe_csv_rows(text))
    if not rows:
        return []
    header = [h.strip() for h in rows[0]]
    idx = {name: i for i, name in enumerate(header)}
    i_name = idx.get("TYPE", 0)
    i_value = idx.get("Value", 1)
    i_meaning = idx.get("Meaning", 2)
    i_ref = idx.get("Reference", 3)
    i_reg = idx.get("Registration Date")

    entries: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows[1:]:
        if len(row) <= max(i_name, i_value):
            continue
        raw_name = (row[i_name] or "").strip()
        raw_value = (row[i_value] or "").strip()
        if not raw_name or not raw_value:
            continue
        lower = raw_name.lower()
        if lower.startswith(("unassigned", "reserved", "private")):
            continue
        if "-" in raw_value:
            continue
        try:
            value = int(raw_value)
        except ValueError:
            continue
        if value < 0 or value > 65535:
            continue
        name = "ANY" if raw_name == "*" else raw_name.upper()
        if name in seen:
            continue
        seen.add(name)
        meta = name in _META_NAMES or value in _META_VALUES
        entries.append(
            {
                "name": name,
                "value": value,
                "meaning": (row[i_meaning] if i_meaning is not None and len(row) > i_meaning else "").strip(),
                "reference": (row[i_ref] if i_ref is not None and len(row) > i_ref else "").strip(),
                "registration_date": (
                    row[i_reg].strip() if i_reg is not None and len(row) > i_reg else ""
                ),
                "meta": meta,
                "source": source,
            }
        )
    return entries


def _install(entries: List[Dict[str, Any]], fetched_at: int = 0) -> None:
    global _entries, _by_name, _by_value, _fetched_at, _built
    _entries = list(entries)
    _by_name = {e["name"]: e for e in _entries if e.get("name")}
    _by_value = {int(e["value"]): e for e in _entries if e.get("value") is not None}
    _fetched_at = int(fetched_at or 0)
    _built = True


def load(force: bool = False) -> bool:
    """Load the RR-type catalog from disk, or build it if missing."""
    if _built and not force:
        return True
    payload = load_json_cache(_cache_path())
    if payload and not force:
        entries = payload.get("entries") or []
        if entries:
            _install(entries, int(payload.get("_fetched_at", 0) or 0))
            return True
    return build(force=force)


def build(
    force: bool = False,
    log: Optional[LogFn] = None,
    progress: Optional[ProgressFn] = None,
) -> bool:
    """Fetch the IANA DNS RR-type CSV and cache it under ~/.looking-glass/data."""
    info = build_info("dns types build", log)
    path = _cache_path()
    if not force:
        payload = load_json_cache(path)
        if payload and payload.get("entries"):
            _install(payload["entries"], int(payload.get("_fetched_at", 0) or 0))
            info(f"using cached DNS types ({len(_entries)} entries)")
            return True

    info(f"GET {IANA_DNS_TYPES_CSV}")
    text = fetch_text(IANA_DNS_TYPES_CSV, progress=progress, log=log)
    if not text:
        info("download failed")
        return False
    entries = parse_dns_types_csv(text)
    if not entries:
        info("no RR types parsed")
        return False
    now = int(time.time())
    save_json_cache(path, {"_fetched_at": now, "entries": entries})
    _install(entries, now)
    info(f"wrote {len(entries)} RR types")
    return True


def get_fetched_at() -> int:
    return int(_fetched_at or 0)


def types(*, lookup_only: bool = True) -> List[Dict[str, Any]]:
    """IANA RR types. lookup_only drops ANY/AXFR/OPT and other meta-types."""
    _ensure_catalog()
    rows = list(_entries)
    if lookup_only:
        rows = [e for e in rows if not e.get("meta")]
    return rows


def _ensure_catalog() -> None:
    if _built:
        return
    payload = load_json_cache(_cache_path())
    if payload and payload.get("entries"):
        _install(payload["entries"], int(payload.get("_fetched_at", 0) or 0))


def canonicalize_qtype(qtype: Optional[str]) -> Dict[str, Any]:
    """Return {name, value} for a mnemonic, number, or TYPE#. Rejects meta-types."""
    raw = (qtype or "A").strip().upper()
    if not raw:
        raw = "A"
    if raw == "*":
        raw = "ANY"

    value: Optional[int] = None
    name: Optional[str] = None
    m = _TYPE_NUM.match(raw)
    if m:
        value = int(m.group(1))
    elif raw.isdigit():
        value = int(raw)
    else:
        name = raw

    _ensure_catalog()

    if value is not None:
        if value < 1 or value > 65534:
            raise ValueError(f"invalid qtype {qtype!r}")
        entry = _by_value.get(value)
        name = (entry or {}).get("name") or _rdatatype_name(value)
        meta = bool((entry or {}).get("meta")) or value in _META_VALUES
        if meta or name in _META_NAMES:
            raise ValueError(f"{name} is not a lookup type")
        return {"name": name, "value": value}

    entry = _by_name.get(name or "")
    if entry:
        if entry.get("meta") or entry["name"] in _META_NAMES:
            raise ValueError(f"{entry['name']} is not a lookup type")
        return {"name": entry["name"], "value": int(entry["value"])}

    parsed = _rdatatype_from_text(name or "")
    if parsed is None:
        raise ValueError(f"invalid qtype {qtype!r}")
    value, text_name = parsed
    if value in _META_VALUES or text_name in _META_NAMES:
        raise ValueError(f"{text_name} is not a lookup type")
    return {"name": text_name, "value": value}


def _rdatatype_from_text(name: str) -> Optional[Tuple[int, str]]:
    try:
        import dns.rdatatype
    except ImportError:
        return None
    try:
        value = int(dns.rdatatype.from_text(name))
        return value, dns.rdatatype.to_text(value)
    except Exception:
        return None


def _rdatatype_name(value: int) -> str:
    try:
        import dns.rdatatype

        return dns.rdatatype.to_text(value)
    except Exception:
        return f"TYPE{value}"


def normalize_qname(name: str, *, qtype: Optional[str] = None) -> str:
    """Absolute DNS name. IPs become PTR owners when qtype is PTR."""
    text = str(name).strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        text = text[1:-1]
    if not text:
        raise ValueError("empty name")
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        ip = None
    if ip is not None:
        want_ptr = (qtype or "A").strip().upper() in {"PTR", "12", "TYPE12"}
        if want_ptr:
            import dns.reversename

            return str(dns.reversename.from_address(str(ip)))
        raise ValueError("IP names require PTR (use /dns/<ip>/PTR)")

    text = text.rstrip(".")
    reject_bogus_ipv4(text)
    if not text or " " in text or ".." in text:
        raise ValueError("invalid domain name")
    labels = text.split(".")
    ascii_labels: List[str] = []
    for label in labels:
        if not label:
            raise ValueError("invalid domain name")
        if label == "*":
            ascii_labels.append("*")
            continue
        if label.startswith("_"):
            lowered = label.lower()
            if not _LABEL_OK.match(lowered):
                raise ValueError("invalid domain name")
            ascii_labels.append(lowered)
            continue
        try:
            encoded = label.encode("idna").decode("ascii")
        except Exception as exc:
            raise ValueError("invalid domain name") from exc
        if not encoded.startswith("xn--"):
            encoded = encoded.lower()
        if not _LABEL_OK.match(encoded) and not encoded.startswith("xn--"):
            raise ValueError("invalid domain name")
        ascii_labels.append(encoded)
    return ".".join(ascii_labels) + "."


def is_dns_name(name: str) -> bool:
    try:
        normalize_qname(name, qtype="A")
        return True
    except ValueError:
        return False


def parse_dns_path(path: str) -> Tuple[str, str]:
    """Parse /dns/<name> or /dns/<name>/<type> into (name, qtype)."""
    from urllib.parse import unquote

    text = unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "dns" and not text.startswith("dns/"):
        raise ValueError("not a dns path")
    rest = "" if text == "dns" else text[4:]
    if not rest:
        raise ValueError("dns path needs a name, e.g. /dns/example.com or /dns/example.com/AAAA")
    parts = rest.split("/")
    if len(parts) == 1 and parts[0]:
        return parts[0], "A"
    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1]
    raise ValueError("dns path is /dns/<name> or /dns/<name>/<type>")


def _rr_item(name: Any, rdtype: int, rdclass: int, ttl: int, rdata: Any) -> Dict[str, Any]:
    import dns.rdataclass
    import dns.rdatatype

    return {
        "name": str(name),
        "type": dns.rdatatype.to_text(rdtype),
        "class": dns.rdataclass.to_text(rdclass),
        "ttl": int(ttl),
        "data": rdata.to_text(),
    }


def records_from_section(section: Any) -> List[Dict[str, Any]]:
    """Every RR in a message section. An RRset like google.com/A is many rdata."""
    out: List[Dict[str, Any]] = []
    if section is None:
        return out
    for rrset in section:
        rdatas = list(getattr(rrset, "items", None) or rrset)
        for rr in rdatas:
            out.append(
                _rr_item(rrset.name, rrset.rdtype, rrset.rdclass, rrset.ttl, rr)
            )
    return out


def result_from_response(
    response: Any,
    *,
    qname: str,
    qtype: Dict[str, Any],
    status: str,
) -> Dict[str, Any]:
    return {
        "status": status,
        "name": qname,
        "qtype": qtype["name"],
        "qtype_value": qtype["value"],
        "answers": records_from_section(getattr(response, "answer", None)),
        "authority": records_from_section(getattr(response, "authority", None)),
        "additional": records_from_section(getattr(response, "additional", None)),
    }


def _payload(
    *,
    ok: bool,
    qname: str,
    qtype: Dict[str, Any],
    result: Optional[Dict[str, Any]],
    error: Optional[str] = None,
    total_ms: float = 0.0,
) -> Dict[str, Any]:
    return {
        "ok": ok,
        "name": qname,
        "qtype": qtype["name"],
        "result": result,
        "error": error,
        "total_ms": round(total_ms, 3),
    }


def system_resolver_targets(port: Optional[int] = None) -> List[Tuple[str, int]]:
    """Nameserver (ip, port) pairs from resolv.conf / the OS resolver.

    No public recursor is substituted. An empty list means none are configured.
    Duplicate addresses from resolv.conf are dropped.
    """
    try:
        import dns.resolver
    except ImportError:
        return []
    resolver = dns.resolver.Resolver(configure=True)
    ports_map = getattr(resolver, "nameserver_ports", None) or {}
    out: List[Tuple[str, int]] = []
    seen = set()
    for ns in list(resolver.nameservers or []):
        host = str(ns)
        if port is not None:
            ns_port = int(port)
        else:
            ns_port = int(ports_map.get(ns, ports_map.get(host, 53)))
        if not 1 <= ns_port <= 65535:
            continue
        key = (host, ns_port)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def resolver_targets(
    server: Optional[str] = None, port: Optional[int] = None
) -> List[Tuple[str, int]]:
    """Explicit nameserver, or the system resolver from resolv.conf."""
    text = (server or "").strip()
    if text:
        host, ns_port = parse_nameserver(text, port)
        if not host:
            raise ValueError("nameserver must be an IP address")
        return [(host, ns_port)]
    return system_resolver_targets(port)


def _port_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise ValueError("nameserver port must be 1–65535") from None
    if not 1 <= value <= 65535:
        raise ValueError("nameserver port must be 1–65535")
    return value


def _split_host_port(text: str) -> Tuple[str, Optional[int]]:
    """Split `1.1.1.1:5353` or `[2001:db8::1]:53` into (host, port or None)."""
    text = text.strip()
    if text.startswith("["):
        close = text.find("]")
        if close < 2:
            raise ValueError("nameserver must be an IP address")
        host = text[1:close]
        rest = text[close + 1 :]
        if not rest:
            return host, None
        if not rest.startswith(":"):
            raise ValueError("nameserver must be an IP address")
        return host, _port_int(rest[1:])
    if text.count(":") == 1:
        host, _, port_s = text.partition(":")
        if host and port_s:
            try:
                ipaddress.IPv4Address(host)
            except ValueError:
                raise ValueError("nameserver must be an IP address") from None
            return host, _port_int(port_s)
    try:
        ipaddress.ip_address(text)
    except ValueError:
        raise ValueError("nameserver must be an IP address") from None
    return text, None


def parse_nameserver(
    server: Optional[str] = None,
    port: Optional[int] = None,
) -> Tuple[Optional[str], int]:
    """Return `(ip or None, port)`. Accepts IP, `IP:port`, or `[IPv6]:port`.

    An explicit `port` overrides a port encoded in `server`. Default is 53.
    """
    ns_port = 53
    host: Optional[str] = None
    text = (server or "").strip()
    if text.startswith("@"):
        text = text[1:].strip()
    if text:
        parsed_host, parsed_port = _split_host_port(text)
        host = str(ipaddress.ip_address(parsed_host))
        if parsed_port is not None:
            ns_port = parsed_port
    if port is not None:
        ns_port = int(port)
    if not 1 <= ns_port <= 65535:
        raise ValueError("nameserver port must be 1–65535")
    return host, ns_port


async def _query(
    qname: str,
    rdtype: Any,
    timeout: float,
    server: Optional[str],
    *,
    port: Optional[int] = None,
) -> Tuple[Optional[Any], str, Optional[str]]:
    """UDP then TCP (on TC). Returns the full wire message, every RR."""
    import dns.asyncquery
    import dns.exception
    import dns.message
    import dns.rcode
    import dns.rdatatype

    last_error: Optional[str] = None
    last_refused: Optional[Any] = None
    try:
        targets = resolver_targets(server, port)
    except ValueError as exc:
        return None, "ERROR", str(exc)
    if not targets:
        return None, "ERROR", "no nameservers"
    try:
        qtype_name = dns.rdatatype.to_text(rdtype)
    except Exception:
        qtype_name = ""
    want_dnssec = qtype_name in _DNSSEC_QTYPES
    for ns, ns_port in targets:
        q = dns.message.make_query(
            qname,
            rdtype,
            use_edns=0,
            payload=_EDNS_PAYLOAD,
            want_dnssec=want_dnssec,
        )
        try:
            response, _truncated = await dns.asyncquery.udp_with_fallback(
                q, ns, timeout=timeout, port=ns_port
            )
        except (dns.exception.Timeout, asyncio.TimeoutError):
            last_error = "timeout"
            continue
        except OSError as exc:
            last_error = str(exc) or "no nameservers"
            continue
        except Exception as exc:
            last_error = str(exc) or exc.__class__.__name__
            continue
        status = dns.rcode.to_text(response.rcode())
        if status == "NXDOMAIN":
            return response, "NXDOMAIN", None
        if status == "SERVFAIL":
            # Validating resolvers (Unbound) SERVFAIL bogus names. That is the
            # answer; do not skip to another nameserver.
            return response, "SERVFAIL", None
        if status == "REFUSED":
            last_error = "REFUSED"
            last_refused = response
            continue
        return response, status, None
    if last_refused is not None:
        return last_refused, "REFUSED", None
    return None, "ERROR", last_error or "no nameservers"


async def lookup_dns_async(
    name: str,
    qtype: Optional[str] = None,
    *,
    timeout: float = 5.0,
    server: Optional[str] = None,
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """Look up `name`/`qtype` and return the JSON envelope."""
    start = time.time()
    qtype_info = canonicalize_qtype(qtype)
    qname = normalize_qname(name, qtype=qtype_info["name"])
    if server:
        nameserver, ns_port = parse_nameserver(server, port)
    else:
        nameserver, ns_port = None, port
    try:
        import dns.rdatatype
    except ImportError:
        return _payload(
            ok=False,
            qname=qname,
            qtype=qtype_info,
            result=None,
            error="dnspython is required for DNS lookups",
            total_ms=(time.time() - start) * 1000.0,
        )
    rdtype = dns.rdatatype.from_text(qtype_info["name"])
    response, status, error = await _query(
        qname, rdtype, timeout, nameserver, port=ns_port
    )
    elapsed = (time.time() - start) * 1000.0
    if error:
        return _payload(
            ok=False,
            qname=qname,
            qtype=qtype_info,
            result=None,
            error=error,
            total_ms=elapsed,
        )
    if response is None:
        result = {
            "status": status,
            "name": qname,
            "qtype": qtype_info["name"],
            "qtype_value": qtype_info["value"],
            "answers": [],
            "authority": [],
            "additional": [],
        }
        servfail = status == "SERVFAIL"
        return _payload(
            ok=not servfail,
            qname=qname,
            qtype=qtype_info,
            result=result,
            error="SERVFAIL" if servfail else None,
            total_ms=elapsed,
        )
    result = result_from_response(response, qname=qname, qtype=qtype_info, status=status)
    servfail = status == "SERVFAIL"
    return _payload(
        ok=not servfail,
        qname=qname,
        qtype=qtype_info,
        result=result,
        error="SERVFAIL" if servfail else None,
        total_ms=elapsed,
    )


def lookup_dns(
    name: str,
    qtype: Optional[str] = None,
    *,
    timeout: float = 5.0,
    server: Optional[str] = None,
    port: Optional[int] = None,
) -> Dict[str, Any]:
    """Sync wrapper for lookup_dns_async. Do not call from a running event loop."""
    return asyncio.run(
        lookup_dns_async(name, qtype, timeout=timeout, server=server, port=port)
    )
