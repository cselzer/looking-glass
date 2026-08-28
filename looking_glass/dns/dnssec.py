"""DNSSEC chain of trust, DNSViz-style.

Walks from the IANA root trust anchors to the queried name. Each zone
records DS (from the parent), DNSKEY, and whether RRSIGs validate.
Unsigned delegations are insecure, not broken. A DS that does not match
the child KSK, or a failed RRSIG, is bogus — that zone is where the
chain breaks.

RFCs 4033–4035, 5155 (NSEC3), 6781, 9718 (root trust anchors).
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote

from .apex import _EDNS_PAYLOAD
from .resolve import normalize_qname, resolver_targets

QueryFn = Callable[..., Awaitable[Tuple[Optional[Any], Optional[str]]]]

# IANA root-anchors.xml (RFC 9718). KSK-2017 active; KSK-2024 pre-published.
ROOT_TRUST_ANCHORS: Tuple[Dict[str, Any], ...] = (
    {
        "id": "KSK-2017",
        "key_tag": 20326,
        "algorithm": 8,
        "digest_type": 2,
        "digest": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    },
    {
        "id": "KSK-2024",
        "key_tag": 38696,
        "algorithm": 8,
        "digest_type": 2,
        "digest": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
    },
)

STANDARDS = (
    {"rfc": 4033, "title": "DNS Security Introduction and Requirements", "why": "Chain of trust", "url": "https://www.rfc-editor.org/rfc/rfc4033", "sections": ["3", "5"]},
    {"rfc": 4034, "title": "Resource Records for the DNS Security Extensions", "why": "DNSKEY, DS, RRSIG, NSEC", "url": "https://www.rfc-editor.org/rfc/rfc4034", "sections": ["2", "3", "5"]},
    {"rfc": 4035, "title": "Protocol Modifications for the DNS Security Extensions", "why": "Resolving and authenticating", "url": "https://www.rfc-editor.org/rfc/rfc4035", "sections": ["4", "5"]},
    {"rfc": 5155, "title": "DNS Security (DNSSEC) Hashed Authenticated Denial of Existence", "why": "NSEC3 at unsigned delegations", "url": "https://www.rfc-editor.org/rfc/rfc5155"},
    {"rfc": 6781, "title": "DNSSEC Operational Practices, Version 2", "why": "KSK/ZSK roles", "url": "https://www.rfc-editor.org/rfc/rfc6781"},
    {"rfc": 9718, "title": "DNSSEC Trust Anchor Publication for the Root Zone", "why": "IANA root-anchors.xml", "url": "https://www.rfc-editor.org/rfc/rfc9718"},
)


def parse_dnssec_path(path: str) -> str:
    """Parse /dnssec/<domain>."""
    text = unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "dnssec" and not text.startswith("dnssec/"):
        raise ValueError("not a dnssec path")
    rest = "" if text == "dnssec" else text[len("dnssec/") :]
    if not rest or "/" in rest:
        raise ValueError("dnssec path needs a domain, e.g. /dnssec/example.com")
    return rest


def _name(text: str) -> Any:
    import dns.name

    return dns.name.from_text(text)


def _rcode(msg: Any) -> str:
    try:
        import dns.rcode

        return dns.rcode.to_text(msg.rcode())
    except Exception:
        return "UNKNOWN"


def _rrsig_covers(rrset: Any) -> Any:
    """RRset.covers is a property in current dnspython and a method in older ones."""
    covers = getattr(rrset, "covers", None)
    if callable(covers):
        try:
            return covers()
        except TypeError:
            return covers
    return covers


def _find_rrset(msg: Any, qname: str, rdtype: str) -> Tuple[Optional[Any], Optional[Any]]:
    """Return (rrset, covering RRSIG rrset) from answer then authority."""
    if msg is None:
        return None, None
    import dns.rdatatype

    want = _name(qname)
    rdtype_obj = dns.rdatatype.from_text(rdtype)
    found = None
    rrsig = None
    sections = list(getattr(msg, "answer", None) or []) + list(getattr(msg, "authority", None) or [])
    for rrset in sections:
        if rrset.name != want:
            continue
        if rrset.rdtype == rdtype_obj:
            found = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG and _rrsig_covers(rrset) == rdtype_obj:
            rrsig = rrset
    return found, rrsig


def _key_tag(key: Any) -> int:
    from dns.dnssec import key_id

    return int(key_id(key))


def _key_role(key: Any) -> str:
    flags = int(getattr(key, "flags", 0) or 0)
    return "KSK" if flags & 1 else "ZSK"


def _algo_name(num: int) -> str:
    try:
        from dns.dnssec import algorithm_to_text

        return algorithm_to_text(num)
    except Exception:
        return str(num)


def _digest_name(num: int) -> str:
    return {1: "SHA-1", 2: "SHA-256", 4: "SHA-384"}.get(int(num), str(num))


def _digest_hex(value: Any) -> str:
    """DS digest as uppercase hex. Wire rdata is bytes; str(bytes) is not hex."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex().upper()
    text = str(value).strip().replace(" ", "").replace(":", "")
    if text.startswith(("b'", 'b"')):
        return ""
    return text.upper()


def _ds_from_key(zone: str, key: Any, digest_type: int = 2) -> Optional[str]:
    try:
        from dns.dnssec import make_ds
        import dns.name

        name = zone if hasattr(zone, "to_text") else dns.name.from_text(zone)
        algo = {1: "SHA1", 2: "SHA256", 4: "SHA384"}.get(int(digest_type), "SHA256")
        ds = make_ds(name, key, algo)
        return _digest_hex(ds.digest)
    except Exception:
        return None


def _validate(rrset: Any, rrsig: Any, keys: Dict[Any, Any]) -> Tuple[str, Optional[str]]:
    if rrset is None:
        return "missing", "No RRset to validate"
    if rrsig is None:
        return "missing", "No RRSIG covering this RRset"
    if not keys:
        return "indeterminate", "No DNSKEYs to validate with"
    try:
        from dns.dnssec import validate

        validate(rrset, rrsig, keys)
        return "valid", None
    except Exception as exc:
        return "bogus", str(exc) or exc.__class__.__name__


async def _default_query(
    server: str,
    qname: str,
    rdtype: str,
    timeout: float = 4.0,
    rd: bool = True,
    tcp: bool = False,
    dnssec: bool = True,
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
        # want_dnssec sets DO. A later use_edns() would clear it (ednsflags=0).
        q = dns.message.make_query(
            qname,
            dns.rdatatype.from_text(rdtype),
            want_dnssec=bool(dnssec),
            payload=_EDNS_PAYLOAD,
        )
        q.flags |= dns.flags.CD
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
            host,
            qname,
            rdtype,
            timeout=timeout,
            rd=True,
            tcp=False,
            dnssec=True,
            port=ns_port,
        )
        if msg is not None:
            rcode = _rcode(msg)
            answers = list(getattr(msg, "answer", None) or [])
            authority = list(getattr(msg, "authority", None) or [])
            if rcode == "SERVFAIL" and not answers and not authority:
                last = "SERVFAIL"
                continue
            return msg, None
        last = err
    return None, last or "no nameservers"


def _dnskey_rows(zone: str, rrset: Any) -> List[Dict[str, Any]]:
    if rrset is None:
        return []
    rows = []
    for key in rrset:
        tag = _key_tag(key)
        rows.append(
            {
                "key_tag": tag,
                "flags": int(getattr(key, "flags", 0) or 0),
                "protocol": int(getattr(key, "protocol", 3) or 3),
                "algorithm": int(key.algorithm),
                "algorithm_name": _algo_name(int(key.algorithm)),
                "role": _key_role(key),
            }
        )
    return rows


def _match_ds(
    zone: str, ds_rrset: Any, dnskey_rrset: Any
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    keys = list(dnskey_rrset) if dnskey_rrset is not None else []
    if ds_rrset is None:
        return rows
    for ds in ds_rrset:
        digest = _digest_hex(ds.digest)
        matched = False
        matched_tag: Optional[int] = None
        for key in keys:
            if int(getattr(ds, "key_tag", 0)) != _key_tag(key):
                continue
            if int(ds.algorithm) != int(key.algorithm):
                continue
            made = _ds_from_key(zone, key, int(ds.digest_type))
            if made and made == digest:
                matched = True
                matched_tag = _key_tag(key)
                break
        rows.append(
            {
                "key_tag": int(ds.key_tag),
                "algorithm": int(ds.algorithm),
                "algorithm_name": _algo_name(int(ds.algorithm)),
                "digest_type": int(ds.digest_type),
                "digest_name": _digest_name(int(ds.digest_type)),
                "digest": digest,
                "matches_dnskey": matched,
                "matched_key_tag": matched_tag,
            }
        )
    return rows


def _anchor_ds_rows(zone: str, dnskey_rrset: Any) -> List[Dict[str, Any]]:
    rows = []
    keys = list(dnskey_rrset) if dnskey_rrset is not None else []
    for anchor in ROOT_TRUST_ANCHORS:
        digest = str(anchor["digest"]).replace(" ", "").upper()
        matched = False
        for key in keys:
            if _key_tag(key) != int(anchor["key_tag"]):
                continue
            made = _ds_from_key(zone, key, int(anchor["digest_type"]))
            if made and made == digest:
                matched = True
                break
        rows.append(
            {
                "key_tag": int(anchor["key_tag"]),
                "algorithm": int(anchor["algorithm"]),
                "algorithm_name": _algo_name(int(anchor["algorithm"])),
                "digest_type": int(anchor["digest_type"]),
                "digest_name": _digest_name(int(anchor["digest_type"])),
                "digest": digest,
                "matches_dnskey": matched,
                "source": "iana-root-anchors",
                "id": anchor["id"],
            }
        )
    return rows


def _aa(msg: Any) -> bool:
    try:
        import dns.flags

        return bool(msg) and bool(msg.flags & dns.flags.AA)
    except Exception:
        return False


def _ns_names(msg: Any) -> List[str]:
    if msg is None:
        return []
    import dns.rdatatype

    names: List[str] = []
    seen = set()
    for rrset in list(getattr(msg, "answer", None) or []) + list(getattr(msg, "authority", None) or []):
        if getattr(rrset, "rdtype", None) != dns.rdatatype.NS:
            continue
        for rr in rrset:
            host = str(getattr(rr, "target", None) or rr).rstrip(".") + "."
            key = host.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(host)
    return names


def _first_address(msg: Any) -> Optional[str]:
    if msg is None:
        return None
    import dns.rdatatype

    for rrset in list(getattr(msg, "answer", None) or []):
        if getattr(rrset, "rdtype", None) not in {dns.rdatatype.A, dns.rdatatype.AAAA}:
            continue
        for rr in rrset:
            addr = getattr(rr, "address", None)
            if addr:
                return str(addr)
    return None


def _rrsig_rows(rrsig: Any) -> List[Dict[str, Any]]:
    if rrsig is None:
        return []
    try:
        records = list(rrsig)
    except TypeError:
        return []
    rows = []
    for rr in records:
        tag = int(getattr(rr, "key_tag", None) or getattr(rr, "key_id", 0) or 0)
        covers = getattr(rr, "type_covered", None)
        try:
            import dns.rdatatype

            covers_name = dns.rdatatype.to_text(covers) if covers is not None else None
        except Exception:
            covers_name = str(covers) if covers is not None else None
        algo = int(getattr(rr, "algorithm", 0) or 0)
        rows.append(
            {
                "key_tag": tag,
                "algorithm": algo,
                "algorithm_name": _algo_name(algo),
                "covers": covers_name,
                "inception": int(getattr(rr, "inception", 0) or 0),
                "expiration": int(getattr(rr, "expiration", 0) or 0),
                "signer": str(getattr(rr, "signer", "") or ""),
            }
        )
    return rows


def _digest_short(digest: Optional[str]) -> str:
    text = str(digest or "").replace(" ", "")
    if len(text) <= 16:
        return text
    return text[:16] + "…"


def _diagnose(
    *,
    zone: str,
    parent: Optional[str],
    status: str,
    detail: str,
    ds_rows: List[Dict[str, Any]],
    dnskeys: List[Dict[str, Any]],
    dnskey_sig: str,
    dnskey_sig_err: Optional[str],
) -> Dict[str, Any]:
    """Structured explanation of this link, DNSViz-style."""
    parent_name = (parent or "the parent").rstrip(".") or "."
    zone_name = (zone or ".").rstrip(".") or "."
    ds_tags = [str(row.get("key_tag")) for row in ds_rows]
    key_bits = [f"{row.get('role') or 'KEY'} {row.get('key_tag')}" for row in dnskeys]
    keys_text = ", ".join(key_bits) if key_bits else "no DNSKEY records"
    ds_text = ", ".join(ds_tags) if ds_tags else "none"

    if status == "secure":
        return {
            "code": "ok",
            "severity": "ok",
            "title": "This link is authenticated",
            "what": detail,
            "effect": None,
            "fix": None,
            "rfc": "RFC 4035",
        }
    if status == "nxdomain":
        return {
            "code": "nxdomain",
            "severity": "info",
            "title": "No such zone",
            "what": detail,
            "effect": None,
            "fix": None,
            "rfc": "RFC 4035",
        }
    if status == "insecure":
        return {
            "code": "insecure_delegation",
            "severity": "info",
            "title": f"{zone_name} is not signed",
            "what": (
                f"{parent_name} does not publish a DS record for {zone_name}, so there is "
                "no chain of trust into this zone."
            ),
            "effect": (
                "Resolvers treat answers from this zone as unauthenticated. That is not a "
                "break — the zone is simply unsigned."
            ),
            "fix": (
                "To sign it, publish a KSK at the child and a matching DS at the parent "
                f"({parent_name})."
            ),
            "rfc": "RFC 4035 §4.3",
        }
    if status == "indeterminate":
        return {
            "code": "indeterminate",
            "severity": "warn",
            "title": f"Could not authenticate {zone_name}",
            "what": detail,
            "effect": "This report cannot say whether the zone is secure or bogus.",
            "fix": "Retry when the parent and child nameservers answer DS and DNSKEY queries.",
            "rfc": "RFC 4035 §4.3",
        }
    if ds_rows and not any(row.get("matches_dnskey") for row in ds_rows) and dnskeys:
        return {
            "code": "ds_mismatch",
            "severity": "error",
            "title": f"Chain breaks at {zone_name}",
            "what": (
                f"{parent_name} publishes DS for key {ds_text}, but none of those digests "
                f"match a DNSKEY at {zone_name} ({keys_text}). RFC 4035 requires the parent "
                "DS to be the hash of a child DNSKEY — usually the KSK."
            ),
            "effect": (
                "Validating resolvers SERVFAIL this name. Stub resolvers that do not "
                "validate may still see answers."
            ),
            "fix": (
                f"Either restore DNSKEY {ds_text} at {zone_name}, or replace the DS at "
                f"{parent_name} with a DS generated from the current KSK ({keys_text})."
            ),
            "rfc": "RFC 4035 §5.2",
        }
    if ds_rows and not dnskeys:
        return {
            "code": "missing_dnskey",
            "severity": "error",
            "title": f"DS exists but {zone_name} published no DNSKEY",
            "what": (
                f"{parent_name} says {zone_name} is signed (DS {ds_text}), but the child "
                "did not return a DNSKEY RRset."
            ),
            "effect": "Validating resolvers SERVFAIL this name.",
            "fix": f"Publish DNSKEYs at {zone_name} that match DS {ds_text}, and sign the zone.",
            "rfc": "RFC 4035 §3.1.4",
        }
    if dnskey_sig == "bogus":
        return {
            "code": "rrsig_bogus",
            "severity": "error",
            "title": f"DNSKEY signature at {zone_name} does not validate",
            "what": dnskey_sig_err or detail,
            "effect": "Validating resolvers SERVFAIL this name.",
            "fix": "Re-sign the DNSKEY RRset with a private key that matches a published DNSKEY.",
            "rfc": "RFC 4035 §5.3",
        }
    if dnskey_sig == "missing" and ds_rows:
        return {
            "code": "rrsig_missing",
            "severity": "error",
            "title": f"Signed zone {zone_name} has no DNSKEY RRSIG",
            "what": dnskey_sig_err or detail,
            "effect": "Validating resolvers SERVFAIL this name.",
            "fix": "Sign the DNSKEY RRset and serve the RRSIG alongside it.",
            "rfc": "RFC 4035 §3.1.1",
        }
    return {
        "code": "bogus",
        "severity": "error",
        "title": f"Chain breaks at {zone_name}",
        "what": detail,
        "effect": "Validating resolvers SERVFAIL this name.",
        "fix": None,
        "rfc": "RFC 4035",
    }


def _graph_for_zone(
    *,
    zone: str,
    parent: Optional[str],
    status: str,
    ds_rows: List[Dict[str, Any]],
    dnskeys: List[Dict[str, Any]],
    dnskey_sig: str,
) -> Dict[str, Any]:
    parent_name = (parent or "parent").rstrip(".") or "."
    zone_name = (zone or ".").rstrip(".") or "."
    ds_items: List[Dict[str, Any]] = []
    for row in ds_rows:
        matched = bool(row.get("matches_dnskey"))
        node_status = "secure" if matched else ("bogus" if status == "bogus" else status)
        ds_items.append(
            {
                "kind": "ds",
                "label": f"DS {row.get('key_tag')}",
                "sub": " · ".join(
                    part
                    for part in (
                        row.get("algorithm_name"),
                        row.get("digest_name"),
                        _digest_short(row.get("digest")),
                    )
                    if part
                ),
                "status": node_status,
                "matched": matched,
            }
        )
    if not ds_items and zone != ".":
        ds_items = [
            {
                "kind": "ds",
                "label": "no DS",
                "sub": f"unsigned at {parent_name}",
                "status": "insecure" if status == "insecure" else status,
                "matched": False,
            }
        ]
    key_items = []
    matched_tags = {
        int(row.get("matched_key_tag") or row.get("key_tag") or 0)
        for row in ds_rows
        if row.get("matches_dnskey")
    }
    for row in dnskeys:
        tag = int(row.get("key_tag") or 0)
        authenticated = tag in matched_tags
        if status == "secure" and authenticated:
            key_status = "secure"
        elif status == "bogus" and ds_rows and not authenticated:
            key_status = "bogus"
        else:
            key_status = status
        key_items.append(
            {
                "kind": "dnskey",
                "label": f"{row.get('role') or 'KEY'} {tag}",
                "sub": row.get("algorithm_name") or "",
                "status": key_status,
                "matched": authenticated,
            }
        )
    groups: List[Dict[str, Any]] = []
    ds_status = "secure" if any(item.get("matched") for item in ds_items) else status
    if zone == ".":
        ds_title = "IANA trust anchors"
        link_ds = (
            {"status": "secure", "label": "matches KSK"}
            if status == "secure"
            else {"status": status, "label": "anchor mismatch"}
        )
    elif any(row.get("matches_dnskey") for row in ds_rows):
        ds_title = f"DS at {parent_name}"
        link_ds = {"status": "secure", "label": "authenticates"}
    elif ds_rows:
        ds_title = f"DS at {parent_name}"
        link_ds = {"status": "bogus", "label": "no matching digest"}
    else:
        ds_title = f"DS at {parent_name}"
        link_ds = {"status": "insecure", "label": "no DS"}
        ds_status = "insecure" if status == "insecure" else status
    groups.append({"title": ds_title, "status": ds_status, "nodes": ds_items, "link": link_ds})
    if key_items:
        if dnskey_sig == "valid":
            link_sig: Optional[Dict[str, Any]] = {"status": "secure", "label": "RRSIG valid"}
        elif dnskey_sig == "bogus":
            link_sig = {"status": "bogus", "label": "RRSIG invalid"}
        elif dnskey_sig == "missing":
            link_sig = {
                "status": "bogus" if status == "bogus" else "insecure",
                "label": "no RRSIG",
            }
        else:
            link_sig = None
        key_status = "secure" if status == "secure" else status
        groups.append(
            {
                "title": f"DNSKEY at {zone_name}",
                "status": key_status,
                "nodes": key_items,
                "link": link_sig,
            }
        )
    return {"groups": groups}


def _ns_agreement(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    ok = [row for row in rows if row.get("ok")]
    variants = {tuple(sorted(int(t) for t in (row.get("tags") or []))) for row in ok}
    return {
        "ok": len(variants) <= 1,
        "responded": len(ok),
        "queried": len(rows),
        "variants": len(variants),
    }


def _rfc6761_nxdomain_name(qname: str) -> bool:
    """RFC 6761: names under `.invalid` should be NXDOMAIN; do not follow localhost NS."""
    labels = [part for part in str(qname or "").strip(".").lower().split(".") if part]
    return bool(labels) and labels[-1] == "invalid"


def _is_loopback_ns(host: str, ip: str = "") -> bool:
    name = str(host or "").strip(".").lower()
    if name == "localhost" or name.endswith(".localhost"):
        return True
    if name == "invalid" or name.endswith(".invalid"):
        return True
    raw = str(ip or "").split("%", 1)[0]
    if not raw:
        return False
    try:
        return ipaddress.ip_address(raw).is_loopback
    except ValueError:
        return False


_MAX_NS = 4


async def _ns_targets(zone: str, timeout: float, query: QueryFn) -> List[Dict[str, str]]:
    if not zone:
        return []
    msg, _err = await _query_public(zone, "NS", timeout, query)
    names = [n for n in _ns_names(msg)[:_MAX_NS] if not _is_loopback_ns(n)]
    if not names:
        return []

    async def resolve_one(host: str) -> Dict[str, str]:
        a_msg, _ = await _query_public(host, "A", timeout, query)
        ip = _first_address(a_msg)
        if not ip:
            aaaa_msg, _ = await _query_public(host, "AAAA", timeout, query)
            ip = _first_address(aaaa_msg)
        return {"host": host, "ip": ip or ""}

    rows = list(await asyncio.gather(*(resolve_one(host) for host in names)))
    return [row for row in rows if not _is_loopback_ns(row.get("host") or "", row.get("ip") or "")]


async def _probe_rr(
    targets: List[Dict[str, str]],
    qname: str,
    rdtype: str,
    timeout: float,
    query: QueryFn,
    side: str,
) -> List[Dict[str, Any]]:
    async def one(row: Dict[str, str]) -> Dict[str, Any]:
        host = row.get("host") or ""
        ip = row.get("ip") or ""
        if _is_loopback_ns(host, ip):
            return {
                "host": host,
                "ip": None,
                "side": side,
                "ok": False,
                "error": "skipped loopback/special-use nameserver",
            }
        if not ip:
            return {
                "host": host,
                "ip": None,
                "side": side,
                "ok": False,
                "error": "no address",
                "qtype": rdtype,
                "tags": [],
            }
        start = time.perf_counter()
        msg, err = await query(
            ip, qname, rdtype, timeout=timeout, rd=False, tcp=False, dnssec=True
        )
        ms = round((time.perf_counter() - start) * 1000.0, 1)
        if msg is None:
            return {
                "host": host,
                "ip": ip,
                "side": side,
                "ok": False,
                "error": err or "no response",
                "ms": ms,
                "qtype": rdtype,
                "tags": [],
            }
        rrset, rrsig = _find_rrset(msg, qname, rdtype)
        tags: List[int] = []
        if rrset is not None:
            if rdtype == "DNSKEY":
                tags = [_key_tag(key) for key in rrset]
            elif rdtype == "DS":
                tags = [int(getattr(ds, "key_tag", 0) or 0) for ds in rrset]
            else:
                tags = []
        return {
            "host": host,
            "ip": ip,
            "side": side,
            "ok": True,
            "error": None,
            "ms": ms,
            "qtype": rdtype,
            "rcode": _rcode(msg),
            "aa": _aa(msg),
            "tags": tags,
            "rrsig": rrsig is not None,
            "count": 0 if rrset is None else len(list(rrset)),
        }

    if not targets:
        return []
    return list(await asyncio.gather(*(one(row) for row in targets)))


async def _apex_and_zones(
    qname: str, timeout: float, query: QueryFn
) -> Tuple[str, List[str], bool]:
    import dns.rdatatype

    want = _name(qname)
    apex = want
    nxdomain = False
    msg, _err = await _query_public(qname, "SOA", timeout, query)
    if msg is not None:
        if _rcode(msg) == "NXDOMAIN":
            nxdomain = True
        for rrset in list(msg.answer) + list(msg.authority):
            if rrset.rdtype == dns.rdatatype.SOA:
                apex = rrset.name
                break
    zones: List[str] = []
    cur = apex
    root = _name(".")
    while True:
        zones.append(cur.to_text())
        if cur == root:
            break
        cur = cur.parent()
    zones.reverse()
    return apex.to_text(), zones, nxdomain


def _leaf_verdict(
    *,
    rrtype: str,
    apex_status: str,
    rrsig_status: str,
    rrsig_error: Optional[str] = None,
    has_rrset: bool = True,
) -> Dict[str, Any]:
    """Separate local RRSIG validity from authenticated chain status.

    A valid signature proves integrity relative to a DNSKEY. It does not prove
    that DNSKEY is trusted. Only an unbroken chain to a configured trust
    anchor makes the RRset DNSSEC-secure.
    """
    chain_secure = apex_status == "secure"
    rrsig = "missing" if not has_rrset else (rrsig_status or "missing")

    def pack(status: str, detail: str, authenticated: bool) -> Dict[str, Any]:
        return {
            "status": status,
            "rrsig": rrsig,
            "authenticated": authenticated,
            "chain_secure": chain_secure,
            "detail": detail,
        }

    if apex_status == "insecure":
        extra = (
            f" A local RRSIG still validates against the zone DNSKEY."
            if has_rrset and rrsig == "valid"
            else ""
        )
        return pack(
            "insecure",
            f"Apex is unsigned, so this {rrtype} RRset is not authenticated.{extra}",
            False,
        )
    if not has_rrset:
        return pack(
            "indeterminate",
            rrsig_error or f"No {rrtype} RRset",
            False,
        )
    if rrsig == "valid" and chain_secure:
        return pack(
            "secure",
            (
                f"The {rrtype} RRset is DNSSEC-secure: its RRSIG validates and the "
                "zone DNSKEY is authenticated to a configured root trust anchor."
            ),
            True,
        )
    if rrsig == "valid" and not chain_secure:
        why = (
            "the parent DS does not match"
            if apex_status == "bogus"
            else "the chain of trust is not authenticated"
        )
        return pack(
            "rrsig_valid",
            (
                f"The {rrtype} RRset signature validates against the zone DNSKEY, but "
                f"the DNSKEY is not authenticated because {why}."
            ),
            False,
        )
    if chain_secure and rrsig == "missing":
        return pack(
            "bogus",
            rrsig_error or f"Signed zone but {rrtype} has no RRSIG.",
            False,
        )
    if rrsig == "bogus":
        return pack(
            "bogus",
            rrsig_error or f"The {rrtype} RRSIG does not validate with the zone DNSKEY.",
            False,
        )
    return pack(
        "indeterminate" if rrsig == "indeterminate" else "bogus",
        rrsig_error or f"{rrtype} signature status: {rrsig}",
        False,
    )


async def check_dnssec_async(
    name: str,
    *,
    timeout: float = 4.0,
    query: Optional[QueryFn] = None,
) -> Dict[str, Any]:
    start = time.time()
    try:
        qname = normalize_qname(name, qtype="A")
    except ValueError as exc:
        return {"ok": False, "result": None, "error": str(exc)}
    qfn: QueryFn = query or _default_query
    try:
        apex, zones, name_nxdomain = await _apex_and_zones(qname, timeout, qfn)
    except Exception as exc:
        return {"ok": False, "result": None, "error": str(exc)}
    if _rfc6761_nxdomain_name(qname):
        name_nxdomain = True
        apex = "."
        zones = ["."]

    chain: List[Dict[str, Any]] = []
    parent_secure = True
    broken_at: Optional[str] = None
    broken_reason: Optional[str] = None
    keys_by_zone: Dict[str, Any] = {}

    for zone in zones:
        parent = None if zone == "." else _name(zone).parent().to_text()
        dnskey_msg, dnskey_err = await _query_public(zone, "DNSKEY", timeout, qfn)
        dnskey_rrset, dnskey_rrsig = _find_rrset(dnskey_msg, zone, "DNSKEY")
        ds_rrset = None
        ds_rrsig = None
        ds_err = None
        ds_rcode = None
        ds_msg = None
        if parent:
            ds_msg, ds_err = await _query_public(zone, "DS", timeout, qfn)
            ds_rrset, ds_rrsig = _find_rrset(ds_msg, zone, "DS")
            ds_rcode = _rcode(ds_msg) if ds_msg is not None else None
        dnskeys = _dnskey_rows(zone, dnskey_rrset)
        if zone == ".":
            ds_rows = _anchor_ds_rows(zone, dnskey_rrset)
        else:
            ds_rows = _match_ds(zone, ds_rrset, dnskey_rrset)

        keyset = {}
        if dnskey_rrset is not None:
            keyset = {_name(zone): dnskey_rrset}
            keys_by_zone[zone] = dnskey_rrset

        dnskey_sig, dnskey_sig_err = _validate(dnskey_rrset, dnskey_rrsig, keyset)

        has_ds = bool(ds_rows)
        ds_match = any(row.get("matches_dnskey") for row in ds_rows) if ds_rows else False
        ds_query_failed = bool(parent) and ds_msg is None
        ds_nxdomain = bool(parent) and ds_rcode == "NXDOMAIN"
        unsigned = (not has_ds) and zone != "." and not ds_query_failed and not ds_nxdomain
        status = "indeterminate"
        detail = ""

        if zone == ".":
            if ds_match and dnskey_sig == "valid":
                status = "secure"
                detail = "Root DNSKEY matches an IANA trust anchor and its RRSIG validates."
            elif not dnskeys:
                status = "bogus"
                detail = dnskey_err or "No root DNSKEY RRset"
            elif not ds_match:
                status = "bogus"
                detail = "Root DNSKEY does not match the embedded IANA trust anchors."
            else:
                status = "bogus"
                detail = dnskey_sig_err or "Root DNSKEY RRSIG did not validate."
        elif not parent_secure:
            prior = chain[-1]["status"] if chain else "insecure"
            if prior == "bogus":
                status = "indeterminate"
                detail = "Ancestor failed authentication, so this zone cannot be authenticated."
            elif prior == "indeterminate":
                status = "indeterminate"
                detail = "Ancestor could not be authenticated."
            else:
                status = "insecure"
                detail = "Ancestor is unsigned, so this zone is not authenticated."
        elif ds_query_failed:
            status = "indeterminate"
            detail = ds_err or "Could not fetch DS from the parent."
            if ds_err and "DS" not in detail:
                detail = f"Could not fetch DS from the parent ({ds_err})."
        elif ds_nxdomain:
            status = "nxdomain"
            detail = f"{zone} does not exist (parent DS NXDOMAIN)."
            name_nxdomain = True
        elif unsigned:
            status = "insecure"
            detail = (
                f"Parent {parent} has no DS for this zone"
                + (f" ({ds_rcode})" if ds_rcode else "")
                + " — insecure delegation, not a break."
            )
        elif not dnskeys:
            status = "bogus"
            detail = ds_err or dnskey_err or "DS exists at the parent but the child published no DNSKEY."
        elif not ds_match:
            status = "bogus"
            detail = "Parent DS does not match any child DNSKEY digest. This is where the chain breaks."
        elif dnskey_sig != "valid":
            status = "bogus"
            detail = dnskey_sig_err or "DNSKEY RRSIG did not validate with the zone's keys."
        else:
            status = "secure"
            detail = "Parent DS matches a child KSK and the DNSKEY RRSIG validates."

        if status == "bogus" and broken_at is None:
            broken_at = zone
            broken_reason = detail
        if status != "secure":
            parent_secure = False

        issue = _diagnose(
            zone=zone,
            parent=parent,
            status=status,
            detail=detail,
            ds_rows=ds_rows,
            dnskeys=dnskeys,
            dnskey_sig=dnskey_sig,
            dnskey_sig_err=dnskey_sig_err,
        )
        graph = _graph_for_zone(
            zone=zone,
            parent=parent,
            status=status,
            ds_rows=ds_rows,
            dnskeys=dnskeys,
            dnskey_sig=dnskey_sig,
        )
        chain.append(
            {
                "zone": zone,
                "parent": parent,
                "status": status,
                "detail": detail,
                "dnskeys": dnskeys,
                "ds": ds_rows,
                "dnskey_rrsig": dnskey_sig,
                "dnskey_rrsig_error": dnskey_sig_err,
                "dnskey_rrsigs": _rrsig_rows(dnskey_rrsig),
                "ds_rrsigs": _rrsig_rows(ds_rrsig),
                "ds_rcode": ds_rcode,
                "query_error": dnskey_err or ds_err,
                "issue": issue,
                "graph": graph,
                "nameservers": [],
                "ns_agreement": {"ok": True, "responded": 0, "queried": 0, "variants": 0},
            }
        )

    leaf_type = "A"
    leaf_msg, leaf_err = await _query_public(qname, "A", timeout, qfn)
    if leaf_msg is not None and _rcode(leaf_msg) == "NXDOMAIN":
        name_nxdomain = True
    leaf_rrset, leaf_rrsig = _find_rrset(leaf_msg, qname, "A")
    if leaf_rrset is None:
        leaf_msg, leaf_err = await _query_public(qname, "AAAA", timeout, qfn)
        if leaf_msg is not None and _rcode(leaf_msg) == "NXDOMAIN":
            name_nxdomain = True
        leaf_rrset, leaf_rrsig = _find_rrset(leaf_msg, qname, "AAAA")
        leaf_type = "AAAA"
    if leaf_rrset is None and not name_nxdomain:
        leaf_msg, leaf_err = await _query_public(apex, "SOA", timeout, qfn)
        leaf_rrset, leaf_rrsig = _find_rrset(leaf_msg, apex, "SOA")
        leaf_type = "SOA"
    apex_keys = {}
    if apex in keys_by_zone:
        apex_keys = {_name(apex): keys_by_zone[apex]}
    leaf_sig, leaf_sig_err = _validate(leaf_rrset, leaf_rrsig, apex_keys)
    apex_status = chain[-1]["status"] if chain else "indeterminate"
    verdict = _leaf_verdict(
        rrtype=leaf_type,
        apex_status=apex_status,
        rrsig_status=leaf_sig,
        rrsig_error=leaf_sig_err or leaf_err,
        has_rrset=leaf_rrset is not None,
    )
    leaf_status = verdict["status"]
    leaf_detail = verdict["detail"]
    if leaf_status == "bogus" and broken_at is None:
        broken_at = apex
        broken_reason = leaf_detail

    statuses = [row["status"] for row in chain]
    if name_nxdomain:
        nx_detail = (
            f"{qname} does not exist (authenticated NXDOMAIN)."
            if apex_status == "secure"
            else f"{qname} does not exist (NXDOMAIN)."
        )
        verdict = {
            "status": "nxdomain",
            "rrsig": "missing" if leaf_rrset is None else verdict.get("rrsig"),
            "authenticated": apex_status == "secure",
            "chain_secure": apex_status == "secure",
            "detail": nx_detail,
        }
        leaf_status = "nxdomain"
        leaf_detail = nx_detail
        overall = "nxdomain"
    elif "bogus" in statuses or leaf_status == "bogus":
        overall = "bogus"
    elif all(s == "secure" for s in statuses) and leaf_status == "secure" and verdict["authenticated"]:
        overall = "secure"
    elif "insecure" in statuses:
        overall = "insecure"
    else:
        overall = "indeterminate"

    async def enrich(row: Dict[str, Any]) -> None:
        zone = row["zone"]
        if zone == ".":
            return
        parent = row.get("parent")
        probe_to = min(timeout, 2.0)
        child_ns = await _ns_targets(zone, probe_to, qfn)
        parent_ns: List[Dict[str, str]] = []
        if parent and parent != ".":
            parent_ns = await _ns_targets(parent, probe_to, qfn)
        if parent_ns:
            child_views, parent_views = await asyncio.gather(
                _probe_rr(child_ns, zone, "DNSKEY", probe_to, qfn, "child"),
                _probe_rr(parent_ns, zone, "DS", probe_to, qfn, "parent"),
            )
        else:
            child_views = await _probe_rr(child_ns, zone, "DNSKEY", probe_to, qfn, "child")
            parent_views = []
        row["nameservers"] = list(parent_views) + list(child_views)
        row["ns_agreement"] = _ns_agreement(child_views)
        if not row["ns_agreement"]["ok"] and row["ns_agreement"]["responded"] > 1:
            row["detail"] = (row.get("detail") or "") + " Child nameservers disagree on the DNSKEY set."

    await asyncio.gather(*(enrich(row) for row in chain))
    apex_ns = [] if apex == "." else await _ns_targets(apex, min(timeout, 2.0), qfn)
    leaf_name = qname if leaf_type != "SOA" else apex
    leaf_ns = await _probe_rr(apex_ns, leaf_name, leaf_type, min(timeout, 2.0), qfn, "child")
    issue = next((row.get("issue") for row in chain if row.get("status") == "bogus"), None)
    if issue is None and overall == "nxdomain":
        issue = {
            "code": "nxdomain",
            "severity": "info",
            "title": "No such zone",
            "what": leaf_detail,
            "effect": None,
            "fix": None,
            "rfc": "RFC 4035",
        }
    elif issue is None and overall == "insecure":
        issue = next((row.get("issue") for row in reversed(chain) if row.get("status") == "insecure"), None)
    elif issue is None and overall == "secure":
        issue = {
            "code": "ok",
            "severity": "ok",
            "title": "Chain of trust holds",
            "what": f"{qname} authenticates from the IANA root anchors to the apex.",
            "effect": None,
            "fix": None,
            "rfc": "RFC 4035",
        }

    result = {
        "name": qname,
        "apex": apex,
        "status": overall,
        "secure": overall == "secure",
        "broken": overall == "bogus",
        "broken_at": broken_at,
        "broken_reason": broken_reason,
        "chain": chain,
        "leaf": {
            "name": qname if leaf_type != "SOA" or overall == "nxdomain" else apex,
            "type": leaf_type,
            "status": verdict["status"],
            "detail": verdict["detail"],
            "rrsig": verdict["rrsig"],
            "authenticated": verdict["authenticated"],
            "chain_secure": verdict["chain_secure"],
            "rrsigs": _rrsig_rows(leaf_rrsig),
            "nameservers": leaf_ns,
        },
        "trust_anchors": [dict(row) for row in ROOT_TRUST_ANCHORS],
        "standards": [dict(row) for row in STANDARDS],
        "issue": issue,
    }
    return {
        "ok": True,
        "result": result,
        "error": None,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


def check_dnssec(name: str, **kwargs: Any) -> Dict[str, Any]:
    """Sync wrapper. Do not call from a running event loop."""
    return asyncio.run(check_dnssec_async(name, **kwargs))
