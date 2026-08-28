"""Shared IP lookup pipeline used by the CLI and the intel server."""

from __future__ import annotations

import ipaddress
import time
from typing import Any, Dict, Tuple

from ..intel import asn as asn_mod
from ..intel import asn_org, flags, iana, rir

_MODULES = (
    ("iana", iana),
    ("rir", rir),
    ("asn", asn_mod),
    ("asn_org", asn_org),
)


def classify_query(value: str) -> Tuple[str, str]:
    """Detect IP, ASN, or country from a single token. No kind argument."""
    text = str(value).strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        text = text[1:-1]
    try:
        return "ip", str(ipaddress.ip_address(text))
    except ValueError:
        pass
    asn = text.upper()
    if asn.startswith("AS"):
        asn = asn[2:].strip()
    if asn.isdigit():
        return "asn", asn
    country = flags.canonical_country(text)
    if country:
        return "country", country
    raise ValueError(f"{value!r} is not an IP address, ASN, or country code")


def warmup() -> None:
    """Load all datasets into memory. Call once before a bulk local lookup."""
    for _name, mod in _MODULES:
        if hasattr(mod, "load"):
            mod.load(force=False)


def lookup_ip(ip: str, *, load: bool = True) -> Dict[str, Any]:
    """Look up country, ASN, and organization for an IP.

    Same path for `looking-glass lookup` and the Unix-socket intel server.
    Pass load=False when datasets are already in memory.
    """
    start_total = time.time()
    timings: Dict[str, float] = {}
    errors: Dict[str, str] = {}
    result: Dict[str, Any] = {
        "ip": ip,
        "source": None,
        "iana": None,
        "country": None,
        "flag": None,
        "asn": None,
        "prefix": None,
    }

    if load:
        for name, mod in _MODULES:
            t0 = time.time()
            try:
                if hasattr(mod, "load"):
                    mod.load(force=False)
                timings[f"{name}_load_ms"] = (time.time() - t0) * 1000.0
            except Exception as e:
                timings[f"{name}_load_ms"] = (time.time() - t0) * 1000.0
                errors[f"{name}_load_error"] = str(e)

    t0 = time.time()
    try:
        iana_entry = iana.find_for_ip(ip)
        timings["iana_lookup_ms"] = (time.time() - t0) * 1000.0
        if iana_entry:
            result.update({"source": "iana", "iana": iana_entry, "asn": False})
            return _payload(ip, result, timings, errors, start_total)
    except Exception as e:
        timings["iana_lookup_ms"] = (time.time() - t0) * 1000.0
        errors["iana_lookup_error"] = str(e)

    t0 = time.time()
    try:
        rir_entry = rir.get_country(ip)
        timings["rir_lookup_ms"] = (time.time() - t0) * 1000.0
        if rir_entry:
            if isinstance(rir_entry, dict) and rir_entry.get("iana") is not None:
                result.update({"source": "iana", "iana": rir_entry.get("iana"), "asn": False})
            else:
                result["source"] = "rir"
                if isinstance(rir_entry, dict):
                    result["country"] = rir_entry.get("country")
                    result["flag"] = rir_entry.get("flag")
                    for key in ("country_name", "flag_url", "flag_html"):
                        if rir_entry.get(key):
                            result[key] = rir_entry[key]
        else:
            result["source"] = None
    except Exception as e:
        timings["rir_lookup_ms"] = (time.time() - t0) * 1000.0
        errors["rir_lookup_error"] = str(e)

    if result.get("source") == "rir":
        t0 = time.time()
        try:
            origin = asn_mod.find_origin(ip)
            timings["asn_lookup_ms"] = (time.time() - t0) * 1000.0
            if isinstance(origin, dict):
                if origin.get("iana") is not None:
                    result["iana"] = origin.get("iana")
                    result["asn"] = False
                    result["prefix"] = None
                elif origin.get("asn") is not None:
                    asn_field = origin.get("asn")
                    result["asn"] = (
                        int(asn_field)
                        if isinstance(asn_field, (int, str)) and asn_field is not False
                        else None
                    )
                    result["prefix"] = origin.get("prefix")
                    try:
                        t_asn_org = time.time()
                        org = None
                        if result.get("asn") is not None:
                            org = asn_org.find_org(result["asn"])
                        timings["asn_org_lookup_ms"] = (time.time() - t_asn_org) * 1000.0
                        if org and isinstance(org, dict) and org.get("name"):
                            result["org_name"] = org.get("name")
                    except Exception as e:
                        timings["asn_org_lookup_ms"] = (time.time() - t_asn_org) * 1000.0
                        errors["asn_org_lookup_error"] = str(e)
            elif isinstance(origin, tuple):
                a, p = origin
                result["asn"] = int(a) if a is not None else None
                result["prefix"] = p
            else:
                result["asn"] = None
                result["prefix"] = None
        except Exception as e:
            timings["asn_lookup_ms"] = (time.time() - t0) * 1000.0
            errors["asn_lookup_error"] = str(e)

    return _payload(ip, result, timings, errors, start_total)


def _payload(
    ip: str,
    result: Dict[str, Any],
    timings: Dict[str, float],
    errors: Dict[str, str],
    start_total: float,
) -> Dict[str, Any]:
    return {
        "ok": True,
        "ip": ip,
        "result": {k: v for k, v in result.items() if v is not None},
        "timings": {k: round(v, 3) for k, v in timings.items()},
        "errors": errors,
        "total_ms": round((time.time() - start_total) * 1000.0, 3),
    }


def lookup_country(code: str, *, load: bool = True) -> Dict[str, Any]:
    """Flag fields plus every RIR CIDR allocated to this country."""
    if load:
        try:
            rir.load(force=False)
        except Exception:
            pass
    cc = flags.canonical_country(code) or str(code).strip().upper()
    info = flags.flag_info(cc)
    fields = flags.lookup_fields(cc)
    dump = rir.cidrs_for_country(cc) or {
        "country": cc,
        "prefixes": [],
        "count": 0,
        "ipv4": 0,
        "ipv6": 0,
    }
    result = {
        "country": dump["country"],
        "country_name": info.name,
        **fields,
        "prefixes": dump["prefixes"],
        "count": dump["count"],
        "ipv4": dump["ipv4"],
        "ipv6": dump["ipv6"],
    }
    fetched = rir.get_fetched_at() or None
    return {
        "ok": True,
        "country": dump["country"],
        "result": result,
        "fetched_at": fetched,
        "error": None,
    }
