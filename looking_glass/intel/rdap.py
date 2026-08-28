"""RDAP client for IP, domain, and autnum.

Domain lookups follow IANA dns.json (jp → JPRS, de → DENIC, com → Verisign).
IP and autnum still try https://rdap.org then the RIRs. Responses are cached
under ~/.looking-glass/data/cache/rdap. The GUI uses the summarized fields;
JSON includes the raw object as well.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .. import cache as query_cache
from ..net.host import parse_asn_number
from ..utility import get_cache_path, load_json_cache, save_json_cache

_ASN = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)
_LDH_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_RDAP_TARGET_ERROR = "rdap path needs an IP, domain, or ASN, e.g. /rdap/AS13335"


def parse_rdap_path(path: str) -> str:
    """Parse /rdap/<ip|domain|ASnnn>."""
    text = urllib.parse.unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "rdap" and not text.startswith("rdap/"):
        raise ValueError("not an rdap path")
    rest = "" if text == "rdap" else text[len("rdap/") :]
    if not rest or rest.count("/") > 4:
        raise ValueError(_RDAP_TARGET_ERROR)
    detect_rdap_type(rest)
    return rest


def _is_rdap_domain(text: str) -> bool:
    name = str(text or "").strip().rstrip(".")
    if not name or " " in name or "/" in name:
        return False
    try:
        ascii_name = name.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return False
    labels = ascii_name.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if tld.startswith("xn--"):
        if len(tld) < 5:
            return False
    elif not tld.isalpha() or len(tld) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not _LDH_LABEL.match(label):
            return False
    return True


def detect_rdap_type(target: str) -> str:
    text = str(target).strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        text = text[1:-1]
    if "%" in text:
        raise ValueError(_RDAP_TARGET_ERROR)
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if _ASN.match(text):
        parse_asn_number(text)
        return "autnum"
    if _is_rdap_domain(text):
        return "domain"
    raise ValueError(_RDAP_TARGET_ERROR)


def _autnum(target: str) -> str:
    return str(parse_asn_number(target))


_DNSSEC_ALGS = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    12: "ECC-GOST",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}
_DS_DIGESTS = {1: "SHA-1", 2: "SHA-256", 3: "GOST R 34.11-94", 4: "SHA-384"}
_EVENT_KIND = {
    "registration": "registered",
    "registered": "registered",
    "created": "registered",
    "expiration": "expires",
    "expired": "expires",
    "expire": "expires",
    "last changed": "last_changed",
    "last update": "last_changed",
    "last update of rdap database": "last_changed",
    "last update of whois database": "last_changed",
    "transfer": "transfer",
    "deletion": "deleted",
    "reinstantiation": "reinstated",
}


def _first(data: Dict[str, Any], *keys: str) -> Any:
    lower = {str(key).lower(): value for key, value in data.items()}
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
        value = lower.get(key.lower())
        if value not in (None, ""):
            return value
    return None


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"true", "yes", "1", "signed", "signeddelegation"}:
            return True
        if low in {"false", "no", "0", "unsigned", "unsigneddelegation"}:
            return False
    return None


def parse_when(text: Any) -> Optional[datetime]:
    """Parse an RDAP/WHOIS timestamp into an aware UTC datetime."""
    if isinstance(text, datetime):
        dt = text
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    raw = str(text or "").strip()
    if not raw:
        return None
    raw = raw.replace("Z", "+00:00")
    for noise in (" UTC", " GMT", " (UTC)"):
        if raw.endswith(noise):
            raw = raw[: -len(noise)].strip()
            if "+" not in raw[1:] and not raw.endswith("Z"):
                raw = raw + "+00:00"
            break
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d",
        "%Y.%m.%d",
        "%Y/%m/%d",
        "%d-%b-%Y",
        "%d-%B-%Y",
        "%d.%m.%Y",
        "%Y-%m-%d %H:%M:%S",
        "%Y.%m.%d %H:%M:%S",
    ):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def format_when(text: Any) -> Optional[str]:
    dt = parse_when(text)
    if dt is None:
        raw = str(text or "").strip()
        return raw or None
    if dt.hour == 0 and dt.minute == 0 and dt.second == 0 and dt.microsecond == 0:
        return dt.strftime("%Y-%m-%d")
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def human_span(seconds: float) -> str:
    days = int(abs(seconds) // 86400)
    years, rem = divmod(days, 365)
    months, days = divmod(rem, 30)
    parts: List[str] = []
    if years:
        parts.append(f"{years} year" + ("s" if years != 1 else ""))
    if months:
        parts.append(f"{months} month" + ("s" if months != 1 else ""))
    if not parts:
        if days:
            parts.append(f"{days} day" + ("s" if days != 1 else ""))
        else:
            return "less than a day"
    return ", ".join(parts)


def timeline_from_dates(
    dates: Dict[str, Any],
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Turn registered/expires/last_changed into age phrases."""
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        clock = clock.replace(tzinfo=timezone.utc)
    registered = parse_when(dates.get("registered"))
    expires = parse_when(dates.get("expires"))
    last_changed = parse_when(dates.get("last_changed"))
    out: Dict[str, Any] = {
        "registered": format_when(dates.get("registered")),
        "expires": format_when(dates.get("expires")),
        "last_changed": format_when(dates.get("last_changed")),
        "transfer": format_when(dates.get("transfer")),
        "registered_age": None,
        "registered_ago": None,
        "expires_in": None,
        "summary": None,
    }
    if registered:
        age = human_span((clock - registered).total_seconds())
        out["registered_age"] = age
        out["registered_ago"] = f"{age} ago"
    if expires:
        delta = (expires - clock).total_seconds()
        span = human_span(delta)
        out["expires_in"] = f"in {span}" if delta >= 0 else f"expired {span} ago"
    bits = []
    if out["registered_ago"]:
        when = f" ({out['registered']})" if out["registered"] else ""
        bits.append(f"registered {out['registered_ago']}{when}")
    if out["expires_in"]:
        when = f" ({out['expires']})" if out["expires"] else ""
        bits.append(f"{out['expires_in']}{when}")
    if last_changed and not bits:
        bits.append(f"last changed {format_when(last_changed)}")
    out["summary"] = " · ".join(bits) if bits else None
    return out


def _format_adr(value: Any, params: Optional[Dict[str, Any]] = None) -> str:
    if isinstance(value, list):
        parts = [str(part).strip() for part in value if part not in (None, "", [])]
        text = ", ".join(parts)
    else:
        text = str(value or "").strip()
    cc = None
    if isinstance(params, dict):
        cc = params.get("cc") or params.get("country")
    if cc and cc not in text:
        text = f"{text}, {cc}" if text else str(cc)
    return text.strip(" ,")


def _vcard_rows(entity: Dict[str, Any], code: str) -> List[Tuple[Dict[str, Any], Any]]:
    blob = entity.get("vcardArray")
    if not isinstance(blob, list) or len(blob) < 2 or not isinstance(blob[1], list):
        return []
    out: List[Tuple[Dict[str, Any], Any]] = []
    for row in blob[1]:
        if not isinstance(row, list) or len(row) < 4:
            continue
        if str(row[0]).lower() != code.lower():
            continue
        params = row[1] if isinstance(row[1], dict) else {}
        out.append((params, row[3]))
    return out


def _vcard_values(entity: Dict[str, Any], code: str) -> List[str]:
    out: List[str] = []
    for params, value in _vcard_rows(entity, code):
        if code.lower() == "adr":
            text = _format_adr(value, params)
        elif isinstance(value, list):
            text = ", ".join(str(part) for part in value if part not in (None, "", []))
        else:
            text = str(value or "").strip()
        if text:
            out.append(text)
    return out


def _entity_name(entity: Dict[str, Any]) -> Optional[str]:
    names = _vcard_values(entity, "fn")
    if names:
        return names[0]
    orgs = _vcard_values(entity, "org")
    if orgs:
        return orgs[0]
    handle = entity.get("handle")
    return str(handle) if handle else None


def _public_ids(entity: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for item in entity.get("publicIds") or entity.get("publicIds") or []:
        if not isinstance(item, dict):
            continue
        ident = item.get("identifier")
        if ident in (None, ""):
            ident = item.get("identifier")
        if ident in (None, ""):
            continue
        out.append({"type": item.get("type"), "identifier": str(ident)})
    return out


def _summarize_entity(entity: Dict[str, Any], *, nested: bool = False) -> Dict[str, Any]:
    address = (_vcard_values(entity, "adr") or [None])[0]
    org = (_vcard_values(entity, "org") or [None])[0]
    country = None
    for params, value in _vcard_rows(entity, "adr"):
        if isinstance(params, dict) and (params.get("cc") or params.get("country")):
            country = str(params.get("cc") or params.get("country"))
            break
        if isinstance(value, list) and value:
            last = str(value[-1] or "").strip()
            if last and len(last) <= 3:
                country = last
    row: Dict[str, Any] = {
        "handle": entity.get("handle"),
        "name": _entity_name(entity),
        "org": org,
        "roles": [str(role) for role in (entity.get("roles") or [])],
        "email": (_vcard_values(entity, "email") or [None])[0],
        "tel": (_vcard_values(entity, "tel") or [None])[0],
        "address": address,
        "country": country or (address if address and len(str(address)) <= 3 else None),
        "public_ids": _public_ids(entity),
    }
    if nested:
        row["nested"] = True
    return row


def _role_entity(entities: List[Dict[str, Any]], role: str) -> Optional[Dict[str, Any]]:
    want = role.lower()
    for entity in entities:
        roles = [str(item).lower() for item in (entity.get("roles") or [])]
        if want in roles:
            return entity
    return None


def _nameserver_entry(ns: Any) -> Optional[Dict[str, Any]]:
    if isinstance(ns, str):
        host = ns.rstrip(".").lower()
        return {"host": host, "v4": [], "v6": []} if host else None
    if not isinstance(ns, dict):
        return None
    host = str(_first(ns, "ldhName", "unicodeName", "handle") or "").rstrip(".").lower()
    if not host:
        return None
    addrs = ns.get("ipAddresses") if isinstance(ns.get("ipAddresses"), dict) else {}
    if not addrs and isinstance(ns.get("ipAddresses"), dict):
        addrs = ns.get("ipAddresses") or {}
    v4 = [str(item) for item in (addrs.get("v4") or []) if item]
    v6 = [str(item) for item in (addrs.get("v6") or []) if item]
    unicode_name = ns.get("unicodeName")
    row: Dict[str, Any] = {"host": host, "v4": v4, "v6": v6}
    if unicode_name and str(unicode_name).rstrip(".").lower() != host:
        row["unicode"] = str(unicode_name)
    status = list(ns.get("status") or [])
    if status:
        row["status"] = status
    return row


def _dnssec_record(algo: Any, table: Dict[int, str]) -> Tuple[Optional[int], Optional[str]]:
    try:
        number = int(algo)
    except (TypeError, ValueError):
        return None, str(algo) if algo not in (None, "") else None
    return number, table.get(number) or str(number)


def summarize_dnssec(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    blob = None
    if isinstance(data, dict):
        blob = data.get("secureDNS")
        if blob is None:
            blob = data.get("secureDns")
        if blob is None:
            for key, value in data.items():
                if str(key).lower() == "securedns" and isinstance(value, dict):
                    blob = value
                    break
    if not isinstance(blob, dict):
        return {
            "present": False,
            "signed": None,
            "delegation_signed": None,
            "zone_signed": None,
            "ds": [],
            "keys": [],
            "label": "unknown",
        }
    delegation = _as_bool(_first(blob, "delegationSigned", "delegation_signed"))
    zone = _as_bool(_first(blob, "zoneSigned", "zone_signed"))
    ds_rows = []
    for item in blob.get("dsData") or blob.get("dsData") or blob.get("ds_data") or []:
        if not isinstance(item, dict):
            continue
        alg_n, alg_name = _dnssec_record(item.get("algorithm"), _DNSSEC_ALGS)
        dig_n, dig_name = _dnssec_record(
            item.get("digestType") or item.get("digest_type") or item.get("digestType"),
            _DS_DIGESTS,
        )
        ds_rows.append(
            {
                "key_tag": item.get("keyTag") if item.get("keyTag") is not None else (item.get("key_tag") if item.get("key_tag") is not None else item.get("keyTag")),
                "algorithm": alg_n,
                "algorithm_name": alg_name,
                "digest_type": dig_n,
                "digest_type_name": dig_name,
                "digest": item.get("digest"),
            }
        )
    key_rows = []
    for item in blob.get("keyData") or blob.get("key_data") or []:
        if not isinstance(item, dict):
            continue
        alg_n, alg_name = _dnssec_record(item.get("algorithm"), _DNSSEC_ALGS)
        key_rows.append(
            {
                "flags": item.get("flags"),
                "protocol": item.get("protocol"),
                "algorithm": alg_n,
                "algorithm_name": alg_name,
                "public_key": item.get("publicKey") or item.get("public_key"),
            }
        )
    if delegation is True or zone is True or ds_rows or key_rows:
        signed, label = True, "signed"
    elif delegation is False or zone is False:
        signed, label = False, "unsigned"
    else:
        signed, label = None, "unknown"
    return {
        "present": True,
        "signed": signed,
        "delegation_signed": delegation,
        "zone_signed": zone,
        "max_sig_life": blob.get("maxSigLife") or blob.get("max_sig_life"),
        "ds": ds_rows,
        "keys": key_rows,
        "label": label,
    }


def _event_kind(action: Any) -> Optional[str]:
    if not action:
        return None
    return _EVENT_KIND.get(str(action).strip().lower())


def _remarks(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for item in data.get("remarks") or []:
        if not isinstance(item, dict):
            continue
        desc = item.get("description")
        if isinstance(desc, list):
            text = " ".join(str(part) for part in desc if part)
        else:
            text = str(desc or "").strip()
        title = item.get("title")
        if not text and not title:
            continue
        out.append({"title": title, "description": text or None})
    return out


def summarize_rdap(
    data: Optional[Dict[str, Any]],
    *,
    kind: str,
    query: str,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    data = data or {}
    entities: List[Dict[str, Any]] = []
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        entities.append(_summarize_entity(entity))
        for extra in entity.get("entities") or []:
            if not isinstance(extra, dict):
                continue
            entities.append(_summarize_entity(extra, nested=True))
    events = []
    date_map: Dict[str, Any] = {}
    for event in data.get("events") or []:
        if not isinstance(event, dict):
            continue
        action = _first(event, "eventAction", "event_action", "action")
        date = _first(event, "eventDate", "event_date", "date")
        events.append(
            {
                "action": action,
                "date": date,
                "date_display": format_when(date),
                "actor": _first(event, "eventActor", "event_actor", "actor"),
            }
        )
        slot = _event_kind(action)
        if slot and date and slot not in date_map:
            date_map[slot] = date
    nameserver_details = []
    nameservers = []
    for ns in data.get("nameservers") or []:
        row = _nameserver_entry(ns)
        if not row:
            continue
        nameserver_details.append(row)
        nameservers.append(row["host"])
    cidrs: List[str] = []
    for item in data.get("cidr0_cidrs") or []:
        if not isinstance(item, dict):
            continue
        prefix = item.get("v4prefix") or item.get("v6prefix")
        length = item.get("length")
        if prefix is not None and length is not None:
            cidrs.append(f"{prefix}/{length}")
    links = []
    for link in data.get("links") or []:
        if isinstance(link, dict) and link.get("href"):
            links.append({"rel": link.get("rel"), "href": link.get("href"), "type": link.get("type")})
    secure = data.get("secureDNS")
    if secure is None:
        secure = data.get("secureDns")
    dnssec = summarize_dnssec(data)
    timeline = timeline_from_dates(date_map, now=now)
    registrar = _role_entity(entities, "registrar")
    registrant = _role_entity(entities, "registrant")
    iana_id = None
    if registrar:
        for item in registrar.get("public_ids") or []:
            kind_id = str(item.get("type") or "").lower()
            if "iana" in kind_id and item.get("identifier"):
                iana_id = str(item["identifier"])
                break
    registrar_info = None
    if registrar:
        registrar_info = {
            "name": registrar.get("name") or registrar.get("org") or registrar.get("handle"),
            "iana_id": iana_id,
            "email": registrar.get("email"),
            "url": None,
        }
        for item in registrar.get("public_ids") or []:
            if str(item.get("type") or "").lower() == "iana registrar id":
                registrar_info["iana_id"] = str(item.get("identifier"))
    origin_asns = []
    for item in data.get("arin_originas0_originautnums") or []:
        try:
            origin_asns.append(int(item))
        except (TypeError, ValueError):
            continue
    ldh = data.get("ldhName") or data.get("ldh_name")
    unicode_name = data.get("unicodeName") or data.get("unicode_name")
    return {
        "query": query,
        "type": kind,
        "handle": data.get("handle"),
        "name": data.get("name") or ldh or unicode_name,
        "ldh_name": str(ldh).rstrip(".").lower() if ldh else None,
        "unicode_name": unicode_name,
        "object_class": data.get("objectClassName"),
        "country": data.get("country"),
        "start_address": data.get("startAddress"),
        "end_address": data.get("endAddress"),
        "ip_version": data.get("ipVersion"),
        "type_field": data.get("type"),
        "parent_handle": data.get("parentHandle"),
        "cidr": cidrs,
        "origin_asns": origin_asns,
        "status": list(data.get("status") or []),
        "port43": data.get("port43"),
        "entities": entities,
        "events": events,
        "dates": {
            "registered": timeline["registered"],
            "expires": timeline["expires"],
            "last_changed": timeline["last_changed"],
            "transfer": timeline["transfer"],
        },
        "registered_age": timeline["registered_age"],
        "registered_ago": timeline["registered_ago"],
        "expires_in": timeline["expires_in"],
        "timeline": timeline["summary"],
        "nameservers": nameservers,
        "nameserver_details": nameserver_details,
        "registrar": registrar_info,
        "registrant": (
            {
                "name": registrant.get("name"),
                "org": registrant.get("org"),
                "country": registrant.get("country"),
                "email": registrant.get("email"),
            }
            if registrant
            else None
        ),
        "dnssec": dnssec,
        "secure_dns": secure if isinstance(secure, dict) else None,
        "remarks": _remarks(data),
        "links": links,
        "notices": [
            {"title": n.get("title"), "description": n.get("description")}
            for n in (data.get("notices") or [])
            if isinstance(n, dict)
        ],
        "raw": data,
    }


_RIR_RDAP = (
    "https://rdap.arin.net/registry",
    "https://rdap.db.ripe.net",
    "https://rdap.apnic.net",
    "https://rdap.lacnic.net",
    "https://rdap.afrinic.net/rdap",
)
_DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_DNS_BOOTSTRAP_TTL = 7 * 86400
_FETCH_TIMEOUT = (3, 8)
_DNS_BOOTSTRAP: Optional[List[Tuple[Tuple[str, ...], Tuple[str, ...]]]] = None
_DNS_BOOTSTRAP_LOADED = 0.0


def _rdap_json_body(resp: Any) -> Optional[dict]:
    """Return a RDAP object dict, or None for HTML / non-object bodies."""
    headers = getattr(resp, "headers", None)
    ctype = ""
    getter = getattr(headers, "get", None) if headers is not None else None
    if callable(getter):
        raw = getter("Content-Type")
        if raw is None:
            raw = getter("content-type")
        if isinstance(raw, str):
            ctype = raw
    if "html" in ctype.lower():
        return None
    text = getattr(resp, "text", None)
    if isinstance(text, str):
        head = text.lstrip()[:64].lower()
        if head.startswith("<!doctype") or head.startswith("<html"):
            return None
    try:
        data = resp.json()
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _is_not_found(resp: Any, data: Optional[dict]) -> bool:
    if int(getattr(resp, "status_code", 0) or 0) == 404:
        return True
    if not isinstance(data, dict):
        return False
    try:
        return int(data.get("errorCode") or 0) == 404
    except (TypeError, ValueError):
        return False


def _join_rdap(base: str, endpoint: str, quoted: str) -> str:
    return f"{str(base).rstrip('/')}/{endpoint}/{quoted}"


def _fail_message(url: Optional[str], status: Optional[int], detail: Optional[str] = None) -> str:
    parts = ["rdap lookup failed"]
    if url:
        parts.append(str(url))
    if status is not None:
        parts.append(str(status))
    if detail:
        parts.append(str(detail))
    return " ".join(parts)


def _parse_dns_services(payload: Any) -> List[Tuple[Tuple[str, ...], Tuple[str, ...]]]:
    if not isinstance(payload, dict):
        return []
    out: List[Tuple[Tuple[str, ...], Tuple[str, ...]]] = []
    for entry in payload.get("services") or []:
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        tlds = tuple(
            str(item).lower().strip(".")
            for item in (entry[0] or [])
            if str(item).strip()
        )
        urls = tuple(str(item).strip() for item in (entry[1] or []) if str(item).strip())
        if tlds and urls:
            out.append((tlds, urls))
    return out


def _dns_bootstrap_path() -> str:
    return get_cache_path("rdap-dns.json")


def dns_bootstrap_services(*, force: bool = False) -> List[Tuple[Tuple[str, ...], Tuple[str, ...]]]:
    """IANA dns.json services: [(tlds, urls), ...], cached on disk."""
    global _DNS_BOOTSTRAP, _DNS_BOOTSTRAP_LOADED
    now = time.time()
    if (
        not force
        and _DNS_BOOTSTRAP is not None
        and (now - _DNS_BOOTSTRAP_LOADED) < _DNS_BOOTSTRAP_TTL
    ):
        return _DNS_BOOTSTRAP
    path = _dns_bootstrap_path()
    if not force:
        cached = load_json_cache(path)
        services = _parse_dns_services(cached)
        fetched_at = float((cached or {}).get("_fetched_at") or 0) if cached else 0.0
        if services and (now - fetched_at) < _DNS_BOOTSTRAP_TTL:
            _DNS_BOOTSTRAP = services
            _DNS_BOOTSTRAP_LOADED = fetched_at or now
            return services
    import requests

    try:
        resp = requests.get(
            _DNS_BOOTSTRAP_URL,
            timeout=_FETCH_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        if int(getattr(resp, "status_code", 0) or 0) == 200:
            payload = resp.json()
            if isinstance(payload, dict):
                payload = dict(payload)
                payload["_fetched_at"] = now
                save_json_cache(path, payload)
                services = _parse_dns_services(payload)
                _DNS_BOOTSTRAP = services
                _DNS_BOOTSTRAP_LOADED = now
                return services
    except Exception:
        pass
    cached = load_json_cache(path)
    services = _parse_dns_services(cached)
    _DNS_BOOTSTRAP = services
    _DNS_BOOTSTRAP_LOADED = now
    return services


def domain_rdap_urls(alabel: str) -> List[str]:
    """Registry URLs for an A-label domain, longest TLD match in IANA dns.json."""
    ascii_name = str(alabel or "").strip().rstrip(".").lower()
    quoted = urllib.parse.quote(ascii_name, safe="")
    labels = ascii_name.split(".")
    best: Tuple[str, ...] = ()
    best_len = 0
    for tlds, urls in dns_bootstrap_services():
        for tld in tlds:
            parts = tuple(part for part in tld.split(".") if part)
            n = len(parts)
            if n == 0 or n > len(labels) or n <= best_len:
                continue
            if tuple(labels[-n:]) == parts:
                best = urls
                best_len = n
    if best:
        return [_join_rdap(base, "domain", quoted) for base in best]
    return [f"https://rdap.org/domain/{quoted}"]


def _rdap_urls(kind: str, lookup: str) -> List[str]:
    quoted = urllib.parse.quote(lookup, safe=":/" if kind == "ip" else "")
    endpoint = {"ip": "ip", "domain": "domain", "autnum": "autnum"}.get(kind, "ip")
    if kind == "domain":
        return domain_rdap_urls(lookup)
    urls = [f"https://rdap.org/{endpoint}/{quoted}"]
    urls.extend(_join_rdap(base, endpoint, quoted) for base in _RIR_RDAP)
    return urls


def _fetch_rdap_result(
    target: str,
    target_type: Optional[str] = None,
    cache_days: int = 7,
    force: bool = False,
    timeout: Any = _FETCH_TIMEOUT,
) -> Dict[str, Any]:
    empty = {
        "data": None,
        "not_found": False,
        "url": None,
        "http_status": None,
        "error": None,
        "kind": None,
        "lookup": None,
    }
    try:
        detected = detect_rdap_type(target)
    except ValueError:
        empty["error"] = "rdap lookup failed"
        return empty
    kind = (target_type or detected).strip().lower()
    if kind == "autnum":
        lookup = _autnum(target)
    elif kind == "ip":
        lookup = str(ipaddress.ip_address(str(target).strip().strip("[]")))
    else:
        lookup = str(target).strip().rstrip(".")
        try:
            lookup = lookup.encode("idna").decode("ascii")
        except (UnicodeError, ValueError) as exc:
            raise ValueError(_RDAP_TARGET_ERROR) from exc
        kind = "domain"
    empty["kind"] = kind
    empty["lookup"] = lookup
    key = f"{kind}_{lookup}"
    _ = cache_days
    if not force:
        hit = query_cache.get("rdap", key)
        if hit is not None:
            return {
                "data": hit,
                "not_found": False,
                "url": None,
                "http_status": 200,
                "error": None,
                "kind": kind,
                "lookup": lookup,
            }

    import requests

    urls = _rdap_urls(kind, lookup)
    last_url = urls[0] if urls else None
    last_status: Optional[int] = None
    last_error = "rdap lookup failed"
    for url in urls:
        last_url = url
        try:
            resp = requests.get(
                url,
                timeout=timeout if timeout is not None else _FETCH_TIMEOUT,
                allow_redirects=True,
                headers={"Accept": "application/rdap+json, application/json"},
            )
            last_status = int(getattr(resp, "status_code", 0) or 0)
            rdap_data = _rdap_json_body(resp)
            if _is_not_found(resp, rdap_data):
                if kind in {"ip", "autnum"}:
                    last_error = _fail_message(url, last_status)
                    continue
                return {
                    "data": None,
                    "not_found": True,
                    "url": url,
                    "http_status": last_status or 404,
                    "error": "not found",
                    "kind": kind,
                    "lookup": lookup,
                }
            if last_status == 200 and rdap_data is not None:
                query_cache.put("rdap", key, rdap_data)
                return {
                    "data": rdap_data,
                    "not_found": False,
                    "url": url,
                    "http_status": 200,
                    "error": None,
                    "kind": kind,
                    "lookup": lookup,
                }
            last_error = _fail_message(
                url,
                last_status,
                None if rdap_data is not None or last_status != 200 else "not json",
            )
        except Exception as exc:
            last_status = None
            last_error = _fail_message(url, None, str(exc) or "timeout")
            continue
    cached = query_cache.get_any("rdap", key)
    if cached is not None:
        return {
            "data": cached,
            "not_found": False,
            "url": last_url,
            "http_status": last_status,
            "error": None,
            "kind": kind,
            "lookup": lookup,
        }
    return {
        "data": None,
        "not_found": False,
        "url": last_url,
        "http_status": last_status,
        "error": last_error,
        "kind": kind,
        "lookup": lookup,
    }


def fetch_rdap(
    target: str,
    target_type: Optional[str] = None,
    cache_days: int = 7,
    force: bool = False,
    timeout: Any = _FETCH_TIMEOUT,
) -> Optional[dict]:
    """Fetch RDAP for an IP, domain, or autnum."""
    return _fetch_rdap_result(
        target,
        target_type=target_type,
        cache_days=cache_days,
        force=force,
        timeout=timeout,
    ).get("data")


def get_rdap_for_ip(ip_address: str, cache_days: int = 7, force: bool = False) -> Optional[dict]:
    """Resolve RDAP target for an IP and use fetch_rdap."""
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return None
    return fetch_rdap(ip_address, target_type="ip", cache_days=cache_days, force=force)


def lookup_rdap(target: str, *, force: bool = False) -> Dict[str, Any]:
    start = time.time()
    try:
        kind = detect_rdap_type(target)
    except ValueError:
        return {
            "ok": False,
            "result": None,
            "error": "rdap lookup failed",
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }
    fetched = _fetch_rdap_result(target, target_type=kind, force=force)
    elapsed = round((time.time() - start) * 1000.0, 3)
    data = fetched.get("data")
    if data:
        return {
            "ok": True,
            "result": summarize_rdap(data, kind=kind, query=target),
            "error": None,
            "total_ms": elapsed,
        }
    out: Dict[str, Any] = {
        "ok": False,
        "result": None,
        "error": str(fetched.get("error") or "rdap lookup failed"),
        "total_ms": elapsed,
        "status": 404 if fetched.get("not_found") else 502,
    }
    if fetched.get("url"):
        out["url"] = fetched["url"]
    if fetched.get("http_status") is not None:
        out["http_status"] = fetched["http_status"]
    if fetched.get("not_found"):
        out["error"] = "not found"
        out["status"] = 404
    elif out["error"] == "rdap lookup failed":
        out["error"] = _fail_message(fetched.get("url"), fetched.get("http_status"))
    return out


async def lookup_rdap_async(target: str, *, force: bool = False) -> Dict[str, Any]:
    return await asyncio.to_thread(lookup_rdap, target, force=force)


def rdap_cache_stats() -> Dict[str, Any]:
    """Inventory of ~/.looking-glass/data/cache/rdap JSON files."""
    return query_cache.stats("rdap")


def clear_rdap_cache(name: Optional[str] = None) -> Dict[str, Any]:
    """Delete one cached RDAP object, or every file when name is omitted."""
    return query_cache.clear("rdap", name)


def rdap_for_asn(asn: Any, *, force: bool = False) -> Optional[Dict[str, Any]]:
    """Summarized autnum RDAP, or None if the registry is unreachable."""
    try:
        data = fetch_rdap(str(asn), target_type="autnum", force=force)
    except Exception:
        return None
    if not data:
        return None
    summary = summarize_rdap(data, kind="autnum", query=str(asn))
    summary.pop("raw", None)
    return summary
