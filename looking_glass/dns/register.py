"""Check one DNS label against every IANA TLD (DNS delegation, not a registrar)."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import unquote

from ..net.host import restore_collapsed_slashes
from ..utility import (
    LogFn,
    ProgressFn,
    build_info,
    fetch_text,
    get_cache_path,
    load_json_cache,
    save_json_cache,
)
from .resolve import _query

IANA_TLDS_TXT = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
CACHE_NAME = "tlds.json"
SKIP_TLDS = frozenset({"arpa"})
CONCURRENCY = 48
QUERY_TIMEOUT = 1.5
KNOWN_WILDCARDS = frozenset(
    {
        "gov",
        "merck",
        "ph",
        "vg",
        "web",
        "ws",
        "xn--fiqs8s",
        "xn--fiqz9s",
        "xn--ngbrx",
        "xn--node",
    }
)
RDAP_TLDS = frozenset({"com", "net", "org", "dev", "io", "app", "pw"})

_LABEL_LDH = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_WILDCARD = re.compile(r"[*]")
_SCHEME_PREFIX = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)

_tlds: List[str] = []
_wildcards: Set[str] = set()
_fetched_at: int = 0
_built: bool = False


def _cache_path() -> str:
    return get_cache_path(CACHE_NAME)


def parse_tlds_text(text: str) -> List[str]:
    """Parse IANA tlds-alpha-by-domain.txt into lowercase TLD labels."""
    out: List[str] = []
    seen: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tld = line.lower().rstrip(".")
        if not tld or tld in SKIP_TLDS or tld in seen:
            continue
        if not _LABEL_LDH.match(tld) and not tld.startswith("xn--"):
            continue
        seen.add(tld)
        out.append(tld)
    return out


def _install(
    tlds: List[str],
    fetched_at: int = 0,
    wildcards: Optional[Sequence[str]] = None,
) -> None:
    global _tlds, _fetched_at, _built, _wildcards
    _tlds = list(tlds)
    _fetched_at = int(fetched_at or 0)
    _wildcards = {str(t).lower() for t in (wildcards or []) if t}
    _built = True


def load(force: bool = False) -> bool:
    """Load the IANA TLD list from disk, or build it if missing."""
    if _built and not force:
        return True
    payload = load_json_cache(_cache_path())
    if payload and not force:
        rows = payload.get("tlds") or []
        if rows:
            _install(
                [str(t).lower() for t in rows if t],
                int(payload.get("_fetched_at", 0) or 0),
                payload.get("wildcards") or [],
            )
            return True
    return build(force=force)


def build(
    force: bool = False,
    log: Optional[LogFn] = None,
    progress: Optional[ProgressFn] = None,
) -> bool:
    """Fetch the IANA TLD list and cache it under ~/.looking-glass/data."""
    info = build_info("tlds build", log)
    path = _cache_path()
    if not force:
        payload = load_json_cache(path)
        if payload and payload.get("tlds"):
            rows = [str(t).lower() for t in payload["tlds"] if t]
            cached_wild = payload.get("wildcards")
            fetched_at = int(payload.get("_fetched_at", 0) or 0)
            if cached_wild is not None:
                _install(rows, fetched_at, cached_wild)
                info(f"using cached TLDs ({len(_tlds)} entries)")
                return True
            info("scanning wildcard TLDs")
            wild = _scan_wildcards_sync(rows)
            save_json_cache(path, {"_fetched_at": fetched_at or int(time.time()), "tlds": rows, "wildcards": wild})
            _install(rows, fetched_at, wild)
            info(f"wrote {len(rows)} TLDs ({len(wild)} wildcards)")
            return True

    info(f"GET {IANA_TLDS_TXT}")
    text = fetch_text(IANA_TLDS_TXT, progress=progress, log=log)
    if not text:
        info("download failed")
        return False
    rows = parse_tlds_text(text)
    if not rows:
        info("no TLDs parsed")
        return False
    info("scanning wildcard TLDs")
    wild = _scan_wildcards_sync(rows)
    now = int(time.time())
    save_json_cache(path, {"_fetched_at": now, "tlds": rows, "wildcards": wild})
    _install(rows, now, wild)
    info(f"wrote {len(rows)} TLDs ({len(wild)} wildcards)")
    return True


def get_fetched_at() -> int:
    return int(_fetched_at or 0)


def tld_names() -> List[str]:
    _ensure()
    return list(_tlds)


def wildcard_tlds() -> Set[str]:
    return set(KNOWN_WILDCARDS) | set(_wildcards)


def _ensure() -> None:
    if _built:
        return
    payload = load_json_cache(_cache_path())
    if payload and payload.get("tlds"):
        _install(
            [str(t).lower() for t in payload["tlds"] if t],
            int(payload.get("_fetched_at", 0) or 0),
            payload.get("wildcards") or [],
        )
        return
    load()


def parse_register_path(path: str) -> str:
    """Parse /register/<label> into the submitted token."""
    text = restore_collapsed_slashes(unquote(str(path or ""))).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "register" and not text.startswith("register/"):
        raise ValueError("not a register path")
    rest = "" if text == "register" else text[len("register/") :]
    if not rest:
        raise ValueError("register path needs a name, e.g. /register/example")
    if "/" in rest and not _looks_like_url(rest):
        raise ValueError("register path needs a name, e.g. /register/example")
    return rest


def _to_ascii_label(label: str) -> str:
    raw = (label or "").strip()
    if not raw:
        raise ValueError("need a DNS label, e.g. example")
    try:
        return raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("need a DNS label, e.g. example") from exc


def _to_unicode_label(ascii_label: str) -> str:
    raw = str(ascii_label or "")
    if not raw.startswith("xn--"):
        return raw
    try:
        return raw.encode("ascii").decode("idna")
    except UnicodeError:
        return raw


def _looks_like_url(text: str) -> bool:
    raw = str(text or "").strip()
    lower = raw.lower()
    return "://" in raw or lower.startswith("//") or bool(_SCHEME_PREFIX.match(raw))


def parse_label(value: str) -> str:
    """One Unicode DNS label: example.com → example. Rejects IPs, URLs, and empty."""
    text = restore_collapsed_slashes(unquote(str(value or ""))).strip().rstrip(".")
    if not text:
        raise ValueError("need a DNS label, e.g. example")
    if _looks_like_url(text) or " " in text or "/" in text or _WILDCARD.search(text):
        raise ValueError("need a DNS label, e.g. example")
    if "." in text:
        raise ValueError("need a DNS label, e.g. example")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        raise ValueError("need a DNS label, e.g. example")
    ascii_label = _to_ascii_label(text)
    if len(ascii_label) < 1 or len(ascii_label) > 63:
        raise ValueError("need a DNS label, e.g. example")
    if not _LABEL_LDH.match(ascii_label):
        raise ValueError("need a DNS label, e.g. example")
    return _to_unicode_label(ascii_label)


def tld_display(tld: str) -> str:
    raw = str(tld or "").lower()
    if not raw.startswith("xn--"):
        return raw
    try:
        return raw.encode("ascii").decode("idna")
    except UnicodeError:
        return raw


def _response_has_ns(response: Any) -> bool:
    if response is None:
        return False
    try:
        import dns.rdatatype

        ns = dns.rdatatype.NS
    except ImportError:
        ns = 2
    for rrset in getattr(response, "answer", None) or []:
        rdtype = getattr(rrset, "rdtype", None)
        if rdtype == ns or str(rdtype).upper() == "NS":
            return True
    return False


def _classify_dns(
    status: str,
    error: Optional[str],
    response: Any,
) -> Dict[str, str]:
    rcode = str(status or "ERROR")
    if error or rcode in {"ERROR", "TIMEOUT"}:
        err = str(error or rcode)
        reason = "timeout" if "timeout" in err.lower() or rcode == "TIMEOUT" else "timeout"
        wire = "TIMEOUT" if reason == "timeout" else rcode
        return {"status": "unknown", "reason": "timeout", "rcode": wire, "dns": "timeout"}
    if rcode == "SERVFAIL":
        return {"status": "unknown", "reason": "servfail", "rcode": rcode, "dns": "servfail"}
    if rcode == "REFUSED":
        return {"status": "unknown", "reason": "refused", "rcode": rcode, "dns": "refused"}
    if rcode == "NXDOMAIN":
        return {"status": "no-dns", "reason": "nxdomain", "rcode": rcode, "dns": "nxdomain"}
    if rcode == "NOERROR":
        if _response_has_ns(response):
            return {"status": "has-ns", "reason": "ns", "rcode": rcode, "dns": "delegated"}
        return {"status": "unknown", "reason": "nodata", "rcode": rcode, "dns": "nodata"}
    return {"status": "unknown", "reason": rcode.lower(), "rcode": rcode, "dns": rcode.lower()}


def _square(
    tld: str,
    name: str,
    classified: Dict[str, str],
    *,
    wildcards: Optional[Set[str]] = None,
) -> Dict[str, str]:
    row = {
        "tld": tld,
        "name": name,
        "label": tld_display(tld),
        **classified,
    }
    flags = wildcards if wildcards is not None else wildcard_tlds()
    if tld in flags and row.get("status") == "has-ns":
        row["status"] = "unknown"
        row["reason"] = "wildcard"
    return row


async def _probe_one(
    ascii_label: str,
    tld: str,
    *,
    timeout: float,
    sem: asyncio.Semaphore,
    wildcards: Optional[Set[str]] = None,
) -> Dict[str, str]:
    name = f"{ascii_label}.{tld}"
    qname = f"{name}."
    async with sem:
        try:
            import dns.rdatatype
        except ImportError:
            return _square(
                tld,
                name,
                {"status": "unknown", "reason": "timeout", "rcode": "ERROR", "dns": "timeout"},
                wildcards=wildcards,
            )
        try:
            response, status, error = await _query(qname, dns.rdatatype.NS, timeout, None)
        except Exception:
            return _square(
                tld,
                name,
                {"status": "unknown", "reason": "timeout", "rcode": "TIMEOUT", "dns": "timeout"},
                wildcards=wildcards,
            )
    return _square(tld, name, _classify_dns(status, error, response), wildcards=wildcards)


def _rdap_says_registered(payload: Any) -> bool:
    if not isinstance(payload, dict) or not payload.get("ok"):
        return False
    result = payload.get("result")
    if not isinstance(result, dict):
        return False
    if result.get("handle") or result.get("ldh_name") or result.get("unicode_name"):
        return True
    if result.get("status"):
        return True
    dates = result.get("dates") or {}
    if isinstance(dates, dict) and dates.get("registered"):
        return True
    if result.get("registrar") or result.get("entities"):
        return True
    return False


async def _apply_rdap(squares: List[Dict[str, str]]) -> None:
    jobs = [
        (i, row["name"])
        for i, row in enumerate(squares)
        if row.get("reason") == "nxdomain" and row.get("tld") in RDAP_TLDS
    ]
    if not jobs:
        return
    from ..intel.rdap import lookup_rdap_async

    results = await asyncio.gather(
        *[lookup_rdap_async(name) for _i, name in jobs],
        return_exceptions=True,
    )
    for (index, _name), payload in zip(jobs, results):
        if isinstance(payload, BaseException):
            continue
        if _rdap_says_registered(payload):
            squares[index]["status"] = "unknown"
            squares[index]["reason"] = "rdap-registered"


async def _scan_wildcards(tlds: Sequence[str]) -> List[str]:
    nonce = "zz-lg-" + secrets.token_hex(8)
    sem = asyncio.Semaphore(CONCURRENCY)
    empty: Set[str] = set()

    async def one(tld: str) -> Optional[str]:
        row = await _probe_one(nonce, tld, timeout=QUERY_TIMEOUT, sem=sem, wildcards=empty)
        if row.get("reason") == "ns":
            return tld
        return None

    found = await asyncio.gather(*[one(str(t).lower()) for t in tlds if t])
    return sorted(t for t in found if t)


def _scan_wildcards_sync(tlds: Sequence[str]) -> List[str]:
    return asyncio.run(_scan_wildcards(tlds))


async def check_register_async(
    name: str,
    *,
    timeout: float = QUERY_TIMEOUT,
    tlds: Optional[Sequence[str]] = None,
    concurrency: int = CONCURRENCY,
) -> Dict[str, Any]:
    """NS-probe `label.tld` for each IANA TLD."""
    start = time.time()
    try:
        label = parse_label(name)
        ascii_label = _to_ascii_label(label)
    except ValueError as exc:
        return {
            "ok": False,
            "kind": "register",
            "query": str(name or "").strip(),
            "result": None,
            "error": str(exc),
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }
    rows = [str(t).lower().lstrip(".") for t in tlds] if tlds is not None else tld_names()
    rows = [t for t in rows if t and t not in SKIP_TLDS]
    if not rows:
        return {
            "ok": False,
            "kind": "register",
            "query": label,
            "result": None,
            "error": "no IANA TLD list; run looking-glass build --tlds",
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }
    flags = wildcard_tlds()
    sem = asyncio.Semaphore(max(1, int(concurrency or CONCURRENCY)))
    probes = await asyncio.gather(
        *[
            _probe_one(ascii_label, tld, timeout=timeout, sem=sem, wildcards=flags)
            for tld in rows
        ]
    )
    squares = sorted(probes, key=lambda row: str(row.get("tld") or ""))
    await _apply_rdap(squares)
    no_dns = sum(1 for row in squares if row.get("status") == "no-dns")
    has_ns = sum(1 for row in squares if row.get("status") == "has-ns")
    unknown_n = sum(1 for row in squares if row.get("status") == "unknown")
    return {
        "ok": True,
        "kind": "register",
        "query": label,
        "result": {
            "label": label,
            "ascii": ascii_label,
            "tlds": len(squares),
            "no_dns": no_dns,
            "has_ns": has_ns,
            "unknown": unknown_n,
            "source": "dns",
            "squares": squares,
        },
        "error": None,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


def check_register(name: str, **kwargs: Any) -> Dict[str, Any]:
    """Sync wrapper. Do not call from a running event loop."""
    return asyncio.run(check_register_async(name, **kwargs))
