import time
from typing import List, Optional, Any, Dict
from ..utility import (
    LogFn,
    ProgressFn,
    build_info,
    get_cache_path,
    fetch_text,
    save_json_cache,
    load_json_cache,
    parse_iana_csv_text,
)
import ipaddress
from array import array
from bisect import bisect_right

SOURCES = [
    "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv",
    "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv",
]
PARSER_VERSION = 2

# module cache (compact arrays for fast lookup)
_starts_v4: "array | None" = None
_ends_v4: "array | None" = None
_meta_v4: "List[dict] | None" = None

_starts_v6: "List[int] | None" = None
_ends_v6: "List[int] | None" = None
_meta_v6: "List[dict] | None" = None

_fetched_at: int = 0
_built: bool = False


def _get_iana_db_path() -> str:
    return get_cache_path("iana.json")


def _cache_is_current(payload: Optional[dict]) -> bool:
    if not payload:
        return False
    if int(payload.get("parser_version") or 0) < PARSER_VERSION:
        return False
    return bool(payload.get("entries"))


def load(force: bool = False) -> bool:
    """
    Load IANA special registry cache from disk into memory.
    If missing, stale, or force=True the DB will be rebuilt via build().
    """
    global _fetched_at
    path = _get_iana_db_path()
    payload = load_json_cache(path)
    if payload and not force and _cache_is_current(payload):
        entries = (payload.get("entries", []) or [])
        _build_arrays_from_entries(entries)
        _fetched_at = int(payload.get("_fetched_at", 0) or 0)
        return True
    return build(force=True if (payload and not _cache_is_current(payload)) else force)


def build(
    force: bool = False,
    log: Optional[LogFn] = None,
    progress: Optional[ProgressFn] = None,
) -> bool:
    """
    Fetch IANA CSV sources, parse them and persist a compact cache.
    """
    global _fetched_at
    info = build_info("iana build", log)

    info("starting IANA build")
    path = _get_iana_db_path()
    if not force:
        try:
            payload = load_json_cache(path)
            if _cache_is_current(payload):
                entries = payload.get("entries", []) or []
                _build_arrays_from_entries(entries)
                _fetched_at = int(payload.get("_fetched_at", 0) or 0)
                info(f"using cached IANA data ({len(entries)} entries)")
                return True
        except Exception as e:
            info(f"could not read cache: {e}")

    if not force and _starts_v4 is not None and _starts_v6 is not None:
        info("using in-memory IANA data")
        return True

    now = int(time.time())
    combined: List[dict] = []
    for url in SOURCES:
        info(f"fetching {url.split('/')[2] if '://' in url else url}")
        try:
            txt = fetch_text(url, progress=progress, log=info)
            if not txt:
                info(f"no data from {url}")
                continue
            parsed = parse_iana_csv_text(txt, url) or []
            info(f"parsed {len(parsed)} entries")
            combined.extend(parsed)
        except Exception as e:
            info(f"failed to fetch/parse {url}: {e}")
            continue

    combined.sort(key=lambda x: x.get("start", 0))
    if not combined:
        info("no IANA entries parsed — not saving an empty cache")
        return False
    ok = save_json_cache(
        path,
        {"_fetched_at": now, "parser_version": PARSER_VERSION, "entries": combined},
    )
    if ok:
        _build_arrays_from_entries(combined)
        _fetched_at = now
        info(f"saved {len(combined)} IANA entries")
    else:
        info("failed to save IANA cache")
    return bool(ok)


def _build_arrays_from_entries(entries: List[dict]) -> None:
    """
    Convert saved entry dicts into compact numeric arrays/lists for v4/v6 and free verbose lists.
    Expects entries to contain 'prefix' (or convertible start/end); invalid entries are skipped.
    """
    global _starts_v4, _ends_v4, _meta_v4, _starts_v6, _ends_v6, _meta_v6, _built
    v4_rows = []
    v6_rows = []
    for e in entries:
        prefix = e.get("prefix") or e.get("cidr") or e.get("network") or e.get("net") or e.get("range")
        # tolerate single-host numeric start/end entries
        if not prefix and ("start" in e and "end" in e) and e.get("start") == e.get("end"):
            prefix = str(e.get("start"))
        if not prefix:
            continue
        try:
            if "/" not in str(prefix):
                ip = ipaddress.ip_address(prefix)
                prefix = f"{prefix}/32" if ip.version == 4 else f"{prefix}/128"
            net = ipaddress.ip_network(prefix, strict=False)
        except Exception:
            continue
        start = int(net.network_address)
        end = int(net.broadcast_address)
        if net.version == 4:
            v4_rows.append((start, end, e))
        else:
            v6_rows.append((start, end, e))

    # sort by start
    v4_rows.sort(key=lambda r: r[0])
    v6_rows.sort(key=lambda r: r[0])

    # build compact arrays / lists
    s4 = array("I"); e4 = array("I"); m4: List[dict] = []
    for s, en, meta in v4_rows:
        s4.append(s); e4.append(en); m4.append(meta)

    s6: List[int] = []; e6: List[int] = []; m6: List[dict] = []
    for s, en, meta in v6_rows:
        s6.append(s); e6.append(en); m6.append(meta)

    _starts_v4, _ends_v4, _meta_v4 = s4 if len(s4) else None, e4 if len(e4) else None, m4 if m4 else None
    _starts_v6, _ends_v6, _meta_v6 = s6 if len(s6) else None, e6 if len(e6) else None, m6 if m6 else None
    _built = True


def get_fetched_at() -> int:
    return int(_fetched_at or 0)


def _covering_meta(starts, ends, meta, ip_i):
    """Last (most specific start) range that actually contains ip_i."""
    if not starts:
        return None
    i = bisect_right(starts, ip_i) - 1
    while i >= 0:
        if starts[i] <= ip_i <= ends[i]:
            return meta[i]
        i -= 1
    return None


def find_for_ip(ip_address: str) -> Optional[dict]:
    """
    Return the IANA entry matching ip_address or None.
    Uses bisect against compact numeric arrays built at load/build time.
    Walks back when a later prefix starts before the IP but does not cover it
    (IANA specials nest, e.g. 192.88.99.2/32 inside 192.88.99.0/24).
    """
    try:
        if not _built:
            load(force=False)
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.version == 4:
            return _covering_meta(_starts_v4, _ends_v4, _meta_v4, int(ip_obj))
        return _covering_meta(_starts_v6, _ends_v6, _meta_v6, int(ip_obj))
    except Exception:
        return None