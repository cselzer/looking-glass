import time
import ipaddress
from typing import Any, List, Optional, Dict
from array import array
from bisect import bisect_right

from ..utility import (
    LogFn,
    ProgressFn,
    build_info,
    get_cache_path,
    fetch_text,
    save_json_cache,
    load_json_cache,
    parse_rir_delegated,
)

# produce flag emoji cheaply
from .flags import lookup_fields, canonical_country

# Module cache -------------------------------------------------------------
# original ranges list (kept only until arrays built)
_ranges: List[Dict[str, Any]] | None = []
_last_update: int = 0

# compact arrays for fast low-memory lookups
# IPv4: unsigned 32-bit arrays for starts/ends; meta_v4 stores short country codes
_starts_v4: "array | None" = None
_ends_v4: "array | None" = None
_meta_v4: "List[str] | None" = None

# IPv6: Python int lists for starts/ends; meta_v6 stores short country codes
_starts_v6: "List[int] | None" = None
_ends_v6: "List[int] | None" = None
_meta_v6: "List[str] | None" = None

_built: bool = False

SOURCES = [
    "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest",
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
    "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
]


def get_rir_path() -> str:
    return get_cache_path("rir.json")


def _build_arrays_from_ranges() -> None:
    """
    Convert _ranges into compact arrays/lists for v4/v6 lookups and free _ranges.
    stores only small country codes (2-char) in meta lists.
    """
    global _starts_v4, _ends_v4, _meta_v4, _starts_v6, _ends_v6, _meta_v6, _ranges, _built

    if not _ranges:
        _starts_v4 = _ends_v4 = _meta_v4 = None
        _starts_v6 = _ends_v6 = _meta_v6 = None
        _built = True
        return

    v4_s = array("I")
    v4_e = array("I")
    v4_meta: List[str] = []
    v6_s: List[int] = []
    v6_e: List[int] = []
    v6_meta: List[str] = []

    for entry in _ranges:
        country_code = (entry.get("country") or "??")[:2]
        # prefer explicit prefix
        prefix = entry.get("prefix")
        try:
            if prefix:
                net = ipaddress.ip_network(prefix, strict=False)
                s = int(net.network_address)
                e = int(net.broadcast_address)
                if net.version == 4:
                    v4_s.append(s); v4_e.append(e); v4_meta.append(country_code)
                else:
                    v6_s.append(s); v6_e.append(e); v6_meta.append(country_code)
                continue
        except Exception:
            pass

        # fallback to start/end numeric bounds
        start = entry.get("start")
        end = entry.get("end")
        if start is None or end is None:
            continue
        try:
            # allow ints or numeric strings
            s_ip = int(start) if isinstance(start, int) or str(start).isdigit() else int(ipaddress.ip_address(start))
            e_ip = int(end) if isinstance(end, int) or str(end).isdigit() else int(ipaddress.ip_address(end))
        except Exception:
            continue
        # choose v4/v6 by value range (ipv4 fits in 32-bit)
        if s_ip <= 0xFFFFFFFF and e_ip <= 0xFFFFFFFF:
            v4_s.append(s_ip); v4_e.append(e_ip); v4_meta.append(country_code)
        else:
            v6_s.append(s_ip); v6_e.append(e_ip); v6_meta.append(country_code)

    # sort by start (they may already be sorted, but ensure correctness)
    if v4_s:
        combined_v4 = sorted(zip(v4_s, v4_e, v4_meta), key=lambda t: t[0])
        v4_s, v4_e, v4_meta = map(list, zip(*combined_v4))
        v4_s = array("I", v4_s); v4_e = array("I", v4_e)
    if v6_s:
        combined_v6 = sorted(zip(v6_s, v6_e, v6_meta), key=lambda t: t[0])
        v6_s, v6_e, v6_meta = map(list, zip(*combined_v6))

    _starts_v4, _ends_v4, _meta_v4 = (v4_s if v4_s else None, v4_e if v4_e else None, v4_meta if v4_meta else None)
    _starts_v6, _ends_v6, _meta_v6 = (v6_s if v6_s else None, v6_e if v6_e else None, v6_meta if v6_meta else None)

    # free verbose ranges list and hint GC
    try:
        _ranges.clear()
        _ranges = None
    except Exception:
        _ranges = None
    try:
        import gc
        gc.collect()
    except Exception:
        pass
    _built = True


def load(force: bool = False) -> bool:
    """
    Load ranges DB from disk into module cache and build trie.
    If missing or force=True, build() will be invoked.
    """
    global _ranges, _last_update
    db_path = get_rir_path()
    payload = load_json_cache(db_path)
    if payload and not force:
        ranges = payload.get("ranges", []) or []
        if ranges:
            _last_update = int(payload.get("timestamp", 0) or 0)
            _ranges = ranges
            _build_arrays_from_ranges()
            return True
    return bool(build(force=force))


def build(
    force: bool = False,
    log: Optional[LogFn] = None,
    progress: Optional[ProgressFn] = None,
) -> bool:
    """
    Download RIR delegated files and construct the ranges list used for lookups.
    """
    global _ranges, _last_update
    info = build_info("rir build", log)

    info("starting RIR build")
    if not force:
        try:
            payload = load_json_cache(get_rir_path())
            if payload:
                ranges = payload.get("ranges", []) or []
                if ranges:
                    _last_update = int(payload.get("timestamp", 0) or 0)
                    _ranges = ranges
                    n = len(_ranges)
                    _build_arrays_from_ranges()
                    info(f"using cached RIR data ({n} ranges)")
                    return True
                info("cached RIR data is empty — rebuilding")
        except Exception as e:
            info(f"could not read cache: {e}")

    if not force and _ranges:
        info(f"using in-memory RIR data ({len(_ranges)} ranges)")
        return True

    temp: List[Dict[str, Any]] = []
    for src in SOURCES:
        host = src.split("/")[2] if "://" in src else src
        name = host.replace("ftp.", "").split(".")[0].upper()
        info(f"fetching {name}")
        try:
            txt = fetch_text(src, progress=progress, log=info)
            if not txt:
                info(f"no data from {src}")
                continue
            entries = parse_rir_delegated(txt, src) or []
            info(f"parsed {len(entries)} entries")
            temp.extend(entries)
        except Exception as e:
            info(f"failed to fetch/parse {src}: {e}")
            continue

    temp = [r for r in temp if (r.get("start") is not None and r.get("end") is not None) or r.get("prefix")]
    if not temp:
        info("no RIR ranges parsed — not saving an empty cache")
        return False
    temp.sort(key=lambda r: r.get("start", 0))

    _ranges = temp
    _last_update = int(time.time())
    try:
        save_json_cache(get_rir_path(), {"timestamp": _last_update, "ranges": _ranges})
        info(f"saved {len(_ranges)} RIR ranges")
    except Exception as e:
        info(f"failed to save cache: {e}")

    _build_arrays_from_ranges()
    return True


def get_fetched_at() -> int:
    """Return last update timestamp (seconds since epoch)."""
    return int(_last_update or 0)


def get_country(ip: str) -> Optional[Dict[str, Any]]:
    """
    Return RIR allocation info for ip or None.
    Fast path: parse ip once, pick the per-version trie and lookup.
    """
    # parse once
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return None

    # ensure arrays are built (one-time)
    global _built
    if not _built:
        try:
            load(force=False)
        except Exception:
            pass

    try:
        if ip_obj.version == 4:
            if not _starts_v4:
                return None
            country = _covering_country(_starts_v4, _ends_v4, _meta_v4, int(ip_obj))
            if not country:
                return None
            return {"country": country, **lookup_fields(country)}
        if not _starts_v6:
            return None
        country = _covering_country(_starts_v6, _ends_v6, _meta_v6, int(ip_obj))
        if not country:
            return None
        return {"country": country, **lookup_fields(country)}
    except Exception:
        return None


def _covering_country(starts, ends, meta, ip_i) -> Optional[str]:
    """Last (most specific start) range that actually contains ip_i."""
    if not starts:
        return None
    i = bisect_right(starts, ip_i) - 1
    while i >= 0:
        if starts[i] <= ip_i <= ends[i]:
            return meta[i] or "??"
        i -= 1
    return None


def _ensure_loaded() -> None:
    global _built
    if not _built:
        try:
            load(force=False)
        except Exception:
            pass


def _range_cidrs(start: int, end: int, version: int) -> List[str]:
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return [str(net) for net in ipaddress.summarize_address_range(cls(int(start)), cls(int(end)))]


def cidrs_for_country(code: str) -> Optional[Dict[str, Any]]:
    """All RIR allocation CIDRs for a country. No new dataset; scans loaded arrays."""
    cc = canonical_country(code)
    if not cc:
        return None
    _ensure_loaded()
    v4: List[str] = []
    v6: List[str] = []
    if _meta_v4 and _starts_v4 is not None and _ends_v4 is not None:
        for i, meta in enumerate(_meta_v4):
            if canonical_country(meta) == cc:
                v4.extend(_range_cidrs(_starts_v4[i], _ends_v4[i], 4))
    if _meta_v6 and _starts_v6 is not None and _ends_v6 is not None:
        for i, meta in enumerate(_meta_v6):
            if canonical_country(meta) == cc:
                v6.extend(_range_cidrs(_starts_v6[i], _ends_v6[i], 6))
    return {
        "country": cc,
        "prefixes": v4 + v6,
        "count": len(v4) + len(v6),
        "ipv4": len(v4),
        "ipv6": len(v6),
    }


def shrink() -> None:
    """
    Drop the retained _ranges list to release Python-side duplicates.
    Tries remain available for fast lookups.
    """
    global _ranges, _starts_v4, _ends_v4, _meta_v4, _starts_v6, _ends_v6, _meta_v6, _built
    try:
        _ranges = None
    except Exception:
        pass
    # optionally drop arrays/meta as well (keep them by default)
    # _starts_v4 = _ends_v4 = _meta_v4 = None
    # _starts_v6 = _ends_v6 = _meta_v6 = None
    _built = bool(_starts_v4 or _starts_v6)
    # force a GC pass to try reclaiming freed objects immediately
    try:
        import gc
        gc.collect()
    except Exception:
        pass
