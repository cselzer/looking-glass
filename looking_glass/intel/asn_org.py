"""
ASN -> organization name loader using RIPE asn.txt

Data source:
    https://ftp.ripe.net/ripe/asnames/asn.txt

Each non-comment line is of the form:

    AS1234 Some Organization Name
    65000 Private AS
    # comment...

We normalize the first token to an integer ASN and treat the rest of the line
as the display name.

This module provides:

    - build(force: bool = False)  -> bool
    - load(force: bool = False)   -> bool
    - find_org(asn)               -> {"asn": int, "name": str} | None
    - get_fetched_at()            -> int (unix timestamp)

Cache format on disk (JSON):

    {
      "timestamp": <int>,
      "orgs": {
        "13335": "Cloudflare",
        "15169": "Google LLC",
        ...
      }
    }
"""
import re
import time
from typing import Dict, Any, Optional

from ..utility import (
    LogFn,
    ProgressFn,
    build_info,
    fetch_text,
    get_cache_path,
    load_json_cache,
    save_json_cache,
)

_ASN_TXT_URL = "https://ftp.ripe.net/ripe/asnames/asn.txt"
_CACHE_NAME = "asn2org.json"
# RIPE asn.txt is updated regularly but not minute-by-minute.
# A daily TTL is a reasonable default.
_CACHE_TTL = 86400  # 24 hours

_org_map: Optional[Dict[str, str]] = None
_fetched_at: int = 0
_meta_built: bool = False


def _cache_path() -> str:
    return get_cache_path(_CACHE_NAME)


def _normalize_asn_val(v: Any) -> Optional[int]:
    """Normalize various ASN representations to integer, or None if invalid."""
    try:
        if isinstance(v, int):
            return int(v)
        s = str(v).strip()
        if not s:
            return None
        s = s.upper()
        # handle "AS1234" or "AS 1234"
        s = s.replace("AS", "", 1).strip()
        # keep digits only
        s = re.sub(r"\D", "", s)
        return int(s) if s else None
    except Exception:
        return None


def _save_cache(org_map: Dict[str, str]) -> None:
    """Persist org_map and timestamp to disk (best-effort)."""
    global _org_map, _fetched_at, _meta_built
    _fetched_at = int(time.time())
    _org_map = org_map
    _meta_built = True
    try:
        save_json_cache(_cache_path(), {"timestamp": _fetched_at, "orgs": _org_map})
    except Exception:
        # cache errors are non-fatal
        pass


def _load_cache() -> bool:
    """Load JSON cache into memory."""
    global _org_map, _fetched_at, _meta_built
    payload = load_json_cache(_cache_path())
    if not payload:
        return False
    try:
        _fetched_at = int(payload.get("timestamp", 0) or 0)
        raw = payload.get("orgs", {}) or {}
        # normalize keys/values
        _org_map = {str(k): (v if isinstance(v, str) else str(v))
                    for k, v in raw.items()}
        _meta_built = True
        return True
    except Exception:
        return False


def load(force: bool = False) -> bool:
    """
    Load ASN->org cache from disk. Returns True on success.
    Does not attempt network fetch; build() is responsible for fetching.
    """
    if _load_cache():
        return True
    return False


def find_org(asn: Any) -> Optional[Dict[str, Any]]:
    """
    Return minimal org info for given ASN (int or string like 'AS1234').
    Returns None if not found.

    Shape:
        {"asn": <int>, "name": "<org name>"}
    """
    global _meta_built, _org_map
    if not _meta_built:
        try:
            _load_cache()
        except Exception:
            pass
    if not _org_map:
        return None

    asn_i = _normalize_asn_val(asn)
    if asn_i is None:
        return None

    name = _org_map.get(str(asn_i))
    if not name:
        return None

    return {"asn": int(asn_i), "name": name}


def get_fetched_at() -> int:
    return int(_fetched_at or 0)


def build(
    force: bool = False,
    log: Optional[LogFn] = None,
    progress: Optional[ProgressFn] = None,
) -> bool:
    """
    Download RIPE asn.txt and produce compact ASN->name map.

    Honors cache TTL: will not re-download if cache is fresh unless force=True.
    """
    info = build_info("asn_org build", log)
    info("starting ASN org build (RIPE asn.txt)")
    now = int(time.time())

    if not force:
        info("checking cache")
        try:
            if _load_cache():
                age = now - int(_fetched_at or 0)
                if age < _CACHE_TTL:
                    info(f"using cached org names ({age}s old)")
                    return True
                info("cache is older than 24h; refreshing")
        except Exception as e:
            info(f"could not load cache: {e}")

    info("downloading RIPE asn.txt")
    try:
        text = fetch_text(_ASN_TXT_URL, timeout=60, progress=progress, log=info)
        if not text:
            info("download failed")
            return False
    except Exception as e:
        info(f"download failed: {e}")
        return False

    org_map: Dict[str, str] = {}
    parsed = 0
    skipped = 0

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            skipped += 1
            continue

        asn_token = parts[0]
        name = " ".join(parts[1:]).strip()
        asn_val = _normalize_asn_val(asn_token)
        if asn_val is None or not name:
            skipped += 1
            continue

        org_map[str(asn_val)] = name
        parsed += 1

    if not org_map:
        info("no ASN→org entries parsed")
        return False

    info(f"parsed {parsed} names (skipped {skipped})")
    try:
        _save_cache(org_map)
        info("ASN org cache saved")
        return True
    except Exception as e:
        info(f"failed to save cache: {e}")
        return False