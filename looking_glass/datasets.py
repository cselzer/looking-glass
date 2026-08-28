"""Lookup datasets: on-disk files, refresh due, rebuild without Click."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .dns import register as tlds_mod
from .dns import resolve
from .intel import asn as asn_mod
from .intel import asn_org, iana, rir
from .utility import get_cache_path

LogFn = Callable[[str], None]

# Fast datasets first; ASN RIB download is last because it can take minutes.
DATASETS: Tuple[Tuple[str, Any, str, str], ...] = (
    ("iana", iana, "iana.json", "IANA special registries"),
    ("dns_types", resolve, "dns_types.json", "IANA DNS RR types"),
    ("tlds", tlds_mod, "tlds.json", "IANA TLD list"),
    ("rir", rir, "rir.json", "RIR country allocations"),
    ("asn_org", asn_org, "asn2org.json", "ASN organization names"),
    ("asn", asn_mod, "asn_prefix.ipasn.dat", "ASN origin prefixes"),
)

# Empty JSON caches (e.g. {"timestamp": …, "ranges": []}) are a few dozen bytes.
EMPTY_CACHE_BYTES = {
    "rir.json": 256,
    "iana.json": 256,
}


def file_row(filename: str) -> Dict[str, Any]:
    path = get_cache_path(filename)
    if not os.path.exists(path):
        return {"path": path, "exists": False, "size": None, "mtime": None}
    st = os.stat(path)
    empty_limit = EMPTY_CACHE_BYTES.get(filename)
    if empty_limit is not None and st.st_size <= empty_limit:
        return {"path": path, "exists": False, "size": st.st_size, "mtime": st.st_mtime}
    return {"path": path, "exists": True, "size": st.st_size, "mtime": st.st_mtime}


def refresh_due_at(mtime: Optional[float], days: Optional[int]) -> Optional[float]:
    if mtime is None or days is None:
        return None
    return mtime + (days * 86400)


def _as_log_fn(log: Any) -> Optional[LogFn]:
    if log is None:
        return None
    if callable(log) and not hasattr(log, "info"):
        return log  # type: ignore[return-value]
    if hasattr(log, "info"):
        def _write(msg: str) -> None:
            log.info("%s", msg)

        return _write
    return None


def _dataset_due(
    key: str,
    filename: str,
    *,
    now: float,
    days: Optional[int],
    force: bool,
) -> Tuple[bool, Dict[str, Any]]:
    info = file_row(filename)
    due = force or not info["exists"]
    if not due and days is not None:
        at = refresh_due_at(info["mtime"], days)
        due = at is not None and at <= now
    return due, info


def due_keys(
    *,
    now: Optional[float] = None,
    policy: Optional[Dict[str, Any]] = None,
    force: bool = False,
) -> List[str]:
    """Dataset keys that would rebuild (missing or past refresh days)."""
    from .config import refresh_policy

    current = now if now is not None else time.time()
    if policy is None:
        policy = refresh_policy()
    days_map = (policy or {}).get("days") or {}
    keys: List[str] = []
    for key, _mod, filename, _label in DATASETS:
        days = days_map.get(key)
        due, _info = _dataset_due(key, filename, now=current, days=days, force=force)
        if due:
            keys.append(key)
    return keys


def rebuild_due(
    *,
    now: Optional[float] = None,
    policy: Optional[Dict[str, Any]] = None,
    log: Any = None,
    force: bool = False,
) -> List[Dict[str, Any]]:
    """Build then load any dataset whose file is missing or past config refresh days."""
    from .config import refresh_policy

    current = now if now is not None else time.time()
    if policy is None:
        policy = refresh_policy()
    days_map = (policy or {}).get("days") or {}
    logger = log if hasattr(log, "info") else logging.getLogger("looking_glass.datasets")
    log_fn = _as_log_fn(log) or _as_log_fn(logger)
    results: List[Dict[str, Any]] = []
    for key, mod, filename, label in DATASETS:
        days = days_map.get(key)
        due, info = _dataset_due(key, filename, now=current, days=days, force=force)
        if not due:
            results.append(
                {
                    "key": key,
                    "label": label,
                    "result": "up_to_date",
                    "error": None,
                }
            )
            continue
        logger.info("rebuild start %s", key)
        t0 = time.time()
        err: Optional[str] = None
        ok = False
        try:
            ok = bool(mod.build(force=True, log=log_fn))
            if ok and hasattr(mod, "load"):
                mod.load(force=True)
        except Exception as exc:
            ok = False
            err = str(exc)
            logger.exception("rebuild failed %s", key)
        if not ok and err is None:
            err = "build failed"
        logger.info("rebuild end %s", key)
        results.append(
            {
                "key": key,
                "label": label,
                "result": "ok" if ok else "failed",
                "elapsed_s": round(time.time() - t0, 2),
                "error": err,
            }
        )
    return results
