"""BGP origin and RPKI ROA status via RIPEstat."""

from __future__ import annotations

import asyncio
import ipaddress
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple

import requests

from .. import cache as query_cache

RIPE = "https://stat.ripe.net/data"


def parse_bgp_path(path: str) -> str:
    text = urllib.parse.unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "bgp" and not text.startswith("bgp/"):
        raise ValueError("not a bgp path")
    rest = "" if text == "bgp" else text[len("bgp/") :]
    if not rest:
        raise ValueError("bgp path needs an IP or prefix, e.g. /bgp/1.1.1.1")
    return rest


def _get(url: str, timeout: float = 8.0) -> Dict[str, Any]:
    response = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
    response.raise_for_status()
    body = response.json()
    return body.get("data") if isinstance(body, dict) else {}


def _resource(target: str) -> Tuple[str, Optional[str]]:
    text = str(target).strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
        return str(net), None
    except ValueError:
        pass
    addr = ipaddress.ip_address(text)
    return str(addr), None


def check_bgp(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    start = time.time()
    try:
        resource, _ = _resource(target)
    except ValueError as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": 0.0}
    hit = query_cache.get("bgp", resource)
    if hit is not None:
        return {
            "ok": True,
            "result": hit,
            "error": None,
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }
    try:
        overview = _get(
            f"{RIPE}/prefix-overview/data.json?resource={urllib.parse.quote(resource)}",
            timeout=timeout,
        ) or {}
        prefix = overview.get("resource") or resource
        asns = []
        for row in overview.get("asns") or []:
            if isinstance(row, dict):
                asns.append(
                    {
                        "asn": row.get("asn"),
                        "holder": row.get("holder"),
                    }
                )
        origin = asns[0]["asn"] if asns else None
        rpki: Dict[str, Any] = {}
        if origin is not None and prefix:
            rpki = _get(
                f"{RIPE}/rpki-validation/data.json?resource={origin}&prefix={urllib.parse.quote(str(prefix))}",
                timeout=timeout,
            ) or {}
        status = str(rpki.get("status") or rpki.get("validating_roas") and "valid" or "unknown")
        if not rpki:
            status = "not found"
        result = {
            "query": resource,
            "prefix": prefix,
            "origins": asns,
            "origin_asn": origin,
            "announced": bool(overview.get("announced")),
            "rpki": {
                "status": str(rpki.get("status") or status).lower(),
                "validator": rpki.get("validator"),
                "roas": rpki.get("validating_roas") or rpki.get("roas") or [],
            },
            "block": overview.get("block"),
            "holder": overview.get("holder") or (asns[0].get("holder") if asns else None),
        }
        query_cache.put("bgp", resource, result)
        return {
            "ok": True,
            "result": result,
            "error": None,
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }
    except Exception as exc:
        stale = query_cache.get_any("bgp", resource)
        if stale is not None:
            return {
                "ok": True,
                "result": stale,
                "error": None,
                "total_ms": round((time.time() - start) * 1000.0, 3),
            }
        return {
            "ok": False,
            "result": None,
            "error": str(exc) or exc.__class__.__name__,
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }


async def check_bgp_async(target: str, timeout: float = 8.0) -> Dict[str, Any]:
    return await asyncio.to_thread(check_bgp, target, timeout)
