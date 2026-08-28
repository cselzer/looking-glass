"""PTR plus forward-confirmed reverse DNS (FCrDNS)."""

from __future__ import annotations

import asyncio
import ipaddress
import time
import urllib.parse
from typing import Any, Dict, List

from ..net.host import unbracket_host


def parse_ptr_path(path: str) -> str:
    text = urllib.parse.unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "ptr" and not text.startswith("ptr/"):
        raise ValueError("not a ptr path")
    rest = "" if text == "ptr" else text[len("ptr/") :]
    if not rest:
        raise ValueError("ptr path needs an IP, e.g. /ptr/1.1.1.1")
    try:
        return str(ipaddress.ip_address(unbracket_host(rest)))
    except ValueError as exc:
        raise ValueError("ptr path needs an IP, e.g. /ptr/1.1.1.1") from exc


async def check_ptr_async(target: str, timeout: float = 4.0) -> Dict[str, Any]:
    from .resolve import lookup_dns_async

    start = time.time()
    try:
        ip = ipaddress.ip_address(str(target).strip())
    except ValueError as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": 0.0}
    ptr = await lookup_dns_async(str(ip), "PTR", timeout=timeout)
    names: List[str] = []
    for row in (ptr.get("result") or {}).get("answers") or []:
        data = str(row.get("data") or "").rstrip(".")
        if data:
            names.append(data)
    forwards: List[Dict[str, Any]] = []
    matched = False
    mapped = getattr(ip, "ipv4_mapped", None)
    for name in names:
        if mapped is not None:
            qtype = "A"
            expect = {str(mapped), str(ip)}
        elif ip.version == 6:
            qtype = "AAAA"
            expect = {str(ip)}
        else:
            qtype = "A"
            expect = {str(ip)}
        look = await lookup_dns_async(name, qtype, timeout=timeout)
        addrs = [
            str(row.get("data") or "")
            for row in (look.get("result") or {}).get("answers") or []
        ]
        hit = any(addr in expect for addr in addrs)
        matched = matched or hit
        forwards.append({"name": name, "type": qtype, "addresses": addrs, "matches": hit})
    result = {
        "ip": str(ip),
        "ptr": names,
        "forward": forwards,
        "fcrdns": bool(names) and matched,
        "detail": (
            "PTR hostname resolves back to this IP."
            if matched
            else ("PTR exists but does not forward-confirm." if names else "No PTR.")
        ),
    }
    return {
        "ok": True,
        "result": result,
        "error": None if ptr.get("ok") or names else ptr.get("error"),
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


def check_ptr(target: str, timeout: float = 4.0) -> Dict[str, Any]:
    return asyncio.run(check_ptr_async(target, timeout=timeout))
