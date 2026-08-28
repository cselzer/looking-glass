"""Path MTU discovery via ping don't-fragment probes."""

from __future__ import annotations

import asyncio
import ipaddress
import platform
import shutil
import subprocess
import time
import urllib.parse
from typing import Any, Dict, Optional, Tuple


def parse_pmtu_path(path: str) -> str:
    text = urllib.parse.unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "pmtu" and not text.startswith("pmtu/"):
        raise ValueError("not a pmtu path")
    rest = "" if text == "pmtu" else text[len("pmtu/") :]
    if not rest:
        raise ValueError("pmtu path needs a host, e.g. /pmtu/1.1.1.1")
    from .host import unbracket_host

    return unbracket_host(rest)


def _is_ipv6_host(host: str) -> bool:
    text = str(host or "").strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        text = text[1:-1]
    text = text.split("%", 1)[0]
    try:
        return ipaddress.ip_address(text).version == 6
    except ValueError:
        return False


def _ping_cmd(host: str, payload: int) -> Optional[list[str]]:
    v6 = _is_ipv6_host(host)
    target = host.strip()
    if target.startswith("[") and target.endswith("]") and len(target) > 2:
        target = target[1:-1]
    ping6 = shutil.which("ping6")
    ping = shutil.which("ping")
    system = platform.system()
    if v6 and ping6:
        binary, force6 = ping6, []
    elif ping:
        binary, force6 = ping, (["-6"] if v6 else [])
    else:
        return None
    if system == "Darwin":
        return [binary, *force6, "-c", "1", "-t", "2", "-D", "-s", str(payload), target]
    return [binary, *force6, "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), target]


def _probe(host: str, payload: int) -> Tuple[bool, str]:
    cmd = _ping_cmd(host, payload)
    if not cmd:
        return False, "ping is not installed"
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
    except Exception as exc:
        return False, str(exc) or exc.__class__.__name__
    text = (proc.stdout or "") + (proc.stderr or "")
    low = text.lower()
    if proc.returncode == 0 and ("bytes from" in low or "icmp_seq" in low):
        return True, text.strip().splitlines()[-1] if text.strip() else "ok"
    return False, text.strip().splitlines()[-1] if text.strip() else f"exit {proc.returncode}"


def check_pmtu(host: str, timeout: float = 20.0) -> Dict[str, Any]:
    start = time.time()
    if not _ping_cmd(host, 56):
        return {
            "ok": False,
            "result": None,
            "error": "ping is not available for DF probes",
            "total_ms": 0.0,
        }
    v6 = _is_ipv6_host(host)
    header = 48 if v6 else 28
    lo, hi = 68, (1452 if v6 else 1472)
    best = None
    probes = []
    error = None
    while lo <= hi and (time.time() - start) < timeout:
        mid = (lo + hi) // 2
        ok, detail = _probe(host, mid)
        probes.append({"payload": mid, "ok": ok, "detail": detail})
        if ok:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
            if "not installed" in detail:
                error = detail
                break
    mtu = None if best is None else best + header
    result = {
        "host": host,
        "payload_bytes": best,
        "path_mtu": mtu,
        "header_bytes": header,
        "probes": probes[-12:],
        "note": (
            "ICMPv6 echo. Path MTU ≈ payload + 40 IPv6 + 8 ICMPv6."
            if v6
            else "ICMP echo with don't-fragment. Path MTU ≈ payload + 20 IP + 8 ICMP."
        ),
    }
    return {
        "ok": best is not None,
        "result": result,
        "error": None if best is not None else (error or "no DF echo replies"),
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


async def check_pmtu_async(host: str, timeout: float = 20.0) -> Dict[str, Any]:
    return await asyncio.to_thread(check_pmtu, host, timeout)
