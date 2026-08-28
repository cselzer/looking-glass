# async-capable lookup client using aiohttp + UDS connector
import asyncio
import ipaddress
import json
import sys
import argparse
from dataclasses import dataclass
from collections import OrderedDict
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
from urllib.parse import quote
import threading

import aiohttp

from ..utility import get_data_dir

# default socket path (derived, not hard-coded)
LOOKUP_SOCKET = str(Path(get_data_dir()) / "lookup.sock")


def lookup_url(token: str) -> str:
    """HTTP URL for the UDS intel server: GET /{ip} or GET /{cc}."""
    text = str(token).strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        text = text[1:-1]
    try:
        return f"http://localhost/{ipaddress.ip_address(text)}"
    except ValueError:
        return f"http://localhost/{quote(text, safe='')}"


@dataclass
class IPContext:
    ip: str
    country: Optional[str] = None
    flag: Optional[str] = None
    country_name: Optional[str] = None
    flag_url: Optional[str] = None
    flag_html: Optional[str] = None
    asn: Optional[int] = None
    prefix: Optional[str] = None
    org_name: Optional[str] = None
    source: Optional[str] = None
    iana: Optional[Dict[str, Any]] = None
    timings: Optional[Dict[str, Any]] = None
    errors: Optional[Dict[str, Any]] = None
    total_ms: Optional[float] = None


async def lookup_ip_async(ip: str, socket_path: Optional[str] = None, timeout: float = 0.2, session: Optional[aiohttp.ClientSession] = None) -> Optional[IPContext]:
    """
    Async lookup over UDS; if session provided it will be reused, otherwise a temporary session is created.
    """
    sock = socket_path or LOOKUP_SOCKET
    own_session = False
    try:
        if session is None:
            conn = aiohttp.UnixConnector(path=sock)
            session = aiohttp.ClientSession(connector=conn)
            own_session = True

        # use http://localhost/ as base; aiohttp will send requests over UDS
        try:
            async with session.get(lookup_url(ip), timeout=timeout) as resp:
                txt = await resp.text()
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

        try:
            data = json.loads(txt)
        except Exception:
            return None

        if not data.get("ok"):
            return None
        result = data.get("result") or {}
        return IPContext(
            ip=result.get("ip", ip),
            country=result.get("country"),
            flag=result.get("flag"),
            country_name=result.get("country_name"),
            flag_url=result.get("flag_url"),
            flag_html=result.get("flag_html"),
            asn=result.get("asn"),
            prefix=result.get("prefix"),
            org_name=result.get("org_name"),
            source=result.get("source"),
            iana=result.get("iana"),
            timings=data.get("timings") or result.get("timings"),
            errors=data.get("errors") or result.get("errors"),
            total_ms=data.get("total_ms") or result.get("total_ms"),
        )
    finally:
        if own_session and session is not None:
            try:
                await session.close()
            except Exception:
                pass


# successful lookups only — never cache None (intel server blips would stick)
_OK: "OrderedDict[Tuple[str, Optional[str], float], IPContext]" = OrderedDict()
_OK_LOCK = threading.Lock()
_OK_MAX = 10000


def _lookup_ip_cache_clear() -> None:
    with _OK_LOCK:
        _OK.clear()


def lookup_ip(ip: str, socket_path: Optional[str] = None, timeout: float = 0.2) -> Optional[IPContext]:
    key = (str(ip), socket_path, float(timeout))
    with _OK_LOCK:
        hit = _OK.get(key)
        if hit is not None:
            _OK.move_to_end(key)
            return hit
    result = asyncio.run(lookup_ip_async(ip, socket_path=socket_path, timeout=timeout))
    if result is not None:
        with _OK_LOCK:
            _OK[key] = result
            _OK.move_to_end(key)
            while len(_OK) > _OK_MAX:
                _OK.popitem(last=False)
    return result


lookup_ip.cache_clear = _lookup_ip_cache_clear


def lookup_json(
    ip: str, socket_path: Optional[str] = None, timeout: float = 0.5
) -> Optional[Dict[str, Any]]:
    """Return the intel server's JSON payload, or None if the socket is down."""

    try:
        return asyncio.run(lookup_json_async(ip, socket_path=socket_path, timeout=timeout))
    except Exception:
        return None


async def lookup_json_async(
    ip: str,
    socket_path: Optional[str] = None,
    timeout: float = 0.5,
    session: Optional[aiohttp.ClientSession] = None,
) -> Optional[Dict[str, Any]]:
    """Daemon JSON lookup. Pass a shared session when doing many IPs."""
    sock = socket_path or LOOKUP_SOCKET
    own_session = False
    if session is None:
        conn = aiohttp.UnixConnector(path=sock)
        session = aiohttp.ClientSession(connector=conn)
        own_session = True
    try:
        async with session.get(lookup_url(ip), timeout=timeout) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
        if not isinstance(data, dict) or not data.get("ok"):
            return None
        return data
    except Exception:
        return None
    finally:
        if own_session:
            await session.close()


async def _main_async(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(prog="python -m looking_glass.intel_server.client")
    p.add_argument("ip", help="IP address to lookup")
    p.add_argument("--socket", help="Override lookup socket path (optional)", default=None)
    p.add_argument("--timeout", type=float, default=0.2, help="request timeout seconds")
    args = p.parse_args(argv)

    res = await lookup_ip_async(args.ip, socket_path=args.socket, timeout=args.timeout)
    if res is None:
        print(json.dumps({"ok": False, "ip": args.ip, "result": None}))
        raise SystemExit(2)

    out = {
        "ok": True,
        "ip": res.ip,
        "country": res.country,
        "flag": res.flag,
        "country_name": res.country_name,
        "flag_url": res.flag_url,
        "flag_html": res.flag_html,
        "asn": res.asn,
        "prefix": res.prefix,
        "org_name": res.org_name,
        "source": res.source,
        "iana": res.iana,
        "timings": res.timings,
        "errors": res.errors,
        "total_ms": res.total_ms,
    }
    print(json.dumps(out, ensure_ascii=False))


def main(argv=None):
    asyncio.run(_main_async(argv))


if __name__ == "__main__":
    main()