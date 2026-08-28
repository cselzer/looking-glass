"""TCP connect check: RTT and an optional banner peek."""

from __future__ import annotations

import asyncio
import errno
import socket
import time
import urllib.parse
from typing import Any, Dict, Tuple

from .host import format_hostport, resolve_probe_host, restore_collapsed_slashes, unbracket_host, reject_probe_target, reject_url_as_host

_REFUSED = {errno.ECONNREFUSED, 10061}
_TIMEOUT = {errno.ETIMEDOUT, 10060}
_UNREACH = {
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.EHOSTDOWN,
    errno.ENETDOWN,
    10051,
    10065,
}
_RESET = {errno.ECONNRESET, errno.EPIPE, 10054}
_ETIME = getattr(errno, "ETIME", None)
if _ETIME is not None:
    _TIMEOUT.add(_ETIME)


def parse_tcp_path(path: str) -> Tuple[str, int]:
    text = restore_collapsed_slashes(urllib.parse.unquote(str(path or ""))).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "tcp" and not text.startswith("tcp/"):
        raise ValueError("not a tcp path")
    rest = "" if text == "tcp" else text[len("tcp/") :]
    if not rest:
        raise ValueError("tcp path needs host/port, e.g. /tcp/example.com/443")
    if "://" in rest or rest.lower().startswith("//"):
        raise ValueError("host is not a URL")
    reject_url_as_host(rest.split("/")[0])
    if "/" not in rest:
        host = unbracket_host(rest)
        reject_probe_target(host)
        return host, 443
    host, port_s = rest.rsplit("/", 1)
    try:
        port = int(port_s)
    except ValueError as exc:
        raise ValueError("tcp port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("tcp port must be 1–65535")
    if not host:
        raise ValueError("tcp path needs a host")
    host = unbracket_host(host)
    reject_probe_target(host)
    return host, port


def fail_status(exc: BaseException) -> str:
    if isinstance(exc, socket.gaierror):
        return "resolve"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    err = getattr(exc, "errno", None)
    if err in _REFUSED:
        return "refused"
    if err in _TIMEOUT:
        return "timeout"
    if err in _UNREACH:
        return "unreach"
    if err in _RESET:
        return "reset"
    msg = str(exc).lower()
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if "refused" in msg:
        return "refused"
    if "name or service not known" in msg or "nodename nor servname" in msg or "not known" in msg:
        return "resolve"
    if "unreachable" in msg:
        return "unreach"
    if "reset" in msg:
        return "reset"
    return "error"


def check_tcp(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    start = time.time()
    peer = None
    banner = None
    error = None
    status = "ok"
    rtt_ms = None
    t0 = time.perf_counter()
    host = unbracket_host(host)
    try:
        _ip, family, sockaddr = resolve_probe_host(host, port=int(port), socktype=socket.SOCK_STREAM)
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            rtt_ms = (time.perf_counter() - t0) * 1000.0
            peer = sock.getpeername()
            sock.settimeout(min(timeout, 1.5))
            try:
                sock.sendall(b"\r\n")
            except Exception:
                pass
            try:
                buf = sock.recv(256)
                if buf:
                    banner = buf.decode("utf-8", "replace").strip()
            except Exception:
                banner = None
        finally:
            sock.close()
    except Exception as exc:
        rtt_ms = (time.perf_counter() - t0) * 1000.0
        error = str(exc) or exc.__class__.__name__
        status = fail_status(exc)
    peer_s = None
    if peer:
        peer_s = format_hostport(str(peer[0]).split("%", 1)[0], int(peer[1]))
    result = {
        "host": host,
        "port": int(port),
        "ok": error is None,
        "status": status,
        "peer": peer_s,
        "rtt_ms": None if rtt_ms is None else round(rtt_ms, 3),
        "banner": banner,
        "error": error,
    }
    return {
        "ok": error is None,
        "result": result,
        "error": error,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


async def check_tcp_async(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    return await asyncio.to_thread(check_tcp, host, port, timeout)
