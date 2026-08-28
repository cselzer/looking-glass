"""HTTP inspector: status chain, redirects, headers, TTFB, protocol."""

from __future__ import annotations

import asyncio
import re
import ssl
import time
import ipaddress
import urllib.parse
from http.client import BadStatusLine, HTTPConnection, HTTPSConnection
from typing import Any, Dict, List, Optional, Tuple

from .host import bracket_host, format_hostport, restore_collapsed_slashes, unbracket_host


_SCHEME_URL = re.compile(r"^([a-z][a-z0-9+.-]*):/+(.*)$", re.I)
_BARE_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:$", re.I)
_H2_ERROR = "http2_handshake_failed"


def _looks_binary(text: str) -> bool:
    for ch in text:
        code = ord(ch)
        if ch in "\t\n\r":
            continue
        if code < 32 or code == 0x7F:
            return True
    return False


def _probe_error(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, BadStatusLine):
        return _H2_ERROR
    text = str(exc) or type(exc).__name__
    if _looks_binary(text):
        return _H2_ERROR
    return text


def parse_http_path(path: str) -> str:
    text = restore_collapsed_slashes(urllib.parse.unquote(str(path or ""))).strip()
    if text.startswith("/"):
        text = text[1:]
    if text != "http" and not text.startswith("http/"):
        raise ValueError("not an http path")
    rest = "" if text == "http" else text[len("http/") :]
    return rest


def http_envelope_query(parsed: str, query_string: str = "") -> str:
    """Envelope query for /http/…: restore collapsed `https:/host`, honor ?url= / ?scheme=.

    Host-only `/http/example.com` stays `example.com` unless `?scheme=` or `?url=` is set.
    Full URLs belong in `?url=` so Apache never sees `%2F` in the path.
    """
    qs = urllib.parse.parse_qs(query_string or "", keep_blank_values=False)
    url_param = ((qs.get("url") or [""])[0]).strip()
    if url_param:
        value = _normalize_http_target(restore_collapsed_slashes(url_param))
        scheme = urllib.parse.urlsplit(value).scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("scheme must be http or https")
        return value
    text = restore_collapsed_slashes(str(parsed or "")).strip()
    if not text:
        raise ValueError("http path needs a host or URL, e.g. /http/example.com")
    if _SCHEME_URL.match(text) or "://" in text:
        value = _normalize_http_target(text)
        scheme = urllib.parse.urlsplit(value).scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError("scheme must be http or https")
        return value
    scheme = ((qs.get("scheme") or [""])[0]).lower()
    if scheme in {"http", "https"} and "://" not in text:
        return f"{scheme}://{text}"
    return text


def _authority_url(scheme: str, host: str, port: Optional[int], path: str) -> str:
    netloc = bracket_host(host)
    if port is not None:
        netloc = f"{netloc}:{int(port)}"
    if not path.startswith("/"):
        path = "/" + path
    if path == "/":
        return f"{scheme}://{netloc}"
    return f"{scheme}://{netloc}{path}"


def _split_schemeless(raw: str) -> Tuple[str, Optional[int], str]:
    """Host, optional port, and path from a schemeless target."""
    text = str(raw or "").strip()
    if not text:
        raise ValueError("http path needs a host")
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError("http path needs a host")
        host = text[1:end]
        rest = text[end + 1 :]
        port: Optional[int] = None
        path = "/"
        if rest.startswith(":"):
            rest = rest[1:]
            if "/" in rest:
                port_s, tail = rest.split("/", 1)
                path = "/" + tail
            else:
                port_s = rest
            if not port_s.isdigit():
                raise ValueError("http port must be an integer")
            port = int(port_s)
        elif rest.startswith("/"):
            path = rest
        elif rest:
            raise ValueError("http path needs a host")
        return host, port, path
    if "/" in text:
        auth, tail = text.split("/", 1)
        path = "/" + tail
    else:
        auth, path = text, "/"
    if auth.count(":") >= 2:
        try:
            ipaddress.ip_address(auth)
            return auth, None, path
        except ValueError:
            pass
    if ":" in auth:
        host, port_s = auth.rsplit(":", 1)
        if port_s.isdigit():
            port = int(port_s)
            if not 1 <= port <= 65535:
                raise ValueError("http port must be 1–65535")
            return host, port, path
    return auth, None, path


def _normalize_http_target(target: str) -> str:
    """Turn a host, URL, or path leftover (`https:/host`) into a real URL.

    Putting `https://…` in `/http/<target>` is fragile: proxies collapse `//`,
    and the leftover `https` is then looked up as a hostname.
    """
    raw = restore_collapsed_slashes(str(target or "")).strip()
    if not raw:
        raise ValueError("http path needs a host")
    peeled = _SCHEME_URL.match(raw)
    if peeled:
        scheme = peeled.group(1).lower()
        rest = peeled.group(2)
        nested = _SCHEME_URL.match(rest)
        if nested:
            scheme = nested.group(1).lower()
            rest = nested.group(2)
        rest = rest.lstrip("/")
        if not rest or _BARE_SCHEME.fullmatch(rest):
            raise ValueError("http path needs a host")
        host, port, path = _split_schemeless(rest)
        return _authority_url(scheme, host, port, path)
    if _BARE_SCHEME.fullmatch(raw):
        raise ValueError("http path needs a host")
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        host = unbracket_host(parsed.hostname or parsed.netloc or "")
        if not host:
            raise ValueError("http path needs a host")
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return _authority_url(scheme, host, port, path)
    host, port, path = _split_schemeless(raw)
    if port == 80:
        scheme = "http"
    elif port == 443:
        scheme = "https"
    else:
        scheme = "https"
    return _authority_url(scheme, host, port, path)


def _split_target(target: str) -> Tuple[str, str, int, str]:
    text = _normalize_http_target(target)
    parsed = urllib.parse.urlsplit(text)
    scheme = (parsed.scheme or "https").lower()
    host = parsed.hostname or parsed.netloc
    if host:
        host = unbracket_host(str(host))
    if not host:
        raise ValueError("http path needs a host")
    if scheme not in {"http", "https"}:
        raise ValueError("scheme must be http or https")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return scheme, host, int(port), path


def _read_response(conn: HTTPConnection, path: str, host: str) -> Dict[str, Any]:
    t0 = time.perf_counter()
    conn.request("GET", path, headers={"Host": host, "User-Agent": "looking-glass/http", "Accept": "*/*"})
    response = conn.getresponse()
    ttfb_ms = (time.perf_counter() - t0) * 1000.0
    body = response.read(65536)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    headers = {k: v for k, v in response.getheaders()}
    location = response.getheader("Location")
    return {
        "status": int(response.status),
        "reason": response.reason,
        "http_version": f"HTTP/{response.version // 10}.{response.version % 10}",
        "headers": headers,
        "location": location,
        "ttfb_ms": round(ttfb_ms, 3),
        "elapsed_ms": round(elapsed_ms, 3),
        "bytes": len(body),
        "hsts": headers.get("Strict-Transport-Security"),
        "server": headers.get("Server"),
        "content_type": headers.get("Content-Type"),
    }


def inspect_http(target: str, timeout: float = 8.0, max_redirects: int = 8) -> Dict[str, Any]:
    start = time.time()
    try:
        scheme, host, port, path = _split_target(target)
    except ValueError as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": 0.0}
    chain: List[Dict[str, Any]] = []
    alpn = None
    error = None
    current = (scheme, host, port, path)
    seen = set()
    try:
        for _ in range(max_redirects + 1):
            scheme, host, port, path = current
            key = (scheme, host, port, path)
            if key in seen:
                error = "redirect loop"
                break
            seen.add(key)
            hop_start = time.perf_counter()
            hop_host = bracket_host(host)
            if scheme == "https":
                ctx = ssl.create_default_context()
                # HTTP/1.1 only. Offering h2 makes the peer send a SETTINGS preface
                # that http.client then raises as BadStatusLine with raw bytes.
                ctx.set_alpn_protocols(["http/1.1"])
                conn: HTTPConnection = HTTPSConnection(hop_host, port=port, timeout=timeout, context=ctx)
            else:
                conn = HTTPConnection(hop_host, port=port, timeout=timeout)
            try:
                conn.connect()
                sock = getattr(conn, "sock", None)
                if sock is not None and hasattr(sock, "selected_alpn_protocol"):
                    alpn = sock.selected_alpn_protocol() or alpn
                hop = _read_response(conn, path, hop_host)
            finally:
                conn.close()
            hop["url"] = f"{scheme}://{format_hostport(host, port)}{path}"
            hop["connect_ms"] = round((time.perf_counter() - hop_start) * 1000.0, 3)
            hop["alpn"] = alpn
            chain.append(hop)
            loc = hop.get("location")
            if hop["status"] in {301, 302, 303, 307, 308} and loc:
                nxt = urllib.parse.urljoin(hop["url"], loc)
                current = _split_target(nxt)
                continue
            break
        else:
            error = "too many redirects"
        result = {
            "query": target,
            "final_url": chain[-1]["url"] if chain else None,
            "status": chain[-1]["status"] if chain else None,
            "http_version": chain[-1].get("http_version") if chain else None,
            "alpn": alpn,
            "ttfb_ms": chain[0]["ttfb_ms"] if chain else None,
            "redirects": max(0, len(chain) - 1),
            "hsts": chain[-1].get("hsts") if chain else None,
            "chain": chain,
        }
        return {
            "ok": error is None and bool(chain),
            "result": result,
            "error": error,
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }
    except Exception as exc:
        return {
            "ok": False,
            "result": {"query": target, "chain": chain} if chain else None,
            "error": _probe_error(exc),
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }


async def inspect_http_async(
    target: str, timeout: float = 8.0, max_redirects: int = 8
) -> Dict[str, Any]:
    return await asyncio.to_thread(inspect_http, target, timeout, max_redirects)
