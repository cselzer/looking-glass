"""HTTP content-encoding: gzip and brotli, negotiated from Accept-Encoding."""

from __future__ import annotations

import gzip
import hashlib
import inspect
import io
import threading
import zlib
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Callable, Dict, List, Optional, Tuple

import brotli

HeaderList = List[Tuple[str, str]]
AsgiHeaders = List[Tuple[bytes, bytes]]

GZIP_LEVEL = 5
BROTLI_QUALITY = 4
DEFAULT_MIN_BYTES = 1024
DEFAULT_MAX_REQUEST = 1024 * 1024
ACME_PREFIX = "/.well-known/acme-challenge/"
VARY_TOKEN = "Accept-Encoding"

_COMPRESSIBLE_EXACT = {
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
    "image/svg+xml",
}
_SKIP_STATUS = frozenset({204, 304})
_CACHE_MAX = 32

_cache_lock = threading.Lock()
_cache: Dict[Tuple[str, bytes], bytes] = {}
_cache_order: List[Tuple[str, bytes]] = []


class PayloadTooLarge(Exception):
    """Decompressed request exceeded the configured cap."""


class UnsupportedEncoding(Exception):
    """Content-Encoding is not gzip or brotli."""


class BadEncoding(Exception):
    """Content-Encoding payload is truncated or corrupt."""


@dataclass(frozen=True)
class CompressSettings:
    gzip: bool = True
    brotli: bool = True
    min_bytes: int = DEFAULT_MIN_BYTES
    max_request_bytes: int = DEFAULT_MAX_REQUEST

    @property
    def any_codec(self) -> bool:
        return bool(self.gzip or self.brotli)


def load_settings() -> CompressSettings:
    try:
        from ..config import load

        http = load().get("http") or {}
        raw = http.get("compress") if isinstance(http, dict) else None
    except Exception:
        raw = None
    return settings_from_raw(raw)


def settings_from_raw(raw: Any) -> CompressSettings:
    data = raw if isinstance(raw, dict) else {}
    gzip_on = True if "gzip" not in data else bool(data.get("gzip"))
    brotli_on = True if "brotli" not in data else bool(data.get("brotli"))
    try:
        min_bytes = int(data.get("min_bytes", DEFAULT_MIN_BYTES))
    except (TypeError, ValueError):
        min_bytes = DEFAULT_MIN_BYTES
    if min_bytes < 0:
        min_bytes = 0
    try:
        max_request = int(data.get("max_request_bytes", DEFAULT_MAX_REQUEST))
    except (TypeError, ValueError):
        max_request = DEFAULT_MAX_REQUEST
    if max_request < 1:
        max_request = DEFAULT_MAX_REQUEST
    return CompressSettings(
        gzip=gzip_on,
        brotli=brotli_on,
        min_bytes=min_bytes,
        max_request_bytes=max_request,
    )


def compress(app, config: dict | None = None):
    """Wrap a WSGI or ASGI app with content-encoding middleware."""
    settings = settings_from_raw(config) if config is not None else None
    if _protocol(app) == "asgi":
        return CompressASGI(app, settings)
    return CompressWSGI(app, settings)


def _protocol(app) -> str:
    call = getattr(type(app), "__call__", None)
    if inspect.iscoroutinefunction(call) or inspect.iscoroutinefunction(app):
        return "asgi"
    return "wsgi"


def parse_accept_encoding(header: Optional[str]) -> Optional[Dict[str, float]]:
    """Return coding → q. None means the header is absent (do not negotiate)."""
    if header is None:
        return None
    text = str(header).strip()
    if not text:
        return {"identity": 1.0}
    out: Dict[str, float] = {}
    for raw_part in text.split(","):
        part = raw_part.strip()
        if not part:
            continue
        bits = [item.strip() for item in part.split(";")]
        coding = bits[0].lower()
        if not coding:
            continue
        q = 1.0
        for param in bits[1:]:
            if not param.lower().startswith("q="):
                continue
            try:
                q = float(param.split("=", 1)[1].strip())
            except (TypeError, ValueError, IndexError):
                q = 0.0
            if q < 0:
                q = 0.0
            if q > 1:
                q = 1.0
        if coding in {"gzip", "x-gzip"}:
            coding = "gzip"
        prev = out.get(coding)
        if prev is None or q > prev:
            out[coding] = q
    return out


def choose_codec(
    accept_encoding: Optional[str],
    settings: CompressSettings,
) -> Tuple[Optional[str], bool]:
    """Return (codec, reject). codec is 'br'/'gzip'/None (identity). reject is HTTP 406."""
    parsed = parse_accept_encoding(accept_encoding)
    if parsed is None:
        return None, False
    offered: List[str] = []
    if settings.brotli:
        offered.append("br")
    if settings.gzip:
        offered.append("gzip")

    def q_for(coding: str) -> float:
        if coding in parsed:
            return parsed[coding]
        if "*" in parsed:
            return parsed["*"]
        return 0.0

    if "identity" in parsed:
        identity_q = parsed["identity"]
    elif "*" in parsed:
        identity_q = parsed["*"]
    else:
        identity_q = 1.0

    ranked: List[Tuple[float, int, str]] = []
    for codec in offered:
        q = q_for(codec)
        if q > 0:
            ranked.append((q, 1 if codec == "br" else 0, codec))
    ranked.sort(reverse=True)
    if ranked:
        return ranked[0][2], False
    if identity_q > 0:
        return None, False
    return None, True


def media_type(content_type: Optional[str]) -> str:
    return str(content_type or "").split(";", 1)[0].strip().lower()


def is_compressible_type(content_type: Optional[str]) -> bool:
    media = media_type(content_type)
    if not media:
        return False
    if media.startswith("text/"):
        return True
    return media in _COMPRESSIBLE_EXACT


def _header_value(headers: HeaderList, name: str) -> Optional[str]:
    want = name.lower()
    found: List[str] = []
    for key, value in headers:
        if str(key).lower() == want:
            found.append(str(value))
    if not found:
        return None
    return ", ".join(found)


def _drop_header(headers: HeaderList, name: str) -> HeaderList:
    want = name.lower()
    return [(key, value) for key, value in headers if str(key).lower() != want]


def _set_header(headers: HeaderList, name: str, value: str) -> HeaderList:
    out = _drop_header(headers, name)
    out.append((name, value))
    return out


def merge_vary(headers: HeaderList, token: str = VARY_TOKEN) -> HeaderList:
    tokens: List[str] = []
    seen: set[str] = set()
    rest: HeaderList = []
    for key, value in headers:
        if str(key).lower() == "vary":
            for part in str(value).split(","):
                item = part.strip()
                if not item:
                    continue
                low = item.lower()
                if low in seen:
                    continue
                seen.add(low)
                tokens.append(item)
        else:
            rest.append((key, value))
    if token.lower() not in seen:
        tokens.append(token)
    if not tokens:
        return rest
    return rest + [("Vary", ", ".join(tokens))]


def _has_no_transform(headers: HeaderList) -> bool:
    raw = _header_value(headers, "Cache-Control") or ""
    return any(part.strip().lower() == "no-transform" for part in raw.split(","))


def _cache_control_immutable(headers: HeaderList) -> bool:
    raw = _header_value(headers, "Cache-Control") or ""
    return any(part.strip().lower() == "immutable" for part in raw.split(","))


def _is_acme(path: str) -> bool:
    return str(path or "").startswith(ACME_PREFIX)


def response_eligible(
    status: int,
    headers: HeaderList,
    body: bytes,
    path: str,
    settings: CompressSettings,
    *,
    check_size: bool = True,
) -> bool:
    if not settings.any_codec:
        return False
    if status < 200 or status in _SKIP_STATUS:
        return False
    if _header_value(headers, "Content-Encoding"):
        return False
    if _has_no_transform(headers):
        return False
    if _header_value(headers, "Set-Cookie"):
        return False
    if _is_acme(path):
        return False
    if check_size and len(body) < settings.min_bytes:
        return False
    ctype = _header_value(headers, "Content-Type")
    return is_compressible_type(ctype)


def encode_body(codec: str, body: bytes) -> Optional[bytes]:
    if codec == "gzip":
        encoded = gzip.compress(body, compresslevel=GZIP_LEVEL, mtime=0)
    elif codec == "br":
        encoded = brotli.compress(body, quality=BROTLI_QUALITY)
    else:
        return None
    if len(encoded) >= len(body):
        return None
    return encoded


def _cache_get(codec: str, body: bytes) -> Optional[bytes]:
    key = (codec, hashlib.blake2b(body, digest_size=16).digest())
    with _cache_lock:
        hit = _cache.get(key)
        if hit is None:
            return None
        try:
            _cache_order.remove(key)
        except ValueError:
            pass
        _cache_order.append(key)
        return hit


def _cache_put(codec: str, body: bytes, encoded: bytes) -> None:
    key = (codec, hashlib.blake2b(body, digest_size=16).digest())
    with _cache_lock:
        if key not in _cache and len(_cache) >= _CACHE_MAX and _cache_order:
            old = _cache_order.pop(0)
            _cache.pop(old, None)
        _cache[key] = encoded
        try:
            _cache_order.remove(key)
        except ValueError:
            pass
        _cache_order.append(key)


def encode_cached(codec: str, body: bytes, headers: HeaderList) -> Optional[bytes]:
    use_cache = _cache_control_immutable(headers)
    if use_cache:
        hit = _cache_get(codec, body)
        if hit is not None:
            if len(hit) >= len(body):
                return None
            return hit
    encoded = encode_body(codec, body)
    if encoded is None:
        return None
    if use_cache:
        _cache_put(codec, body, encoded)
    return encoded


def apply_response(
    *,
    status: int,
    headers: HeaderList,
    body: bytes,
    path: str,
    accept_encoding: Optional[str],
    settings: Optional[CompressSettings] = None,
) -> Tuple[int, HeaderList, bytes]:
    cfg = settings if settings is not None else load_settings()
    codec, reject = choose_codec(accept_encoding, cfg)
    if reject:
        msg = b"not acceptable\n"
        return (
            406,
            [
                ("Content-Type", "text/plain; charset=utf-8"),
                ("Content-Length", str(len(msg))),
            ],
            msg,
        )
    headers = list(headers)
    vary_eligible = response_eligible(
        status, headers, body, path, cfg, check_size=False
    )
    if vary_eligible:
        headers = merge_vary(headers)
    if codec is None:
        return status, headers, body
    if not response_eligible(status, headers, body, path, cfg, check_size=True):
        return status, headers, body
    encoded = encode_cached(codec, body, headers)
    if encoded is None:
        return status, headers, body
    headers = _set_header(headers, "Content-Encoding", codec)
    headers = _set_header(headers, "Content-Length", str(len(encoded)))
    return status, headers, encoded


def decode_request_body(
    encoding: Optional[str],
    body: bytes,
    max_bytes: int = DEFAULT_MAX_REQUEST,
) -> Tuple[Optional[bytes], Optional[int]]:
    """Return (decoded_or_none, error_status). None, None means pass through."""
    text = str(encoding or "").strip().lower()
    if not text or text == "identity":
        return None, None
    parts = [part.strip() for part in text.split(",") if part.strip()]
    if len(parts) != 1:
        return None, 415
    coding = parts[0]
    if coding == "x-gzip":
        coding = "gzip"
    if coding not in {"gzip", "br"}:
        return None, 415
    if len(body) > max_bytes:
        return None, 413
    try:
        decoded = _decompress_limited(body, coding, max_bytes)
    except PayloadTooLarge:
        return None, 413
    except (BadEncoding, OSError, zlib.error, brotli.error):
        return None, 400
    return decoded, None


def _decompress_limited(data: bytes, codec: str, max_bytes: int) -> bytes:
    if codec == "gzip":
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            out = decoder.decompress(data, max_bytes + 1)
        except zlib.error as exc:
            raise BadEncoding() from exc
        if len(out) > max_bytes or decoder.unconsumed_tail:
            raise PayloadTooLarge()
        try:
            out += decoder.flush()
        except zlib.error as exc:
            raise BadEncoding() from exc
        if len(out) > max_bytes:
            raise PayloadTooLarge()
        return out
    decoder = brotli.Decompressor()
    try:
        out = decoder.process(data)
    except brotli.error as exc:
        raise BadEncoding() from exc
    if len(out) > max_bytes:
        raise PayloadTooLarge()
    if not decoder.is_finished():
        raise BadEncoding()
    return out


def _status_line(code: int) -> str:
    try:
        return f"{code} {HTTPStatus(code).phrase}"
    except ValueError:
        return f"{code} Status"


def _plain_error(code: int, message: str) -> Tuple[int, HeaderList, bytes]:
    body = (message + "\n").encode("utf-8")
    return (
        code,
        [
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(body))),
        ],
        body,
    )


def _wsgi_accept(environ: dict) -> Optional[str]:
    if "HTTP_ACCEPT_ENCODING" not in environ:
        return None
    return environ.get("HTTP_ACCEPT_ENCODING")


class CompressWSGI:
    def __init__(self, app: Callable, settings: Optional[CompressSettings] = None):
        self.app = app
        self.settings = settings

    def __getattr__(self, name: str):
        return getattr(self.app, name)

    def _cfg(self) -> CompressSettings:
        return self.settings if self.settings is not None else load_settings()

    def __call__(self, environ, start_response):
        cfg = self._cfg()
        encoding = environ.get("HTTP_CONTENT_ENCODING")
        if encoding:
            try:
                length = int(environ.get("CONTENT_LENGTH") or 0)
            except (TypeError, ValueError):
                length = 0
            raw = environ["wsgi.input"].read(length) if length > 0 else b""
            decoded, err = decode_request_body(encoding, raw, cfg.max_request_bytes)
            if err is not None:
                status, headers, body = _plain_error(
                    err,
                    "payload too large"
                    if err == 413
                    else ("unsupported media type" if err == 415 else "bad request"),
                )
                start_response(_status_line(status), headers)
                return [body]
            if decoded is not None:
                environ = dict(environ)
                environ["wsgi.input"] = io.BytesIO(decoded)
                environ["CONTENT_LENGTH"] = str(len(decoded))
                environ.pop("HTTP_CONTENT_ENCODING", None)

        captured: Dict[str, Any] = {}
        chunks: List[bytes] = []

        def _start(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = list(headers or [])
            captured["exc_info"] = exc_info

            def write(data):
                chunks.append(data if isinstance(data, (bytes, bytearray)) else bytes(data))

            return write

        app_iter = self.app(environ, _start)
        try:
            for piece in app_iter:
                if piece:
                    chunks.append(piece)
        finally:
            closer = getattr(app_iter, "close", None)
            if closer:
                try:
                    closer()
                except Exception:
                    pass
        raw_status = captured.get("status") or "500 Internal Server Error"
        try:
            code = int(str(raw_status).split()[0])
        except (TypeError, ValueError):
            code = 500
        headers = list(captured.get("headers") or [])
        body = b"".join(chunks)
        path = str(environ.get("PATH_INFO") or "/")
        code, headers, body = apply_response(
            status=code,
            headers=headers,
            body=body,
            path=path,
            accept_encoding=_wsgi_accept(environ),
            settings=cfg,
        )
        start_response(_status_line(code), headers, captured.get("exc_info"))
        return [body]


def _asgi_header_map(headers: AsgiHeaders) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for raw_name, raw_value in headers or []:
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        if name in out:
            out[name] = out[name] + ", " + value
        else:
            out[name] = value
    return out


def _asgi_to_pairs(headers: AsgiHeaders) -> HeaderList:
    return [
        (name.decode("latin-1"), value.decode("latin-1"))
        for name, value in headers or []
    ]


def _pairs_to_asgi(headers: HeaderList) -> AsgiHeaders:
    return [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in headers
    ]


async def _read_asgi_body(receive) -> bytes:
    chunks: List[bytes] = []
    more = True
    while more:
        message = await receive()
        mtype = message.get("type")
        if mtype == "http.disconnect":
            break
        if mtype != "http.request":
            break
        chunks.append(message.get("body") or b"")
        more = bool(message.get("more_body"))
    return b"".join(chunks)


class CompressASGI:
    def __init__(self, app: Callable, settings: Optional[CompressSettings] = None):
        self.app = app
        self.settings = settings

    def __getattr__(self, name: str):
        return getattr(self.app, name)

    def _cfg(self) -> CompressSettings:
        return self.settings if self.settings is not None else load_settings()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        cfg = self._cfg()
        headers = _asgi_header_map(scope.get("headers") or [])
        encoding = headers.get("content-encoding")
        inbound = receive
        if encoding:
            raw = await _read_asgi_body(receive)
            decoded, err = decode_request_body(encoding, raw, cfg.max_request_bytes)
            if err is not None:
                status, out_headers, body = _plain_error(
                    err,
                    "payload too large"
                    if err == 413
                    else ("unsupported media type" if err == 415 else "bad request"),
                )
                await send(
                    {
                        "type": "http.response.start",
                        "status": status,
                        "headers": _pairs_to_asgi(out_headers),
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
            payload = decoded if decoded is not None else raw
            scope = dict(scope)
            filtered = [
                (name, value)
                for name, value in (scope.get("headers") or [])
                if name.decode("latin-1").lower() != "content-encoding"
            ]
            filtered = [
                (name, value)
                for name, value in filtered
                if name.decode("latin-1").lower() != "content-length"
            ]
            filtered.append((b"content-length", str(len(payload)).encode("latin-1")))
            scope["headers"] = filtered
            sent = {"done": False}

            async def inbound():
                if not sent["done"]:
                    sent["done"] = True
                    return {"type": "http.request", "body": payload, "more_body": False}
                return {"type": "http.disconnect"}

        start_msg: Optional[dict] = None
        body_chunks: List[bytes] = []

        async def _send(message):
            nonlocal start_msg
            mtype = message.get("type")
            if mtype == "http.response.start":
                start_msg = dict(message)
                start_msg["headers"] = list(message.get("headers") or [])
                return
            if mtype == "http.response.body":
                body_chunks.append(message.get("body") or b"")
                if message.get("more_body"):
                    return
                code = int((start_msg or {}).get("status") or 200)
                headers = _asgi_to_pairs((start_msg or {}).get("headers") or [])
                body = b"".join(body_chunks)
                path = str(scope.get("path") or "/")
                accept = headers_map_accept(scope)
                code, headers, body = apply_response(
                    status=code,
                    headers=headers,
                    body=body,
                    path=path,
                    accept_encoding=accept,
                    settings=cfg,
                )
                await send(
                    {
                        "type": "http.response.start",
                        "status": code,
                        "headers": _pairs_to_asgi(headers),
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
            await send(message)

        await self.app(scope, inbound, _send)
        if start_msg is not None and not body_chunks:
            code = int(start_msg.get("status") or 200)
            headers = _asgi_to_pairs(start_msg.get("headers") or [])
            accept = headers_map_accept(scope)
            code, headers, body = apply_response(
                status=code,
                headers=headers,
                body=b"",
                path=str(scope.get("path") or "/"),
                accept_encoding=accept,
                settings=cfg,
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": code,
                    "headers": _pairs_to_asgi(headers),
                }
            )
            await send({"type": "http.response.body", "body": body})


def headers_map_accept(scope: dict) -> Optional[str]:
    found = False
    values: List[str] = []
    for raw_name, raw_value in scope.get("headers") or []:
        if raw_name.decode("latin-1").lower() == "accept-encoding":
            found = True
            values.append(raw_value.decode("latin-1"))
    if not found:
        return None
    return ", ".join(values)

