"""looking-glass ASGI: wall wraps the app. GET / looks up the TCP peer.

    looking-glass wall asgi
    curl -s http://127.0.0.1:8001/
    curl -s http://127.0.0.1:8001/1.1.1.1
    curl -s http://127.0.0.1:8001/reputation/example.com
    curl -s http://127.0.0.1:8001/apex/example.com
    curl -s http://127.0.0.1:8001/ping/1.1.1.1
"""

from __future__ import annotations

from .site import respond_async
from ..auth.session import effective_scheme
from ..wall import wall


def _header_map(scope) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers") or []:
        out[raw_name.decode("latin-1").lower()] = raw_value.decode("latin-1")
    return out


async def _read_body(receive) -> bytes:
    chunks: list[bytes] = []
    more = True
    while more:
        message = await receive()
        if message.get("type") != "http.request":
            break
        chunks.append(message.get("body") or b"")
        more = bool(message.get("more_body"))
    return b"".join(chunks)


async def inner(scope, receive, send):
    if scope["type"] != "http":
        return
    headers = _header_map(scope)
    wall_hdrs = {name: value for name, value in headers.items() if name.startswith("x-wall-")}
    client = scope.get("client")
    visitor = client[0] if client else None
    forwarded = (headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    scheme = effective_scheme(scope.get("scheme"), forwarded)
    raw_qs = scope.get("query_string") or b""
    query_string = raw_qs.decode("latin-1") if isinstance(raw_qs, (bytes, bytearray)) else str(raw_qs)
    path = scope.get("path") or "/"
    raw_body = await _read_body(receive)
    status, content_type, body, extra = await respond_async(
        "asgi",
        visitor,
        path,
        wall_hdrs,
        accept=headers.get("accept"),
        host=headers.get("host"),
        scheme=scheme,
        query_string=query_string,
        method=scope.get("method") or "GET",
        accept_language=headers.get("accept-language"),
        cookie=headers.get("cookie"),
        body=raw_body,
        correlation_id=headers.get("x-correlation-id"),
        authorization=headers.get("authorization"),
    )
    out_headers = [
        (b"content-type", content_type.encode("latin-1")),
        (b"content-length", str(len(body)).encode("latin-1")),
    ]
    for name, value in extra:
        out_headers.append((name.lower().encode("latin-1"), value.encode("latin-1")))
    if path.rstrip("/") == "/status":
        out_headers.append((b"cache-control", b"no-store"))
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": out_headers,
        }
    )
    await send({"type": "http.response.body", "body": body})


app = wall(inner)


def serve(host: str = "127.0.0.1", port: int = 8001) -> None:
    from ..docs.generate import ensure_docs_on_serve

    ensure_docs_on_serve()
    try:
        import uvicorn
    except ImportError as e:
        raise RuntimeError("uvicorn is required to serve the ASGI demo") from e
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    serve()
