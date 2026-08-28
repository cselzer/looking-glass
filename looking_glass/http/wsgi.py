"""looking-glass WSGI: wall wraps the app. GET / looks up the TCP peer.

    looking-glass wall wsgi
    curl -s http://127.0.0.1:8000/
    curl -s http://127.0.0.1:8000/1.1.1.1
    curl -s http://127.0.0.1:8000/reputation/example.com
    curl -s http://127.0.0.1:8000/apex/example.com
    curl -s http://127.0.0.1:8000/ping/1.1.1.1
"""

from __future__ import annotations

from http import HTTPStatus
from wsgiref.simple_server import make_server

from .site import respond
from ..auth.session import effective_scheme
from ..wall import wall


def _header_name(cgi_key: str) -> str:
    parts = cgi_key[5:].split("_")
    return "-".join(part.capitalize() for part in parts if part)


def inner(environ, start_response):
    wall_hdrs = {}
    for key, value in environ.items():
        if key.startswith("HTTP_X_WALL_"):
            wall_hdrs[_header_name(key)] = value
    visitor = (environ.get("REMOTE_ADDR") or "").strip() or None
    scheme = effective_scheme(
        environ.get("wsgi.url_scheme"),
        environ.get("HTTP_X_FORWARDED_PROTO"),
    )
    path = environ.get("PATH_INFO") or "/"
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        length = 0
    raw_body = environ["wsgi.input"].read(length) if length > 0 else b""
    status, content_type, body, extra = respond(
        "wsgi",
        visitor,
        path,
        wall_hdrs,
        accept=environ.get("HTTP_ACCEPT"),
        host=environ.get("HTTP_HOST") or environ.get("SERVER_NAME"),
        scheme=scheme,
        query_string=environ.get("QUERY_STRING") or "",
        method=environ.get("REQUEST_METHOD") or "GET",
        accept_language=environ.get("HTTP_ACCEPT_LANGUAGE"),
        cookie=environ.get("HTTP_COOKIE"),
        body=raw_body,
        correlation_id=environ.get("HTTP_X_CORRELATION_ID"),
    )
    try:
        phrase = HTTPStatus(status).phrase
    except ValueError:
        phrase = "Error"
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
    ]
    headers.extend(extra)
    if path.rstrip("/") == "/status":
        headers.append(("Cache-Control", "no-store"))
    start_response(f"{status} {phrase}", headers)
    return [body]


app = wall(inner)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    from ..docs.generate import ensure_docs_on_serve

    ensure_docs_on_serve()
    httpd = make_server(host, port, app)
    httpd.serve_forever()


if __name__ == "__main__":
    serve()
