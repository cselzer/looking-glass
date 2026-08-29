"""HTTP security headers for every looking-glass response."""

from __future__ import annotations

import secrets
from typing import Any, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

ExtraHeaders = List[Tuple[str, str]]

HSTS = "max-age=15552000"
PERMISSIONS = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"


def csp_nonce() -> str:
    return secrets.token_urlsafe(16)


def normalize_controller_origin(value: Any) -> Optional[str]:
    """Return scheme://host[:port], or None if the value is not a safe origin."""
    text = str(value or "").strip()
    if not text:
        return None
    if any(ch.isspace() or ch in "*'" for ch in text):
        return None
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"}:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    if parts.username or parts.password:
        return None
    host_disp = f"[{host}]" if ":" in host else host
    netloc = f"{host_disp}:{parts.port}" if parts.port else host_disp
    return f"{parts.scheme.lower()}://{netloc}"


def parse_controller_origins(raw: Any, *, strict: bool = False) -> List[str]:
    items: Sequence[Any]
    if raw is None:
        return []
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        if text.startswith("["):
            import json

            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, list):
                items = parsed
            else:
                items = [part.strip() for part in text.split(",") if part.strip()]
        else:
            items = [part.strip() for part in text.split(",") if part.strip()]
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        if strict:
            raise ValueError("http.controller_origins must be a list of origins")
        return []
    out: List[str] = []
    seen = set()
    for item in items:
        origin = normalize_controller_origin(item)
        if origin is None:
            if strict:
                raise ValueError(f"invalid controller origin {item!r}")
            continue
        if origin in seen:
            continue
        seen.add(origin)
        out.append(origin)
    return out


def _controller_origins() -> List[str]:
    try:
        from ..config import load

        raw = (load().get("http") or {}).get("controller_origins")
    except Exception:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw if item]
    return parse_controller_origins(raw)


def _csp(nonce: str, extra_connect: Sequence[str]) -> str:
    script = ["'self'"]
    if nonce:
        script.append(f"'nonce-{nonce}'")
    connect = ["'self'"]
    for origin in extra_connect:
        if origin and origin not in connect:
            connect.append(origin)
    parts = [
        "default-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "object-src 'none'",
        "script-src " + " ".join(script),
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https://flagcdn.com",
        "connect-src " + " ".join(connect),
        "font-src 'self'",
        "upgrade-insecure-requests",
    ]
    return "; ".join(parts)


def security_headers(
    scheme: Optional[str],
    nonce: str,
    *,
    origin: Optional[str] = None,
) -> ExtraHeaders:
    controllers = _controller_origins()
    allowed = normalize_controller_origin(origin) if origin else None
    cors = bool(allowed and allowed in controllers)
    corp = "cross-origin" if cors else "same-origin"
    headers: ExtraHeaders = [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", PERMISSIONS),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", corp),
        ("Content-Security-Policy", _csp(nonce, controllers)),
    ]
    if str(scheme or "").strip().lower() == "https":
        headers.append(("Strict-Transport-Security", HSTS))
    if cors and allowed:
        headers.append(("Access-Control-Allow-Origin", allowed))
        headers.append(("Vary", "Origin"))
    return headers


def merge_security_headers(
    existing: ExtraHeaders,
    scheme: Optional[str],
    nonce: str,
    *,
    origin: Optional[str] = None,
) -> ExtraHeaders:
    have = {str(name).lower() for name, _ in existing}
    extra: ExtraHeaders = []
    for name, value in security_headers(scheme, nonce, origin=origin):
        key = name.lower()
        if key in have:
            continue
        extra.append((name, value))
        have.add(key)
    return list(existing) + extra


def attach(
    out: Tuple[int, str, bytes, ExtraHeaders],
    scheme: Optional[str],
    nonce: str,
    *,
    origin: Optional[str] = None,
) -> Tuple[int, str, bytes, ExtraHeaders]:
    status, ctype, body, extra = out
    return status, ctype, body, merge_security_headers(list(extra or []), scheme, nonce, origin=origin)
