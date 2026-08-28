"""Package CSS/JS under /static, with optional ~/.looking-glass/static overrides."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Tuple

from ..utility import get_root

PACKAGE_STATIC = Path(__file__).resolve().parent / "static"
_ALLOWED_SUFFIX = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8"}
_CACHE = "public, max-age=31536000, immutable"

HttpOut = Tuple[int, str, bytes, List[Tuple[str, str]]]


def override_dir() -> Path:
    return Path(get_root()) / "static"


def resolve_static(name: str) -> Optional[Path]:
    text = str(name or "").replace("\\", "/").lstrip("/")
    if text.startswith("static/"):
        text = text[len("static/") :]
    if not text or text.endswith("/") or ".." in text.split("/"):
        return None
    suffix = Path(text).suffix.lower()
    if suffix not in _ALLOWED_SUFFIX:
        return None
    for root in (override_dir(), PACKAGE_STATIC):
        try:
            base = root.resolve()
        except OSError:
            continue
        dest = (base / text).resolve()
        try:
            if not dest.is_relative_to(base) or dest == base:
                continue
        except (OSError, ValueError):
            continue
        if dest.is_file():
            return dest
    return None


def static_url(name: str) -> str:
    path = resolve_static(name)
    version = "0"
    if path is not None:
        try:
            version = str(int(path.stat().st_mtime))
        except OSError:
            version = "0"
    return f"/static/{name}?v={version}"


def read_static(name: str) -> str:
    path = resolve_static(name)
    if path is None:
        return ""
    return path.read_text(encoding="utf-8")


def serve(method: str, token: str) -> HttpOut:
    verb = (method or "GET").upper()
    if verb not in {"GET", "HEAD"}:
        return 405, "text/plain; charset=utf-8", b"method not allowed", [("Allow", "GET, HEAD")]
    path = resolve_static(token)
    if path is None:
        return 404, "text/plain; charset=utf-8", b"not found", []
    ctype = _ALLOWED_SUFFIX[path.suffix.lower()]
    return 200, ctype, path.read_bytes(), [("Cache-Control", _CACHE)]
