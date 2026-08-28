"""Curated locales to ship. Append a row, then `translate LANG`."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .providers import LocaleCliError

# One catalog file per code (de.json). Runtime strips region (pt-BR → pt).
SHIP_LANGS: Tuple[Mapping[str, str], ...] = (
    {
        "code": "de",
        "prompt": "de (German / Deutsch)",
        "style": (
            "Write standard German for a technical network tool. "
            "Use formal Sie in UI, not du."
        ),
    },
    {
        "code": "fr",
        "prompt": "fr (French / français)",
        "style": (
            "Write international French for a technical network tool. "
            "Not Quebec-only vocabulary or spelling."
        ),
    },
    {
        "code": "es",
        "prompt": "es (Spanish / español)",
        "style": (
            "Write Spanish readable in Spain and Latin America. "
            "Prefer ustedes, not vosotros-only Spain or voseo-only Argentina."
        ),
    },
    {
        "code": "ja",
        "prompt": "ja (Japanese / 日本語)",
        "style": (
            "Write polite です/ます Japanese for UI chrome. "
            "Not casual or overly stiff literary Japanese."
        ),
    },
    {
        "code": "pt",
        "prompt": "pt (Brazilian Portuguese / português brasileiro)",
        "style": (
            "Write Brazilian Portuguese (pt-BR): você and Brazilian vocabulary. "
            "Not European Portuguese (tu, autocarro, ecrã)."
        ),
    },
)


def ship_codes() -> Tuple[str, ...]:
    return tuple(str(row["code"]) for row in SHIP_LANGS)


def get_ship_lang(code: str) -> Optional[Mapping[str, str]]:
    key = (code or "").strip().lower()
    for row in SHIP_LANGS:
        if row["code"] == key:
            return row
    return None


def require_ship_lang(code: str) -> Mapping[str, str]:
    row = get_ship_lang(code)
    if row:
        return row
    allowed = ", ".join(ship_codes())
    raise LocaleCliError(
        f"unknown ship locale {code!r}; add a row in tools/ship_langs.py "
        f"(current: {allowed})"
    )


def _display_names(code: str) -> Tuple[str, str]:
    try:
        from babel import Locale
        from babel.core import UnknownLocaleError

        loc = Locale.parse(code)
        english = (loc.english_name or code).strip()
        native = (loc.get_display_name(code) or english).strip()
        return english, native
    except (UnknownLocaleError, ValueError, TypeError):
        return code, code


def list_ship_langs(shipped_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    folder = Path(shipped_dir) if shipped_dir else None
    shipped = set()
    if folder and folder.is_dir():
        for path in folder.glob("*.json"):
            if path.name.startswith("_") or path.stem == "glossary":
                continue
            shipped.add(path.stem)
    rows: List[Dict[str, Any]] = []
    for spec in SHIP_LANGS:
        code = spec["code"]
        english, native = _display_names(code)
        rows.append(
            {
                "code": code,
                "english": english,
                "native": native,
                "prompt": spec["prompt"],
                "style": spec["style"],
                "shipped": code in shipped,
            }
        )
    return rows
