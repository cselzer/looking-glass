"""JSON-catalog i18n for GUI chrome, Click help, and docs. JSON APIs stay English."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utility import atomic_write, get_root
from .messages import INVENTORY

PACKAGE_LOCALES = Path(__file__).resolve().parent.parent / "locales"

_locale = "en"
_catalog: Dict[str, Dict[str, str]] = {}
_english: Dict[str, Dict[str, str]] = {}


def package_locales_dir() -> Path:
    return PACKAGE_LOCALES


def operator_locales_dir() -> Path:
    return Path(get_root()) / "locales"


def active_locale() -> str:
    return _locale


def normalize_lang(value: Optional[str]) -> str:
    raw = (value or "en").strip().replace("_", "-")
    if not raw:
        return "en"
    primary = raw.split(",")[0].strip().split(";")[0].strip()
    if not primary:
        return "en"
    return primary.split("-")[0].lower() or "en"


LANG_COOKIE = "looking_glass_lang"


def parse_lang_cookie(header: Optional[str]) -> Optional[str]:
    if not header:
        return None
    shipped = set(available_locales())
    for part in str(header).split(";"):
        item = part.strip()
        if not item:
            continue
        name, _, value = item.partition("=")
        if name.strip() != LANG_COOKIE:
            continue
        code = normalize_lang(value.strip())
        if code in shipped:
            return code
        return None
    return None


def parse_accept_language(
    header: Optional[str],
    shipped: Optional[set] = None,
) -> Optional[str]:
    if not header:
        return None
    allowed = shipped if shipped is not None else set(available_locales())
    best: Optional[str] = None
    best_q = -1.0
    for part in header.split(","):
        token = part.strip()
        if not token:
            continue
        lang, _, rest = token.partition(";")
        q = 1.0
        if rest.strip().lower().startswith("q="):
            try:
                q = float(rest.strip()[2:])
            except ValueError:
                q = 0.0
        code = normalize_lang(lang)
        if code not in allowed:
            continue
        if q > best_q:
            best_q = q
            best = code
    return best


def config_locale() -> Optional[str]:
    from ..config import load

    try:
        locale = load().get("locale")
    except OSError:
        return None
    if not locale:
        return None
    return normalize_lang(str(locale))


def resolve_locale(
    *,
    explicit: Optional[str] = None,
    accept_language: Optional[str] = None,
    html: bool = False,
    cookie: Optional[str] = None,
) -> str:
    if explicit:
        return normalize_lang(explicit)
    env = os.environ.get("LOOKING_GLASS_LANG")
    if env:
        return normalize_lang(env)
    shipped = set(available_locales())
    if html:
        from_cookie = parse_lang_cookie(cookie)
        if from_cookie:
            return from_cookie
        from_header = parse_accept_language(accept_language, shipped)
        if from_header:
            return from_header
    cfg = config_locale()
    if cfg and cfg in shipped:
        return cfg
    return "en"


def _msg_text(entry: Any) -> str:
    if isinstance(entry, dict):
        text = entry.get("text")
        if isinstance(text, str) and text:
            return text
        en = entry.get("en")
        if isinstance(en, str) and en:
            return en
        return ""
    if isinstance(entry, str):
        return entry
    return ""


def catalog_to_messages(data: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    raw = data.get("messages") if isinstance(data.get("messages"), dict) else data
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, dict):
            en = str(value.get("en") or value.get("text") or "")
            text = str(value.get("text") or en)
            out[key] = {"text": text, "en": en or text}
        elif isinstance(value, str):
            out[key] = {"text": value, "en": value}
    return out


def dump_catalog(locale: str, messages: Dict[str, Dict[str, str]], source: str = "en") -> str:
    payload = {
        "locale": locale,
        "source": source,
        "messages": {
            key: {
                "text": row.get("text") or row.get("en") or "",
                "en": row.get("en") or row.get("text") or "",
            }
            for key, row in sorted(messages.items())
        },
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def inventory_messages() -> Dict[str, Dict[str, str]]:
    return {key: {"text": text, "en": text} for key, text in INVENTORY.items()}


def load_json_file(path: Path) -> Dict[str, Dict[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return catalog_to_messages(data)


def _locale_paths(lang: str) -> List[Path]:
    name = f"{normalize_lang(lang)}.json"
    return [operator_locales_dir() / name, package_locales_dir() / name]


def load_locale_messages(lang: str) -> Dict[str, Dict[str, str]]:
    lang = normalize_lang(lang)
    merged: Dict[str, Dict[str, str]] = inventory_messages()
    if lang != "en":
        merged.update(_english or {})
    for path in reversed(_locale_paths(lang)):
        if path.is_file():
            merged.update(load_json_file(path))
    return merged


def set_locale(lang: str) -> str:
    global _locale, _catalog, _english
    _english = load_locale_messages("en")
    _locale = normalize_lang(lang)
    _catalog = load_locale_messages(_locale)
    return _locale


def t(key: str, **kwargs: Any) -> str:
    row = _catalog.get(key) or _english.get(key) or {}
    text = _msg_text(row)
    if not text:
        inv = INVENTORY.get(key)
        text = inv if inv else key
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            pass
    return text


def messages_map() -> Dict[str, str]:
    keys = set(_english) | set(_catalog) | set(INVENTORY)
    return {key: t(key) for key in sorted(keys)}


_UI_PREFIXES = ("gui.", "inspect.", "rdap.", "status.", "term.", "result.", "docs.")
_RESULT_GUI_PREFIXES = (
    "gui.group.",
    "gui.tool.",
    "gui.choose_tool",
    "gui.close",
    "gui.minimize",
    "gui.refresh",
    "gui.looking_up",
    "gui.cache.",
    "gui.config.",
    "gui.history",
    "gui.wall",
    "gui.login",
    "gui.logout",
    "gui.logs.",
    "gui.maximize",
    "gui.dnssec.",
    "gui.register.",
    "gui.wait.",
    "gui.elapsed",
    "gui.howto.",
)


def ui_messages_map(page: str = "index") -> Dict[str, str]:
    """Browser catalogs omit Click help so lookup HTML does not ship every CLI string."""
    full = messages_map()
    if page == "index":
        return {key: text for key, text in full.items() if key.startswith(_UI_PREFIXES)}
    out: Dict[str, str] = {}
    for key, text in full.items():
        if key.startswith(("inspect.", "rdap.", "status.", "term.", "result.", "docs.")):
            out[key] = text
        elif key.startswith(_RESULT_GUI_PREFIXES):
            out[key] = text
    return out


def available_locales() -> List[str]:
    found = {"en"}
    for folder in (package_locales_dir(), operator_locales_dir()):
        if not folder.is_dir():
            continue
        for path in folder.glob("*.json"):
            if path.name.startswith("_") or "." in path.stem or path.stem == "glossary":
                continue
            found.add(normalize_lang(path.stem))
    return sorted(found)


def locale_path(lang: str, *, operator: bool = True) -> Path:
    name = f"{normalize_lang(lang)}.json"
    return (operator_locales_dir() if operator else package_locales_dir()) / name


def missing_keys(lang: str) -> List[str]:
    en = load_locale_messages("en")
    other = load_locale_messages(lang) if normalize_lang(lang) != "en" else en
    missing = []
    for key in en:
        got = other.get(key) or {}
        if key not in other:
            missing.append(key)
        elif normalize_lang(lang) != "en" and not (got.get("text") or "").strip():
            missing.append(key)
    return missing


def write_locale(lang: str, messages: Dict[str, Dict[str, str]], *, operator: bool = True) -> Path:
    lang = normalize_lang(lang)
    dest = locale_path(lang, operator=operator)
    dest.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(str(dest), dump_catalog(lang, messages, source="en"))
    return dest


def clone_english() -> Dict[str, Dict[str, str]]:
    en = load_locale_messages("en")
    out: Dict[str, Dict[str, str]] = {}
    for key, row in en.items():
        english = row.get("en") or row.get("text") or INVENTORY.get(key, "")
        out[key] = {"text": english, "en": english}
    return out


def fill_from_english(lang: str) -> Dict[str, Dict[str, str]]:
    en = load_locale_messages("en")
    current = load_locale_messages(lang) if normalize_lang(lang) != "en" else {}
    out: Dict[str, Dict[str, str]] = {}
    for key, row in en.items():
        english = row.get("en") or row.get("text") or ""
        existing = current.get(key) or {}
        text = (existing.get("text") or "").strip()
        out[key] = {"text": text or english, "en": english}
    for key, row in current.items():
        if key not in out:
            out[key] = row
    return out


def import_messages(payload: Any) -> Dict[str, Dict[str, str]]:
    en = load_locale_messages("en")
    data = payload if isinstance(payload, dict) else {}
    incoming = catalog_to_messages(data)
    merged = {
        key: {"text": row.get("en") or row.get("text") or "", "en": row.get("en") or row.get("text") or ""}
        for key, row in en.items()
    }
    for key, row in incoming.items():
        english = (en.get(key) or {}).get("en") or (en.get(key) or {}).get("text") or row.get("en") or ""
        text = row.get("text") or english
        merged[key] = {"text": text, "en": english or text}
    return merged


set_locale("en")
