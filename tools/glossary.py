"""Baked translation glossary and post-batch verify (do not trust the model)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

DEFAULT_GLOSSARY: List[str] = [
    "DNS",
    "DNSSEC",
    "RDAP",
    "WHOIS",
    "TLS",
    "SNI",
    "ASN",
    "BGP",
    "RPKI",
    "ROA",
    "PTR",
    "FCrDNS",
    "MTR",
    "ICMP",
    "TCP",
    "UDP",
    "HTTP",
    "ALPN",
    "HSTS",
    "TTFB",
    "MX",
    "SPF",
    "DMARC",
    "DKIM",
    "SMTP",
    "STARTTLS",
    "SOA",
    "NS",
    "DS",
    "DNSKEY",
    "RRSIG",
    "NSEC",
    "NSEC3",
    "NXDOMAIN",
    "SERVFAIL",
    "NOERROR",
    "IANA",
    "RIR",
    "RIPE",
    "DNSBL",
    "MTU",
    "PMTUD",
    "CIDR",
    "TTL",
    "EHLO",
    "curl",
    "dig",
    "Click",
    "ASGI",
    "WSGI",
    "Apex",
    "GeoIP",
    "looking-glass",
    "PAM",
    "JSON",
    "JSONL",
    "IPv4",
    "IPv6",
    "GUI",
]

_COPY_THROUGH_KEY = re.compile(r"^(gui\.[^.]+\.tab|inspect\.[^.]+\.label)$")
_PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")
_BACKTICK = re.compile(r"`[^`]+`")
_FLAG = re.compile(r"--[A-Za-z0-9][A-Za-z0-9-]*")
_HOME_PATH = re.compile(
    r"~/\.looking-glass(?:/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)?"
)
_ANGLE = re.compile(r"<[A-Za-z][A-Za-z0-9._-]*>")


def load_glossary_file(path: str | Path) -> List[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("glossary file must be a JSON array of strings")
    out: List[str] = []
    for item in data:
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def package_glossary_path() -> Path:
    from looking_glass.i18n.catalog import package_locales_dir

    return package_locales_dir() / "glossary.json"


def _append_terms(terms: List[str], seen: Set[str], extra: Iterable[str]) -> None:
    for term in extra:
        if term in seen:
            continue
        seen.add(term)
        terms.append(term)


def effective_glossary(path: Optional[str | Path] = None) -> List[str]:
    """DEFAULT_GLOSSARY, then package glossary.json, then optional FILE (skip duplicates)."""
    terms = list(DEFAULT_GLOSSARY)
    seen = set(terms)
    pkg = package_glossary_path()
    if pkg.is_file():
        _append_terms(terms, seen, load_glossary_file(pkg))
    if path:
        _append_terms(terms, seen, load_glossary_file(path))
    return terms


def is_copy_through(
    key: str,
    en: str,
    glossary: Optional[Union[Sequence[str], Set[str]]] = None,
) -> bool:
    """Nav tabs, inspect labels, and whole-string glossary terms stay English."""
    if _COPY_THROUGH_KEY.match(key or ""):
        return True
    text = (en or "").strip()
    if not text:
        return False
    terms = glossary if glossary is not None else DEFAULT_GLOSSARY
    return text in terms


def copy_through_keys(
    src: Mapping[str, Mapping[str, str]],
    glossary: Optional[Sequence[str]] = None,
) -> List[str]:
    terms: Set[str] = set(glossary if glossary is not None else DEFAULT_GLOSSARY)
    return [
        key
        for key, row in src.items()
        if is_copy_through(key, (row or {}).get("en") or "", terms)
    ]


def copy_through_dirty_keys(
    src: Mapping[str, Mapping[str, str]],
    dst: Mapping[str, Mapping[str, str]],
    glossary: Optional[Sequence[str]] = None,
) -> List[str]:
    dirty: List[str] = []
    for key in copy_through_keys(src, glossary):
        en = (src.get(key) or {}).get("en") or ""
        got = str((dst.get(key) or {}).get("text") or "")
        if got != en:
            dirty.append(key)
    return dirty


def _token_in(term: str, text: str) -> bool:
    if not term:
        return False
    pattern = r"(?<![A-Za-z0-9_])" + re.escape(term) + r"(?![A-Za-z0-9_])"
    return re.search(pattern, text) is not None


def _spans(en: str) -> List[str]:
    found: List[str] = []
    for pattern in (_PLACEHOLDER, _BACKTICK, _FLAG, _ANGLE):
        found.extend(pattern.findall(en))
    for span in _HOME_PATH.findall(en):
        found.append(span.rstrip("."))
    if r"\b" in en:
        found.append(r"\b")
    return found


def verify_translation(
    en: str,
    text: str,
    glossary: Optional[Sequence[str]] = None,
) -> Tuple[bool, Optional[str]]:
    """Return (ok, reason). reason is set when a protected span is missing from text."""
    source = en or ""
    dest = text if text is not None else ""
    for term in glossary or DEFAULT_GLOSSARY:
        if term and _token_in(term, source) and not _token_in(term, dest):
            return False, f"glossary:{term}"
    for span in _spans(source):
        if span not in dest:
            return False, f"span:{span}"
    return True, None


def glossary_for_prompt(terms: Iterable[str]) -> str:
    return ", ".join(terms)


def undo_utf8_mojibake(text: str) -> str:
    """Undo UTF-8 bytes that were decoded as Latin-1 (Ã¼ → ü)."""
    if not text or ("Ã" not in text and "Â" not in text):
        return text
    try:
        return text.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text
