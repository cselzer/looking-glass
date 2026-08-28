"""Country flags that look right in a terminal and in a browser.

Unicode flag emoji (🇦🇺) is two regional-indicator letters. macOS Terminal
draws them as a flag; Windows browsers usually show “A U” because Segoe UI
Emoji has no flag glyphs. For the web, use the SVG URL / HTML <img> instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from typing import Any, Dict, List, Optional

from babel import Locale

_EN = Locale.parse("en")

# RIR / legacy aliases → ISO 3166-1 alpha-2 used for emoji and images.
_ALIAS = {
    "UK": "GB",
    "EL": "GR",
}

# No national flag (RIR leftovers, user-assigned, unknown).
_NO_ASSET = {
    "AA",
    "AP",
    "A1",
    "A2",
    "O1",
    "XX",
    "ZZ",
}

_FALLBACK_EMOJI = "🏳️"
_UNKNOWN_EMOJI = "❓"

# flagcdn SVGs render on every browser; emoji does not.
_FLAG_SVG = "https://flagcdn.com/{code}.svg"


def _letters(code: Any) -> Optional[str]:
    if code is None:
        return None
    text = str(code).strip().upper()
    if text in ("", "?", "??"):
        return None
    if len(text) != 2 or not text.isalpha():
        return None
    return _ALIAS.get(text, text)


def canonical_country(code: Any) -> Optional[str]:
    """ISO 3166-1 alpha-2 (UK→GB), or None if this is not a country code."""
    return _letters(code)


def country_name(code: Any) -> Optional[str]:
    """English short name from CLDR, or None if unknown."""
    cc = _letters(code)
    if not cc:
        return None
    return _EN.territories.get(cc)


def country_to_flag(code: Any) -> str:
    """Unicode flag emoji. Best for terminals; unreliable on the web."""
    if code is None or str(code).strip() in ("", "?", "??"):
        return _UNKNOWN_EMOJI
    cc = _letters(code)
    if not cc:
        return _FALLBACK_EMOJI
    try:
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    except (IndexError, TypeError, ValueError):
        return _FALLBACK_EMOJI


def flag_url(code: Any) -> Optional[str]:
    """SVG URL that browsers draw as a flag (including Windows)."""
    cc = _letters(code)
    if not cc or cc in _NO_ASSET:
        return None
    if cc not in ("EU", "UN", "XK") and cc not in _EN.territories:
        return None
    return _FLAG_SVG.format(code=cc.lower())


@dataclass(frozen=True)
class Flag:
    """One country as emoji (console), SVG (web), and a name."""

    code: str
    emoji: str
    name: Optional[str]
    url: Optional[str]

    def text(self) -> str:
        """Console fragment: 🇦🇺  AU  Australia"""
        parts = [self.emoji, self.code]
        if self.name:
            parts.append(self.name)
        return "  ".join(parts)

    def html(self, *, height: str = "1.1em") -> str:
        """Inline <img> for HTML. Falls back to emoji+name if there is no SVG."""
        label = self.name or self.code
        alt = escape(f"{self.emoji} {label}".strip())
        title = escape(f"{self.code} — {label}" if self.name else self.code)
        if not self.url:
            return f'<span title="{title}">{escape(self.emoji)} {escape(self.code)}</span>'
        h = escape(height, quote=True)
        return (
            f'<img src="{escape(self.url, quote=True)}" alt="{alt}" title="{title}" '
            f'class="looking-glass-flag" '
            f'style="height:{h};width:auto;vertical-align:-0.15em;'
            f'display:inline-block;border-radius:2px" '
            f'decoding="async" />'
        )


def flag_info(code: Any) -> Flag:
    original = str(code).strip().upper() if code is not None else ""
    cc = _letters(code)
    if not cc:
        shown = original if original else "??"
        return Flag(code=shown, emoji=_UNKNOWN_EMOJI, name="Unknown", url=None)
    return Flag(
        code=cc,
        emoji=country_to_flag(cc),
        name=country_name(cc),
        url=flag_url(cc),
    )


def flag_html(code: Any, *, height: str = "1.1em") -> str:
    """HTML that shows a real flag in a browser."""
    return flag_info(code).html(height=height)


def lookup_fields(code: Any) -> Dict[str, str]:
    """Fields to attach to an IP lookup result."""
    info = flag_info(code)
    fields = {"flag": info.emoji}
    if info.name:
        fields["country_name"] = info.name
    if info.url:
        fields["flag_url"] = info.url
        fields["flag_html"] = info.html()
    return fields


def supported_countries() -> List[Dict[str, str]]:
    """ISO codes this intel layer can name (CLDR) and usually flag."""
    codes = set()
    for key in _EN.territories:
        if len(key) != 2 or not key.isalpha() or key != key.upper():
            continue
        if key in _NO_ASSET:
            continue
        if country_name(key):
            codes.add(key)
    for key in ("EU", "UN", "XK"):
        if flag_url(key) or country_name(key):
            codes.add(key)
    rows: List[Dict[str, str]] = []
    for cc in sorted(codes):
        info = flag_info(cc)
        row: Dict[str, str] = {"code": info.code, "name": info.name or info.code}
        if info.url:
            row["flag_url"] = info.url
        rows.append(row)
    return rows


if __name__ == "__main__":
    for sample in ("AU", "US", "GB", "UK", "EU", "XK", "??"):
        info = flag_info(sample)
        print(info.text())
        print(" ", info.html())
