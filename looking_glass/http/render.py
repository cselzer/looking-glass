"""Jinja2 templates shipped with the package; ~/.looking-glass/templates overrides them."""

from __future__ import annotations

from pathlib import Path

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, select_autoescape

from ..utility import get_root

_PACKAGE_TEMPLATES = Path(__file__).resolve().parent / "templates"


def override_dir() -> Path:
    return Path(get_root()) / "templates"


def environment() -> Environment:
    from .static_files import static_url

    loaders = []
    extra = override_dir()
    if extra.is_dir():
        loaders.append(FileSystemLoader(str(extra)))
    loaders.append(FileSystemLoader(str(_PACKAGE_TEMPLATES)))
    env = Environment(
        loader=ChoiceLoader(loaders),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.globals["static_url"] = static_url
    return env


def render(name: str, **context: object) -> str:
    from ..i18n import active_locale, available_locales, t

    env = environment()
    env.globals["t"] = t
    env.globals["locale"] = active_locale()
    context.setdefault("locale", active_locale())
    context.setdefault("locales", available_locales())
    context.setdefault("user", None)
    from ..config import docs_enabled, docs_generated

    context.setdefault("docs_enabled", docs_enabled())
    context.setdefault("docs_generated", docs_generated())
    return env.get_template(name).render(**context)
