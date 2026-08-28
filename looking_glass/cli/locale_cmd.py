"""Click commands for listing and managing operator UI locales."""

from __future__ import annotations

import json
import os
from typing import Optional

import click

from ..i18n import (
    active_locale,
    available_locales,
    clone_english,
    import_messages,
    load_locale_messages,
    locale_path,
    missing_keys,
    normalize_lang,
    set_locale,
    t,
    write_locale,
)
from .render import emit, emit_path, want_json


@click.group("locale")
def locale_group() -> None:
    """List and manage operator UI locale files (JSON APIs stay English)."""


@locale_group.command("list")
def locale_list() -> None:
    """List shipped and operator locales."""
    current = active_locale()
    rows = []
    for lang in available_locales():
        miss = missing_keys(lang)
        rows.append({"locale": lang, "active": lang == current, "missing": len(miss)})
    if want_json():
        emit({"ok": True, "locales": rows or [{"locale": "en", "active": True, "missing": 0}], "current": current})
        return
    if not rows:
        click.echo("en")
        return
    for row in rows:
        mark = "*" if row["active"] else " "
        click.echo(f"{mark} {row['locale']}  missing={row['missing']}")


@locale_group.command("add")
@click.argument("lang")
@click.argument("file", required=False, type=click.Path(exists=True, dir_okay=False))
def locale_add(lang: str, file: Optional[str]) -> None:
    """Install LANG from FILE, or clone English placeholders."""
    lang = normalize_lang(lang)
    if file:
        payload = json.loads(open(file, encoding="utf-8").read())
        messages = import_messages(payload)
    else:
        messages = clone_english()
    dest = write_locale(lang, messages)
    set_locale(lang)
    emit_path(dest)


@locale_group.command("edit")
@click.argument("lang")
@click.argument("key", required=False)
@click.option("--text", "text_value", default=None, help="Set this key's translated text.")
def locale_edit(lang: str, key: Optional[str], text_value: Optional[str]) -> None:
    """Print LANG, or set KEY with --text."""
    lang = normalize_lang(lang)
    messages = load_locale_messages(lang)
    if not key:
        emit({"ok": True, "locale": lang, "messages": messages}, kind="locale-catalog")
        return
    if text_value is None:
        emit({"ok": True, "key": key, **(messages.get(key) or {})}, kind="config")
        return
    row = messages.get(key) or {"en": t(key), "text": text_value}
    row = {"en": row.get("en") or t(key), "text": text_value}
    messages[key] = row
    dest = write_locale(lang, messages)
    set_locale(active_locale())
    emit_path(dest)


@locale_group.command("delete")
@click.argument("lang")
def locale_delete(lang: str) -> None:
    """Remove an operator locale file. English cannot be deleted."""
    lang = normalize_lang(lang)
    if lang == "en":
        raise click.UsageError(t("cli.locale.err.delete_en"))
    path = locale_path(lang, operator=True)
    if not path.is_file():
        raise click.UsageError(t("cli.locale.err.no_file", path=path))
    os.remove(path)
    if active_locale() == lang:
        set_locale("en")
    emit_path(str(path))
