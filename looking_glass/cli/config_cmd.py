"""Click commands for the unified ~/.looking-glass/config.json."""

from __future__ import annotations

from typing import Optional

import click

from ..config import get as config_get
from ..config import known_keys, load, path, set_value
from .render import emit


@click.group("config", invoke_without_command=True)
@click.pass_context
def config_group(ctx: click.Context) -> None:
    """Show and edit ~/.looking-glass/config.json (locale, cache TTL/GUI, dataset refresh).

    Locale catalogs stay in ~/.looking-glass/locales. Datasets stay in ~/.looking-glass/data.
    Lookup caches stay in ~/.looking-glass/data/cache. Admin: `looking-glass auth password set`.

    \b
    looking-glass config
    looking-glass config get locale
    looking-glass config set cache.gui true
    looking-glass config set docs.enabled true
    looking-glass config set refresh.rir 2
    looking-glass config set history.snapshots -1
    looking-glass config set wall.challenge_ttl_days 5
    looking-glass config hostname
    looking-glass config hostname s1.example.com
    """
    if ctx.invoked_subcommand is None:
        _emit_show()


def _emit_show() -> None:
    cfg = load()
    emit({"ok": True, "path": path(), **cfg}, kind="config")


@config_group.command("show")
def config_show() -> None:
    """Print the operator config file."""
    _emit_show()


@config_group.command("get")
@click.argument("key")
def config_get_cmd(key: str) -> None:
    """Print one dotted key (locale, cache.gui, refresh.rir, …)."""
    try:
        value = config_get(key)
    except KeyError:
        raise click.UsageError(f"unknown key {key!r}; try {', '.join(known_keys())}")
    emit({"ok": True, "key": key, "value": value}, kind="config")


@config_group.command("set", context_settings={"ignore_unknown_options": True})
@click.argument("key")
@click.argument("value")
def config_set_cmd(key: str, value: str) -> None:
    """Set one dotted key and write ~/.looking-glass/config.json."""
    try:
        cfg = set_value(key, value)
    except KeyError:
        raise click.UsageError(f"unknown key {key!r}; try {', '.join(known_keys())}")
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    emit({"ok": True, "path": path(), "key": key, **cfg}, kind="config")


@config_group.command("hostname")
@click.argument("name", required=False, default=None)
def config_hostname_cmd(name: Optional[str]) -> None:
    """Set http.hostname from the node FQDN (Python getfqdn) or NAME."""
    from ..observe import hostname as detect_fqdn

    chosen = (name or "").strip() or detect_fqdn()
    if not chosen:
        raise click.UsageError("could not detect a hostname; pass one explicitly")
    try:
        cfg = set_value("http.hostname", chosen)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    emit(
        {
            "ok": True,
            "path": path(),
            "key": "http.hostname",
            "detected": not bool((name or "").strip()),
            **cfg,
        },
        kind="config",
    )
