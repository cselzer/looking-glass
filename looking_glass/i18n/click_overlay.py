"""Click help overlay and harvest from the live command tree."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import click

from .catalog import t


def walk_click(cmd: click.Command, path: List[str]) -> List[Tuple[click.Command, List[str]]]:
    rows = [(cmd, path)]
    if not isinstance(cmd, click.Group):
        return rows
    ctx = click.Context(cmd, info_name=path[-1] if path else cmd.name or "looking-glass")
    for name in cmd.list_commands(ctx):
        sub = cmd.get_command(ctx, name)
        if sub is None or sub.hidden:
            continue
        rows.extend(walk_click(sub, path + [name]))
    return rows


def help_id(path: List[str]) -> str:
    bits = [p for p in path if p and p != "looking-glass"]
    if not bits:
        return "cli.help"
    return "cli." + ".".join(bits) + ".help"


def opt_id(path: List[str], name: str) -> str:
    bits = [p for p in path if p and p != "looking-glass"]
    if not bits:
        return f"cli.opt.{name}"
    return "cli." + ".".join(bits) + f".opt.{name}"


def harvest_click(cli: click.Group) -> Dict[str, Dict[str, str]]:
    out: Dict[str, Dict[str, str]] = {}
    for cmd, path in walk_click(cli, ["looking-glass"]):
        text = (getattr(cmd, "_help_en", None) or cmd.help or cmd.short_help or "").strip()
        if text:
            out[help_id(path)] = {"text": text, "en": text}
        for param in cmd.params:
            if not isinstance(param, click.Option) or not param.help:
                continue
            opt_help = getattr(param, "_help_en", None) or param.help
            out[opt_id(path, param.name or "opt")] = {"text": opt_help, "en": opt_help}
    return out


def overlay_click(cli: click.Group) -> None:
    for cmd, path in walk_click(cli, ["looking-glass"]):
        if not hasattr(cmd, "_help_en"):
            cmd._help_en = cmd.help
        key = help_id(path)
        translated = t(key)
        cmd.help = translated if translated != key else cmd._help_en
        for param in cmd.params:
            if not isinstance(param, click.Option) or param.help is None:
                continue
            if not hasattr(param, "_help_en"):
                param._help_en = param.help
            oid = opt_id(path, param.name or "opt")
            translated_opt = t(oid)
            param.help = translated_opt if translated_opt != oid else param._help_en
