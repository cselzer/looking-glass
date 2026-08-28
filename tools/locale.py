#!/usr/bin/env python3
"""Ship looking-glass locale catalogs from a git checkout. Not in the pip wheel."""

from __future__ import annotations

import sys
from pathlib import Path

# `python tools/locale.py` puts this directory on sys.path and shadows stdlib locale.
_SCRIPT = Path(__file__).resolve()
_TOOLS = _SCRIPT.parent
_ROOT = _TOOLS.parent
sys.path[:] = [p for p in sys.path if p and Path(p).resolve() != _TOOLS]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
import textwrap
import unicodedata
from typing import Any, Dict, List, Mapping, Optional

import click

from looking_glass.i18n import harvest_click, inventory_messages, normalize_lang, write_locale
from looking_glass.i18n.catalog import package_locales_dir

from tools.engine import configure_logging, reset_locale, status_payload, translate
from tools.providers import DEFAULT_READ_TIMEOUT, LocaleCliError
from tools.ship_langs import list_ship_langs, require_ship_lang, ship_codes


def _want_json() -> bool:
    ctx = click.get_current_context(silent=True)
    if ctx is None:
        return False
    obj = ctx.find_root().obj
    return bool(isinstance(obj, dict) and obj.get("json"))


def _can_prompt() -> bool:
    if _want_json():
        return False
    try:
        return bool(sys.stdin.isatty())
    except Exception:
        return False


def _review_failed(payload: Dict[str, Any]) -> List[str]:
    """TTY y/n per failed key: y drops TM (retry), n stamps TM (keep)."""
    from tools import tm as tm_mod
    from tools.engine import load_dst

    failed = [str(key) for key in (payload.get("failed") or [])]
    if not failed:
        return []
    reasons = payload.get("failed_reasons") if isinstance(payload.get("failed_reasons"), dict) else {}
    dst_path = payload.get("dst")
    tm_path = payload.get("tm")
    dst = load_dst(dst_path) if dst_path else {}
    memory = tm_mod.load_tm(tm_path) if tm_path else {"version": 1, "keys": {}}
    leftover: List[str] = []
    for key in failed:
        row = dst.get(key) if isinstance(dst.get(key), dict) else {}
        en = str((row or {}).get("en") or "")
        reason = str(reasons.get(key) or "verify")
        snippet = textwrap.shorten(en.replace("\n", " "), width=80, placeholder="...")
        lines = [f"Mark {key} invalid so the next pass resends it?", f"    {reason}"]
        if snippet:
            lines.append(f"    {snippet}")
        if click.confirm("\n".join(lines), default=None):
            keys = memory.setdefault("keys", {})
            if isinstance(keys, dict):
                keys.pop(key, None)
            leftover.append(key)
        else:
            tm_mod.put_tm_key(
                memory,
                key,
                en=en,
                text=str((row or {}).get("text") or en),
                provider=payload.get("provider"),
                model=payload.get("model"),
            )
    if tm_path:
        tm_mod.save_tm(tm_path, memory)
    return leftover


def _rel(path: str | Path) -> str:
    dest = Path(path)
    try:
        return str(dest.resolve().relative_to(_ROOT))
    except ValueError:
        return str(dest)


def _emit(payload: Mapping[str, Any], *, kind: str) -> None:
    if _want_json():
        click.echo(json.dumps(dict(payload), ensure_ascii=False, indent=2))
        return
    renderer = {
        "harvest": _render_harvest,
        "status": _render_status,
        "translate": _render_translate,
        "models": _render_models,
        "configure": _render_configure,
        "configure-save": _render_configure_save,
        "glossary": _render_glossary,
        "providers": _render_providers,
        "languages": _render_languages,
        "reset": _render_reset,
    }.get(kind)
    if renderer is None:
        click.echo(json.dumps(dict(payload), ensure_ascii=False, indent=2))
        return
    renderer(payload)


def _render_harvest(payload: Mapping[str, Any]) -> None:
    path = _rel(str(payload.get("path") or ""))
    keys = payload.get("keys")
    extra = f"  ({keys} keys)" if keys is not None else ""
    click.echo(f"📝  wrote {path}{extra}")
    if payload.get("langs") is not None:
        _render_status_all(payload)


def _render_reset(payload: Mapping[str, Any]) -> None:
    removed = [str(path) for path in (payload.get("removed") or [])]
    if not removed:
        click.echo("📭  nothing to delete")
        return
    for path in removed:
        click.echo(f"🗑   {_rel(path)}")
    click.echo("👉  python tools/locale.py translate --provider grok --all")


def _fmt_tok(n: int) -> str:
    if n >= 1000:
        return f"~{n / 1000:.0f}k"
    return f"~{n}"


_ESTIMATE_KEYS = ("batches", "batch_size", "est_input", "est_output", "est_tokens")


def _format_estimate(payload: Mapping[str, Any]) -> str:
    batches = int(payload.get("batches") or 0)
    size = int(payload.get("batch_size") or 25)
    inn = int(payload.get("est_input") or 0)
    out = int(payload.get("est_output") or 0)
    return (
        f"📦  {batches} batches × {size}  {_fmt_tok(inn)} in / {_fmt_tok(out)} out tokens "
        f"(estimate, no retries)"
    )


def _render_estimate(payload: Mapping[str, Any]) -> None:
    click.echo(_format_estimate(payload))


def _render_status_all(payload: Mapping[str, Any]) -> None:
    rows = [row for row in (payload.get("langs") or []) if isinstance(row, dict)]
    if not rows:
        click.echo("📭  no generated locales")
        click.echo("👉  python tools/locale.py translate LANG --provider grok")
        return
    for row in rows:
        code = row.get("lang") or "?"
        new = int(row.get("new") or 0)
        changed = int(row.get("changed") or 0)
        skip = int(row.get("unchanged") or 0)
        click.echo(f"🔍  {code}   ✨ {new} new  🔁 {changed} changed  ✅ {skip} skip")
    stale = [str(code) for code in (payload.get("stale") or [])]
    if stale:
        click.echo("👉  python tools/locale.py translate --provider grok")
    else:
        click.echo("🎉  all caught up")


def _render_status(payload: Mapping[str, Any]) -> None:
    if payload.get("langs") is not None:
        _render_status_all(payload)
        return
    lang = payload.get("lang") or "?"
    new = int(payload.get("new") or 0)
    changed = int(payload.get("changed") or 0)
    skip = int(payload.get("unchanged") or 0)
    missing = int(payload.get("missing") or 0)
    click.echo(
        f"🔍  {lang}   ✨ {new} new  🔁 {changed} changed  ✅ {skip} skip  🕳️ {missing} missing"
    )
    _render_estimate(payload)
    if new or changed or payload.get("copy_through_dirty"):
        if skip == 0:
            click.echo("💡  first run — every key will be sent")
        click.echo(f"👉  python tools/locale.py translate {lang} --provider grok")
    else:
        click.echo("🎉  all caught up")


def _render_translate(payload: Mapping[str, Any]) -> None:
    lang = payload.get("lang") or "?"
    provider = payload.get("provider") or "?"
    model = payload.get("model") or "?"
    dry = bool(payload.get("dry_run")) or "sent" not in payload
    click.echo(f"🌍  {lang}  via {provider} / {model}")
    click.echo(
        f"    ✨ {payload.get('new', 0)} new  🔁 {payload.get('changed', 0)} changed  "
        f"✅ {payload.get('unchanged', 0)} skip"
    )
    if dry:
        nsend = len(payload.get("send") or [])
        click.echo(f"    👀 dry-run  would send {nsend} keys  (nobody called)")
        _render_estimate(payload)
        return
    failed = list(payload.get("failed") or [])
    click.echo(f"    📤 sent {payload.get('sent', 0)}   💥 failed {len(failed)}")
    for key in failed:
        click.echo(f"        {key}")
    dst = payload.get("dst")
    tm = payload.get("tm")
    if dst:
        click.echo(f"📝  {_rel(str(dst))}")
    if tm:
        click.echo(f"🧠  {_rel(str(tm))}")
    if failed:
        return
    if payload.get("sent"):
        name = Path(str(dst)).name if dst else "LANG.json"
        click.echo(f"💾  commit {name} and {name}.tm.json together")
    elif not payload.get("new") and not payload.get("changed"):
        click.echo("🎉  all caught up")


def _render_models(payload: Mapping[str, Any]) -> None:
    current = str(payload.get("model") or "")
    rows = payload.get("models") or []
    if not rows:
        click.echo("📭  no models")
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        mid = str(row.get("id") or "")
        if not mid:
            continue
        mark = "⭐" if mid == current or row.get("mark") == "*" else "  "
        click.echo(f"{mark} {mid}")


def _key_badge(source: str) -> str:
    if source == "env":
        return "🔑 env"
    if source == "file":
        return "🔑 file"
    return "📭 missing"


def _render_configure(payload: Mapping[str, Any]) -> None:
    provider = payload.get("provider") or "?"
    model = payload.get("model") or "?"
    click.echo(f"⚙️  {provider}  model {model}  {_key_badge(str(payload.get('key_source') or ''))}")


def _render_configure_save(payload: Mapping[str, Any]) -> None:
    provider = payload.get("provider") or "?"
    model = payload.get("model") or "?"
    click.echo(f"✅  saved {provider} model {model}")


def _render_glossary(payload: Mapping[str, Any]) -> None:
    terms = [str(t) for t in (payload.get("glossary") or []) if t]
    click.echo(f"📚  {len(terms)} terms")
    if terms:
        click.echo(textwrap.fill(", ".join(terms), width=88))


def _render_providers(payload: Mapping[str, Any]) -> None:
    rows = payload.get("providers") or []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        name = str(row.get("provider") or "")
        model = str(row.get("model") or "")
        badge = _key_badge(str(row.get("key_source") or ""))
        reach = "✅" if row.get("reachable") else "—"
        prefix = "🔌 " if i == 0 else "   "
        click.echo(f"{prefix} {name:<8} {badge:<12} {model:<22} {reach}")


def _display_width(text: str) -> int:
    """Terminal cells: wide CJK is 2, combining marks are 0."""
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("F", "W") else 1
    return width


def _pad_display(text: str, width: int) -> str:
    pad = max(0, width - _display_width(text))
    return f"{text}{' ' * pad}"


def _render_languages(payload: Mapping[str, Any]) -> None:
    rows = [row for row in (payload.get("languages") or []) if isinstance(row, dict)]
    click.echo(f"🌐  {len(rows)} ship locales  (✓ catalog on disk)")
    if not rows:
        return
    keys = ("code", "english", "native")
    widths = [0, 0, 0]
    estimates = [_format_estimate(row) for row in rows]
    est_width = max((_display_width(text) for text in estimates), default=0)
    for row in rows:
        for i, key in enumerate(keys):
            widths[i] = max(widths[i], _display_width(str(row.get(key) or "")))
    for row, estimate in zip(rows, estimates):
        mark = "✓" if row.get("shipped") else "·"
        click.echo(
            f"{_pad_display(str(row.get('code') or ''), widths[0])}  "
            f"{_pad_display(str(row.get('english') or ''), widths[1])}  "
            f"{_pad_display(str(row.get('native') or ''), widths[2])}  "
            f"{mark}  {_pad_display(estimate, est_width)}"
        )


class _LocaleExit(click.ClickException):
    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = code


def _fail(exc: BaseException) -> None:
    if isinstance(exc, LocaleCliError):
        raise _LocaleExit(str(exc), int(exc.exit_code)) from exc
    if isinstance(exc, ValueError):
        raise _LocaleExit(str(exc), 2) from exc
    raise exc


def _package_json(lang: str) -> Path:
    return package_locales_dir() / f"{normalize_lang(lang)}.json"


def generated_langs() -> List[str]:
    """Ship codes that already have a package catalog (not en, not first-time)."""
    folder = package_locales_dir()
    out: List[str] = []
    for code in ship_codes():
        if code == "en":
            continue
        if (folder / f"{code}.json").is_file():
            out.append(code)
    return out


def _is_stale(payload: Mapping[str, Any]) -> bool:
    return bool(
        int(payload.get("new") or 0)
        or int(payload.get("changed") or 0)
        or payload.get("copy_through_dirty")
    )


def all_lang_status(
    *,
    batch_size: int = 25,
    glossary_path: Optional[str] = None,
) -> Dict[str, Any]:
    src = str(_package_json("en"))
    langs: List[Dict[str, Any]] = []
    stale: List[str] = []
    for code in generated_langs():
        row = status_payload(
            src,
            str(_package_json(code)),
            lang=code,
            batch_size=batch_size,
            glossary_path=glossary_path,
        )
        langs.append(row)
        if _is_stale(row):
            stale.append(code)
    return {"ok": not stale, "langs": langs, "stale": stale}


@click.group()
@click.option("--json", "as_json", is_flag=True, help="Print the full payload as JSON.")
@click.option("-v", "--verbose", count=True, help="DEBUG logging on stderr.")
@click.option("--log", "log_file", type=click.Path(dir_okay=False), default=None, help="Write logs to FILE instead of stderr.")
@click.pass_context
def cli(ctx: click.Context, as_json: bool, verbose: int, log_file: Optional[str]) -> None:
    """Rebuild English and translate shipped UI catalogs (not the looking-glass CLI)."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = as_json
    configure_logging(verbose, log_file)


@cli.command("harvest")
def harvest() -> None:
    """Rebuild looking_glass/locales/en.json from inventory + Click help."""
    from looking_glass.cli.entry import cli as looking_glass_cli

    messages = inventory_messages()
    messages.update(harvest_click(looking_glass_cli))
    dest = write_locale("en", messages, operator=False)
    check = all_lang_status()
    _emit(
        {
            "ok": True,
            "path": str(dest),
            "keys": len(messages),
            "langs": check["langs"],
            "stale": check["stale"],
        },
        kind="harvest",
    )


@cli.command("status")
@click.argument("lang", required=False, default=None)
@click.option("--src", "src_file", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--dst", "dst_file", type=click.Path(dir_okay=False), default=None)
@click.option("--tm", "tm_file", type=click.Path(dir_okay=False), default=None)
@click.option("--batch-size", type=click.IntRange(1), default=25, show_default=True)
@click.option("--glossary", "glossary_file", type=click.Path(exists=True, dir_okay=False), default=None)
def status_cmd(
    lang: Optional[str],
    src_file: Optional[str],
    dst_file: Optional[str],
    tm_file: Optional[str],
    batch_size: int,
    glossary_file: Optional[str],
) -> None:
    """Count new / changed / unchanged / missing vs translation memory.

    Omit LANG to report every generated catalog. Exit 1 if any is stale.
    """
    if not lang:
        payload = all_lang_status(batch_size=batch_size, glossary_path=glossary_file)
        _emit(payload, kind="status")
        stale = list(payload.get("stale") or [])
        if stale:
            raise _LocaleExit(f"{len(stale)} locale(s) stale", 1)
        return
    lang = normalize_lang(lang)
    try:
        require_ship_lang(lang)
    except LocaleCliError as exc:
        _fail(exc)
        return
    src = src_file or str(_package_json("en"))
    dst = dst_file or str(_package_json(lang))
    try:
        payload = status_payload(
            src,
            dst,
            lang=lang,
            tm_path=tm_file,
            batch_size=batch_size,
            glossary_path=glossary_file,
        )
    except LocaleCliError as exc:
        _fail(exc)
        return
    _emit(payload, kind="status")


@cli.command("translate")
@click.argument("lang", required=False, default=None)
@click.option("--src", "src_file", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--dst", "dst_file", type=click.Path(dir_okay=False), default=None)
@click.option("--provider", type=click.Choice(["claude", "openai", "grok"]), required=True)
@click.option("--only-changed/--all", "only_changed", default=True, help="Translate new/changed keys only.")
@click.option("--force", is_flag=True, help="Same as --all.")
@click.option("--glossary", "glossary_file", type=click.Path(exists=True, dir_okay=False), default=None)
@click.option("--batch-size", type=click.IntRange(1), default=25, show_default=True)
@click.option("--model", "model_name", default=None, help="One-shot model override; does not write config.")
@click.option("--tm", "tm_file", type=click.Path(dir_okay=False), default=None)
@click.option("--dry-run", is_flag=True, help="Print the to-send key list; call nobody.")
@click.option(
    "--timeout",
    type=click.FloatRange(1),
    default=DEFAULT_READ_TIMEOUT,
    show_default=True,
    help="HTTP read timeout in seconds (connect stays 10s).",
)
@click.option(
    "--reasoning-effort",
    type=click.Choice(["low", "high"]),
    default="high",
    show_default=True,
    help="Grok thinking effort (ignored by Claude/OpenAI).",
)
def translate_cmd(
    lang: Optional[str],
    src_file: Optional[str],
    dst_file: Optional[str],
    provider: str,
    only_changed: bool,
    force: bool,
    glossary_file: Optional[str],
    batch_size: int,
    model_name: Optional[str],
    tm_file: Optional[str],
    dry_run: bool,
    timeout: float,
    reasoning_effort: str,
) -> None:
    """Translate package en.json into looking_glass/locales/LANG.json (TM, only-changed).

    Omit LANG to update every generated catalog that has new or changed keys.
    """
    only = False if force else only_changed
    if not lang:
        _translate_generated(
            provider=provider,
            only_changed=only,
            glossary_file=glossary_file,
            batch_size=batch_size,
            model_name=model_name,
            dry_run=dry_run,
            timeout=timeout,
            src_file=src_file,
            reasoning_effort=reasoning_effort,
        )
        return
    lang = normalize_lang(lang)
    try:
        require_ship_lang(lang)
    except LocaleCliError as exc:
        _fail(exc)
        return
    src = src_file or str(_package_json("en"))
    dst = dst_file or str(_package_json(lang))
    _translate_one(
        lang,
        src=src,
        dst=dst,
        provider=provider,
        only_changed=only,
        glossary_file=glossary_file,
        batch_size=batch_size,
        model_name=model_name,
        tm_file=tm_file,
        dry_run=dry_run,
        timeout=timeout,
        reasoning_effort=reasoning_effort,
        emit=True,
        fail_on_verify=True,
    )


def _translate_one(
    lang: str,
    *,
    src: str,
    dst: str,
    provider: str,
    only_changed: bool,
    glossary_file: Optional[str],
    batch_size: int,
    model_name: Optional[str],
    tm_file: Optional[str],
    dry_run: bool,
    timeout: float,
    reasoning_effort: str,
    emit: bool,
    fail_on_verify: bool,
) -> Dict[str, Any]:
    try:
        payload = translate(
            src,
            dst,
            lang=lang,
            provider=provider,
            model=model_name,
            only_changed=only_changed,
            glossary_path=glossary_file,
            batch_size=batch_size,
            tm_path=tm_file,
            dry_run=dry_run,
            timeout=timeout,
            reasoning_effort=reasoning_effort,
        )
    except LocaleCliError as exc:
        _fail(exc)
        return {}
    payload["dry_run"] = dry_run
    if payload.get("failed") and not dry_run and _can_prompt():
        remaining = _review_failed(payload)
        payload["failed"] = remaining
        payload["ok"] = not remaining
    if emit:
        _emit(payload, kind="translate")
    if fail_on_verify and payload.get("failed"):
        raise _LocaleExit(
            f"{len(payload['failed'])} key(s) failed glossary/placeholder verify",
            4,
        )
    return payload


def _translate_generated(
    *,
    provider: str,
    only_changed: bool,
    glossary_file: Optional[str],
    batch_size: int,
    model_name: Optional[str],
    dry_run: bool,
    timeout: float,
    src_file: Optional[str],
    reasoning_effort: str,
) -> None:
    codes = generated_langs()
    src = src_file or str(_package_json("en"))
    rows: List[Dict[str, Any]] = []
    leftover: List[str] = []
    if not codes:
        payload = {"ok": True, "langs": [], "stale": []}
        if _want_json():
            _emit(payload, kind="status")
        else:
            _render_status_all(payload)
        return
    for code in codes:
        dst = str(_package_json(code))
        if only_changed:
            st = status_payload(src, dst, lang=code, batch_size=batch_size, glossary_path=glossary_file)
            if not _is_stale(st):
                if not _want_json():
                    click.echo(f"🎉  {code}  all caught up")
                rows.append({**st, "send": [], "dry_run": dry_run, "sent": 0, "failed": []})
                continue
        payload = _translate_one(
            code,
            src=src,
            dst=dst,
            provider=provider,
            only_changed=only_changed,
            glossary_file=glossary_file,
            batch_size=batch_size,
            model_name=model_name,
            tm_file=None,
            dry_run=dry_run,
            timeout=timeout,
            reasoning_effort=reasoning_effort,
            emit=not _want_json(),
            fail_on_verify=False,
        )
        rows.append(payload)
        leftover.extend(str(key) for key in (payload.get("failed") or []))
    if _want_json():
        _emit({"ok": not leftover, "langs": rows}, kind="translate")
    if leftover:
        raise _LocaleExit(
            f"{len(leftover)} key(s) failed glossary/placeholder verify",
            4,
        )


@cli.command("models")
@click.option("--provider", type=click.Choice(["claude", "openai", "grok"]), required=True)
def models_cmd(provider: str) -> None:
    """List live chat/text models for PROVIDER. Current config is marked *."""
    from tools.providers import configured_model, list_models

    try:
        rows = list_models(provider)
    except LocaleCliError as exc:
        _fail(exc)
        return
    _emit(
        {
            "ok": True,
            "provider": provider,
            "model": configured_model(provider),
            "models": rows,
        },
        kind="models",
    )


@cli.command("configure")
@click.option("--provider", type=click.Choice(["claude", "openai", "grok"]), required=True)
@click.option("--model", "model_name", default=None)
@click.option("--api-key", "api_key", default=None)
@click.option("--force-model", is_flag=True, help="Accept a model id not returned by models.")
def configure_cmd(
    provider: str, model_name: Optional[str], api_key: Optional[str], force_model: bool
) -> None:
    """Persist provider model/key to ~/.looking-glass/locale.json, or show current settings."""
    from tools.providers import set_provider, show_provider

    try:
        if model_name is None and api_key is None:
            payload = show_provider(provider)
            kind = "configure"
        else:
            payload = set_provider(
                provider, model=model_name, api_key=api_key, force_model=force_model
            )
            kind = "configure-save"
    except LocaleCliError as exc:
        _fail(exc)
        return
    _emit(payload, kind=kind)


@cli.group("glossary")
def glossary_group() -> None:
    """Print the baked glossary (package glossary.json is merged; FILE appends)."""


@glossary_group.command("show")
@click.option("--glossary", "glossary_file", type=click.Path(exists=True, dir_okay=False), default=None)
def glossary_show(glossary_file: Optional[str]) -> None:
    """Print the effective glossary (DEFAULT ∪ package glossary.json ∪ FILE)."""
    from tools.glossary import effective_glossary

    try:
        terms = effective_glossary(glossary_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _fail(ValueError(str(exc)))
        return
    except LocaleCliError as exc:
        _fail(exc)
        return
    _emit({"ok": True, "glossary": terms}, kind="glossary")


@cli.command("providers")
def providers_cmd() -> None:
    """Show key presence, configured model, and whether models is reachable."""
    from tools.providers import provider_status

    rows = provider_status()
    _emit({"ok": True, "providers": rows}, kind="providers")


@cli.command("languages")
def languages_cmd() -> None:
    """List curated ship locales (add a row in tools/ship_langs.py to extend)."""
    rows = list_ship_langs(package_locales_dir())
    src = str(_package_json("en"))
    for row in rows:
        try:
            status = status_payload(src, str(_package_json(str(row["code"]))), lang=str(row["code"]))
        except LocaleCliError as exc:
            _fail(exc)
            return
        for key in _ESTIMATE_KEYS:
            row[key] = status[key]
    _emit({"ok": True, "languages": rows}, kind="languages")


@cli.command("reset")
@click.argument("lang", required=False, default=None)
def reset_cmd(lang: Optional[str]) -> None:
    """Delete LANG.json and LANG.json.tm.json (never en). Omit LANG for all ship locales.

    Does not call a model. Run translate --all afterwards yourself.
    """
    try:
        payload = reset_locale(lang)
    except LocaleCliError as exc:
        _fail(exc)
        return
    _emit(payload, kind="reset")


if __name__ == "__main__":
    cli()
