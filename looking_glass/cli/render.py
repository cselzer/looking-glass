"""Click stdout: compact Rich by default, JSON with --json / LOOKING_GLASS_JSON."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import click
from rich.console import Console
from rich.pretty import Pretty
from rich.table import Table
from rich.text import Text

_SKIP_FIELDS = frozenset(
    {
        "pem",
        "der",
        "raw",
        "chain",
        "chain_pem",
        "certificate",
        "certificate_pem",
        "prefixes",
        "squares",
        "country_catalog",
        "files",
        "actions",
        "checks",
        "messages",
        "datasets",
        "hops",
        "answers",
        "records",
        "series",
        "day",
        "week",
        "intel",
        "systemd",
        "systemd_status",
        "send",
        "skipped",
        "glossary",
    }
)

_HEADER_KEYS = (
    "ok",
    "kind",
    "query",
    "ip",
    "asn",
    "country",
    "name",
    "host",
    "path",
    "action",
    "event",
    "error",
    "via",
    "protocol",
    "url",
)


def want_json() -> bool:
    raw = os.environ.get("LOOKING_GLASS_JSON")
    if raw is not None:
        return raw.strip().lower() not in ("0", "false", "no", "off", "")
    try:
        ctx = click.get_current_context(silent=True)
    except RuntimeError:
        ctx = None
    if ctx is None:
        return False
    obj = ctx.find_root().obj
    return bool(isinstance(obj, dict) and obj.get("json"))


def _console() -> Console:
    return Console(highlight=False, soft_wrap=True, emoji=True)


def emit(payload: Any, *, kind: Optional[str] = None, jsonl: bool = False) -> None:
    if jsonl:
        if want_json():
            click.echo(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
            return
        _render_jsonl_line(payload)
        return
    if want_json():
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    view = kind or _guess_kind(payload)
    renderer = {
        "lookup": _render_lookup,
        "wall-list": _render_wall_list,
        "wall-log": _render_wall_log,
        "wall-mutate": _render_wall_mutate,
        "wall-reset": _render_wall_reset,
        "config": _render_config,
        "cache": _render_cache,
        "auth": _render_auth,
        "validate": _render_validate,
        "serve": _render_serve,
        "daemons": _render_serve,
        "logs-stats": _render_logs_stats,
        "build": _render_build,
        "locale-catalog": _render_locale_catalog,
        "locale-status": _render_kv,
        "path": _render_path,
        "bench": _render_kv,
        "error": _render_error,
    }.get(view)
    if renderer is None:
        _render_pretty(payload)
        return
    renderer(payload)


def emit_path(dest: str, extra: Optional[Dict[str, Any]] = None) -> None:
    payload: Dict[str, Any] = {"ok": True, "path": dest}
    if extra:
        payload.update(extra)
    emit(payload, kind="path")


def _guess_kind(payload: Any) -> str:
    if not isinstance(payload, dict):
        return "pretty"
    if payload.get("ok") is False and payload.get("error") and len(payload) <= 6:
        return "error"
    if payload.get("action") == "reset" or (
        "cleared" in payload and payload.get("action") == "reset"
    ):
        return "wall-reset"
    if payload.get("action") in {"block", "allow", "challenge", "remove"}:
        return "wall-mutate"
    if "actions" in payload and "count" in payload:
        return "wall-log"
    if "country_catalog" in payload or (
        isinstance(payload.get("ip"), dict) and "block" in (payload.get("ip") or {})
    ):
        return "wall-list"
    if payload.get("kind") in {"ip", "asn", "country"} and "block" in payload:
        return "wall-list"
    if "checks" in payload and "failed" in payload:
        return "validate"
    if "datasets" in payload and "refresh" in payload:
        return "build"
    if "day" in payload and "week" in payload and "totals" in payload:
        return "logs-stats"
    if "users" in payload and "count" in payload:
        return "auth"
    if payload.get("removed") is not None and "users" not in payload and "ok" in payload:
        return "auth"
    if "namespaces" in payload or ("files" in payload and "ttl_days" in payload):
        return "cache"
    if isinstance(payload.get("intel"), dict) and isinstance(payload.get("https"), dict):
        return "daemons"
    if "running" in payload or payload.get("state") in {"running", "not_running", "started", "stopped"}:
        return "serve"
    if "messages" in payload and "locale" in payload:
        return "locale-catalog"
    if isinstance(payload.get("glossary"), list):
        return "locale-catalog"
    if "send_unique" in payload or ("send" in payload and "keys" in payload):
        return "locale-status"
    if "result" in payload or payload.get("kind") in {
        "ip",
        "asn",
        "dns",
        "tls",
        "mtr",
        "ping",
        "traceroute",
        "http",
        "rdap",
        "mail",
        "register",
    }:
        return "lookup"
    if "path" in payload and set(payload) <= {"ok", "path", "provider"}:
        return "path"
    if "key" in payload and "value" in payload:
        return "config"
    if "locale" in payload and "cache" in payload:
        return "config"
    return "pretty"


def _render_jsonl_line(payload: Any) -> None:
    if not isinstance(payload, dict):
        _console().print(str(payload))
        return
    query = (
        payload.get("query")
        or payload.get("ip")
        or payload.get("name")
        or payload.get("asn")
        or payload.get("country")
        or ""
    )
    mark = "ok" if payload.get("ok") else "fail"
    err = payload.get("error") or ""
    line = f"{mark}  {query}".rstrip()
    if err:
        line += f"  {err}"
    style = "green" if payload.get("ok") else "red"
    _console().print(Text(line, style=style))


def _render_path(payload: Any) -> None:
    if not isinstance(payload, dict):
        _console().print(str(payload))
        return
    dest = payload.get("path") or ""
    extra = payload.get("provider")
    text = str(dest)
    if extra:
        text += f" ({extra})"
    _console().print(text)


def _render_error(payload: Any) -> None:
    if not isinstance(payload, dict):
        _console().print(str(payload), style="red")
        return
    err = payload.get("error") or "error"
    _console().print(Text(str(err), style="red"))


def _value_style(key: str, value: Any) -> str:
    if key == "error":
        return "red"
    if key == "ok":
        return "green" if value else "red"
    if isinstance(value, bool):
        return "green" if value else "red"
    text = str(value).lower() if value is not None else ""
    if text in {"started", "running", "ready", "true"}:
        return "green"
    if text in {"fail", "failed", "error"}:
        return "red"
    if text in {"stopped", "not_running", "disabled", "false"}:
        return "dim"
    return ""


def _value_text(key: str, value: Any) -> Text:
    cell = _cell(value)
    style = _value_style(key, value)
    return Text(cell, style=style) if style else Text(cell)


def _kv_table(title: str, rows: Sequence[Tuple[str, Any]]) -> Table:
    table = Table(title=title or None, show_header=False, box=None, pad_edge=False)
    table.add_column("k", style="dim cyan", no_wrap=True)
    table.add_column("v", overflow="ellipsis")
    for key, value in rows:
        if value in (None, "", [], {}):
            continue
        table.add_row(str(key), _value_text(key, value))
    return table


def _cell(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, (list, tuple)):
        if not value:
            return "—"
        if len(value) > 8:
            return ", ".join(_cell(v) for v in value[:8]) + f" … +{len(value) - 8}"
        return ", ".join(_cell(v) for v in value)
    if isinstance(value, dict):
        return f"{{{len(value)} keys}}"
    text = str(value)
    if len(text) > 120:
        return text[:117] + "…"
    return text


def _flatten(data: Dict[str, Any], prefix: str = "") -> List[Tuple[str, Any]]:
    rows: List[Tuple[str, Any]] = []
    for key, value in data.items():
        if key in _SKIP_FIELDS:
            if isinstance(value, (list, dict)):
                rows.append((f"{prefix}{key}", f"[{len(value)}]"))
            continue
        dotted = f"{prefix}{key}"
        if isinstance(value, dict) and value and not _looks_scalar_map(value):
            rows.extend(_flatten(value, dotted + "."))
        else:
            rows.append((dotted, value))
    return rows


def _looks_scalar_map(value: Dict[str, Any]) -> bool:
    return all(not isinstance(v, (dict, list)) for v in value.values()) and len(value) <= 8


def _human_uptime(seconds: Any) -> Optional[str]:
    try:
        total = max(0, int(float(seconds)))
    except (TypeError, ValueError):
        return None
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts: List[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def _daemon_name(payload: Dict[str, Any]) -> str:
    if "socket" in payload or "ready" in payload:
        return "intel"
    if "fullchain" in payload or "acme_port" in payload or "port" in payload:
        return "https"
    return "daemon"


def _serve_line(name: str, payload: Dict[str, Any]) -> Text:
    running = bool(payload.get("running"))
    ready = payload.get("ready")
    state = str(payload.get("state") or "").strip()
    ok = payload.get("ok")
    if ok is False:
        mark, style, word = "✗", "bold red", state or "failed"
    elif running or state in {"started", "running", "issued", "unchanged"}:
        mark, style = "✓", "bold green"
        word = state or "running"
        if ready is False and running:
            word, style = "starting", "bold yellow"
    else:
        mark, style, word = "○", "dim", state or "stopped"
    bits = [mark, name, word]
    if payload.get("pid"):
        bits.append(f"pid {payload['pid']}")
    if name == "https" and payload.get("port") and not payload.get("error"):
        bits.append(f":{payload['port']}")
    up = _human_uptime(payload.get("uptime"))
    if up:
        bits.append(f"up {up}")
    if name == "https" and payload.get("days_left") is not None:
        try:
            bits.append(f"cert {int(payload['days_left'])}d")
        except (TypeError, ValueError):
            pass
    sd = payload.get("systemd")
    if isinstance(sd, dict) and sd.get("active_state"):
        bits.append(f"unit {sd['active_state']}")
        if sd.get("enabled") and not sd.get("active"):
            mark, style = "✗", "bold red"
            bits[0] = mark
    return Text("  ".join(str(b) for b in bits), style=style)


def _print_serve_error(payload: Dict[str, Any]) -> None:
    err = payload.get("error")
    if err:
        _console().print(Text(str(err), style="bold red"))


def _print_serve_paths(payload: Dict[str, Any]) -> None:
    con = _console()
    for key in ("fullchain", "privkey"):
        path = payload.get(key)
        if path:
            con.print(Text(f"    {key}  {path}"))


def _render_serve(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    intel = payload.get("intel")
    https = payload.get("https")
    if isinstance(intel, dict) and isinstance(https, dict):
        con.print(_serve_line("intel", intel))
        _print_serve_error(intel)
        con.print(_serve_line("https", https))
        _print_serve_error(https)
        _print_serve_paths(https)
        return
    name = _daemon_name(payload)
    con.print(_serve_line(name, payload))
    _print_serve_error(payload)
    if name == "https":
        _print_serve_paths(payload)


def _render_kv(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    rows: List[Tuple[str, Any]] = []
    for key, value in payload.items():
        if key in _SKIP_FIELDS:
            if isinstance(value, (list, dict)):
                rows.append((key, f"{len(value)} items; pass --json"))
            continue
        if isinstance(value, (list, dict)) and not _small_value(value):
            rows.append((key, f"{len(value)} items; pass --json"))
            continue
        rows.append((key, value))
    _console().print(_kv_table("", rows))


def _render_pretty(payload: Any) -> None:
    _console().print(
        Pretty(payload, max_depth=3, max_length=12, max_string=80, overflow="ellipsis")
    )


def _result_blob(payload: Dict[str, Any]) -> Dict[str, Any]:
    result = payload.get("result")
    return result if isinstance(result, dict) else {}


def _render_register_board(con: Console, result: Dict[str, Any]) -> None:
    label = result.get("label") or ""
    con.print(
        _kv_table(
            "result",
            [
                ("label", label),
                ("tlds", result.get("tlds")),
                ("no_dns", result.get("no_dns")),
                ("has_ns", result.get("has_ns")),
                ("unknown", result.get("unknown")),
            ],
        )
    )
    squares = result.get("squares") or []
    if not isinstance(squares, list) or not squares:
        return
    width = 80
    try:
        width = max(40, int(con.size.width or 80))
    except Exception:
        pass
    col = 8
    per = max(1, width // col)
    styles = {"no-dns": "bold green", "has-ns": "red", "unknown": "yellow"}
    row = Text()
    count = 0
    for item in squares:
        if not isinstance(item, dict):
            continue
        tld = str(item.get("tld") or "")[: col - 1]
        cell = f"{tld:<{col}}"
        row.append(cell, style=styles.get(str(item.get("status") or ""), "dim"))
        count += 1
        if count % per == 0:
            con.print(row)
            row = Text()
    if row.plain:
        con.print(row)


def _render_lookup(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    if payload.get("ok") is False:
        _render_error(payload)
        return
    header: List[Tuple[str, Any]] = []
    for key in _HEADER_KEYS:
        if key in payload and payload[key] not in (None, ""):
            header.append((key, payload[key]))
    if payload.get("total_ms") is not None:
        header.append(("ms", payload["total_ms"]))
    intel = payload.get("intel")
    if isinstance(intel, dict) and intel.get("running") is False:
        header.append(("intel", intel.get("message") or "not running"))
    if header:
        con.print(_kv_table("", header))
    result = _result_blob(payload)
    if payload.get("kind") == "register" or result.get("squares") is not None:
        _render_register_board(con, result)
        return
    hops = result.get("hops") or payload.get("hops")
    answers = result.get("answers") or result.get("records") or payload.get("answers")
    if isinstance(hops, list) and hops:
        con.print(_hop_table(hops))
        return
    if isinstance(answers, list) and answers:
        con.print(_answer_table(answers))
        return
    fields = _lookup_fields(result or payload)
    if fields:
        con.print(_kv_table("result", fields))
    rbl = payload.get("rbl")
    if isinstance(rbl, dict):
        con.print(
            _kv_table(
                "rbl",
                [
                    ("status", rbl.get("status")),
                    ("listed", rbl.get("listed")),
                    ("listed_on", rbl.get("listed_on")),
                    ("error", rbl.get("error")),
                ],
            )
        )


def _lookup_fields(result: Dict[str, Any]) -> List[Tuple[str, Any]]:
    prefer = (
        "ip",
        "prefix",
        "asn",
        "org_name",
        "country",
        "country_name",
        "status",
        "peer",
        "rtt_ms",
        "subject",
        "issuer",
        "not_after",
        "san",
        "verified",
        "count",
        "ipv4",
        "ipv6",
        "mx",
        "spf",
        "dmarc",
        "banner",
        "alpn",
        "version",
        "cipher",
        "ptr",
        "mtu",
        "name",
        "qtype",
        "rcode",
    )
    rows: List[Tuple[str, Any]] = []
    seen = set()
    for key in prefer:
        if key in result and key not in _SKIP_FIELDS:
            rows.append((key, _short_field(key, result[key])))
            seen.add(key)
    extra = 0
    for key, value in result.items():
        if key in seen or key in _SKIP_FIELDS or key in {"ok", "error", "hops", "answers"}:
            continue
        if isinstance(value, (dict, list)) and not _small_value(value):
            extra += 1
            continue
        rows.append((key, _short_field(key, value)))
        if len(rows) >= 18:
            extra += max(0, len(result) - len(seen) - extra)
            break
    if extra:
        rows.append(("…", f"{extra} more fields; pass --json"))
    prefixes = result.get("prefixes")
    if isinstance(prefixes, list) and "count" not in result:
        rows.append(("prefixes", len(prefixes)))
    return rows


def _small_value(value: Any) -> bool:
    if isinstance(value, list):
        return len(value) <= 6 and all(not isinstance(v, (dict, list)) for v in value)
    if isinstance(value, dict):
        return _looks_scalar_map(value)
    return True


def _short_field(key: str, value: Any) -> Any:
    if key == "san" and isinstance(value, list):
        return f"{len(value)} names"
    if key == "prefixes" and isinstance(value, list):
        return len(value)
    return value


def _hop_table(hops: Sequence[Dict[str, Any]]) -> Table:
    table = Table(title="hops", show_header=True, box=None, pad_edge=False)
    table.add_column("ttl", justify="right")
    table.add_column("host", overflow="ellipsis")
    table.add_column("rtt", justify="right")
    table.add_column("asn")
    table.add_column("loss", justify="right")
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        ttl = hop.get("ttl") or hop.get("hop") or ""
        host = hop.get("host") or hop.get("addr") or hop.get("ip") or "*"
        rtt = hop.get("rtt_ms") or hop.get("avg") or hop.get("rtt") or ""
        asn = hop.get("asn") or hop.get("org_name") or ""
        loss = hop.get("loss")
        loss_s = "" if loss in (None, "") else str(loss)
        table.add_row(str(ttl), str(host), _cell(rtt), str(asn), loss_s)
    return table


def _answer_table(answers: Sequence[Any]) -> Table:
    table = Table(title="answers", show_header=True, box=None, pad_edge=False)
    table.add_column("name", overflow="ellipsis")
    table.add_column("type")
    table.add_column("data", overflow="ellipsis")
    for row in answers[:40]:
        if isinstance(row, dict):
            table.add_row(
                str(row.get("name") or row.get("owner") or ""),
                str(row.get("type") or row.get("qtype") or ""),
                _cell(row.get("data") or row.get("rdata") or row.get("value") or ""),
            )
        else:
            table.add_row("", "", _cell(row))
    if len(answers) > 40:
        table.add_row("…", "", f"{len(answers) - 40} more; pass --json")
    return table


def _meta_for(meta: Any, value: Any) -> Dict[str, Any]:
    if not isinstance(meta, dict):
        return {}
    info = meta.get(str(value))
    return info if isinstance(info, dict) else {}


def _render_wall_list(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    path = payload.get("path")
    if path:
        con.print(Text(str(path), style="dim"))
    if isinstance(payload.get("ip"), dict):
        for label, blob in (("ip", payload["ip"]), ("asn", payload.get("asn")), ("country", payload.get("country"))):
            if isinstance(blob, dict):
                _print_wall_kind(con, label, blob)
        catalog = payload.get("country_catalog")
        if isinstance(catalog, list):
            con.print(Text(f"country catalog  {len(catalog)}", style="dim"))
        return
    kind = str(payload.get("kind") or "list")
    _print_wall_kind(con, kind, payload)


def _print_wall_kind(con: Console, label: str, blob: Dict[str, Any]) -> None:
    meta = blob.get("meta") if isinstance(blob.get("meta"), dict) else {}
    rows: List[Tuple[str, Any, str, str]] = []
    for bucket in ("allow", "block", "challenge"):
        for value in blob.get(bucket) or []:
            info = _meta_for(meta, value)
            rows.append((bucket, value, str(info.get("ts") or ""), str(info.get("note") or "")))
    if not rows:
        con.print(Text(f"{label}  (empty)", style="dim"))
        return
    table = Table(title=label, show_header=True, box=None, pad_edge=False)
    table.add_column("status")
    table.add_column("value")
    table.add_column("added")
    table.add_column("note", overflow="ellipsis")
    for bucket, value, ts, note in rows:
        table.add_row(bucket, str(value), ts, note)
    con.print(table)


def _render_wall_log(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    actions = payload.get("actions") or []
    con = _console()
    con.print(Text(f"{payload.get('count', len(actions))} events", style="dim"))
    table = Table(show_header=True, box=None, pad_edge=False)
    table.add_column("ts")
    table.add_column("event")
    table.add_column("kind")
    table.add_column("value")
    table.add_column("note", overflow="ellipsis")
    for row in actions[-50:] if isinstance(actions, list) else []:
        if not isinstance(row, dict):
            continue
        table.add_row(
            str(row.get("ts") or ""),
            str(row.get("event") or ""),
            str(row.get("kind") or ""),
            str(row.get("value") or ""),
            str(row.get("note") or ""),
        )
    con.print(table)


def _render_wall_mutate(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    action = payload.get("action") or ""
    value = payload.get("value")
    kind = payload.get("kind") or ""
    changed = "changed" if payload.get("changed") else "unchanged"
    _console().print(f"{action}  {kind}  {value}  ({changed})")
    counts = []
    for bucket in ("allow", "block", "challenge"):
        if bucket in payload and isinstance(payload[bucket], list):
            counts.append(f"{bucket}={len(payload[bucket])}")
    if counts:
        _console().print("  ".join(counts))


def _render_wall_reset(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    cleared = payload.get("cleared") or {}
    parts = [f"{k}={v}" for k, v in cleared.items() if v]
    status = "cleared " + ", ".join(parts) if parts else "already empty"
    _console().print(status)
    path = payload.get("path")
    if path:
        _console().print(Text(str(path), style="dim"))


def _render_config(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    skip = {"ok"}
    data = {k: v for k, v in payload.items() if k not in skip}
    _console().print(_kv_table("", _flatten(data)))


def _render_cache(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    header = [
        ("directory", payload.get("directory")),
        ("ttl_days", payload.get("ttl_days")),
        ("count", payload.get("count")),
        ("bytes", payload.get("bytes")),
        ("gui", payload.get("gui")),
    ]
    if payload.get("namespace"):
        header.insert(0, ("namespace", payload.get("namespace")))
    con.print(_kv_table("", header))
    files = payload.get("files") or []
    if not files and isinstance(payload.get("namespaces"), dict):
        files = []
        for blob in payload["namespaces"].values():
            files.extend((blob or {}).get("files") or [])
    if not files:
        return
    table = Table(title="files", show_header=True, box=None, pad_edge=False)
    table.add_column("ns")
    table.add_column("query", overflow="ellipsis")
    table.add_column("bytes", justify="right")
    for row in files[:30]:
        if not isinstance(row, dict):
            continue
        table.add_row(
            str(row.get("namespace") or ""),
            str(row.get("query") or row.get("name") or ""),
            str(row.get("bytes") or row.get("size") or ""),
        )
    if len(files) > 30:
        table.add_row("…", f"{len(files) - 30} more; pass --json", "")
    con.print(table)


def _render_auth(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    if "removed" in payload and "users" not in payload:
        _console().print(f"removed {payload.get('removed')} session(s)")
        return
    names = payload.get("users") or []
    _console().print(f"{payload.get('count', len(names))} user(s)")
    for name in names:
        _console().print(f"  {name}")


def _render_validate(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    con.print(
        _kv_table(
            "",
            [
                ("ok", payload.get("ok")),
                ("failed", payload.get("failed")),
                ("warned", payload.get("warned")),
                ("elapsed", payload.get("elapsed")),
                ("data", payload.get("data")),
            ],
        )
    )
    checks = payload.get("checks") or []
    table = Table(show_header=True, box=None, pad_edge=False)
    table.add_column("status")
    table.add_column("check", overflow="ellipsis")
    table.add_column("detail", overflow="ellipsis")
    for row in checks:
        if not isinstance(row, dict):
            continue
        table.add_row(
            str(row.get("status") or ""),
            str(row.get("check") or row.get("id") or ""),
            _cell(row.get("detail") or row.get("message") or ""),
        )
    con.print(table)


def _render_build(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    con.print(
        _kv_table(
            "",
            [
                ("ok", payload.get("ok")),
                ("elapsed_s", payload.get("elapsed_s")),
                ("data", payload.get("data")),
                ("log", payload.get("log")),
            ],
        )
    )
    datasets = payload.get("datasets")
    if not isinstance(datasets, dict):
        return
    table = Table(show_header=True, box=None, pad_edge=False)
    table.add_column("dataset")
    table.add_column("result")
    table.add_column("size")
    for name, row in datasets.items():
        if not isinstance(row, dict):
            table.add_row(str(name), _cell(row), "")
            continue
        table.add_row(str(name), str(row.get("result") or row.get("status") or ""), _cell(row.get("size") or row.get("bytes") or ""))
    con.print(table)


def _iso(stamp: Any) -> str:
    try:
        n = float(stamp)
    except (TypeError, ValueError):
        return ""
    return (
        datetime.fromtimestamp(n, timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _series_span(pages: Any) -> Tuple[str, str, int, int]:
    times: List[float] = []
    hits = 0
    errors = 0
    if isinstance(pages, dict):
        for rows in pages.values():
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                try:
                    times.append(float(row.get("t")))
                except (TypeError, ValueError):
                    pass
                hits += int(row.get("hits") or 0)
                errors += int(row.get("errors") or 0)
    if not times:
        return "", "", hits, errors
    return _iso(min(times)), _iso(max(times)), hits, errors


def _render_logs_stats(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    day_a, day_b, day_h, day_e = _series_span(payload.get("day"))
    week_a, week_b, week_h, week_e = _series_span(payload.get("week"))
    con.print(_kv_table("", [("step", payload.get("step"))]))
    table = Table(show_header=True, box=None, pad_edge=False)
    table.add_column("window")
    table.add_column("hits", justify="right")
    table.add_column("errors", justify="right")
    table.add_column("range")
    if day_a:
        table.add_row("day", str(day_h), str(day_e), f"{day_a} → {day_b}")
    if week_a:
        table.add_row("week", str(week_h), str(week_e), f"{week_a} → {week_b}")
    con.print(table)
    totals = payload.get("totals") or {}
    if isinstance(totals, dict) and totals:
        pages = Table(title="pages", show_header=True, box=None, pad_edge=False)
        pages.add_column("page")
        pages.add_column("hits", justify="right")
        pages.add_column("errors", justify="right")
        for page, row in sorted(totals.items()):
            blob = row if isinstance(row, dict) else {}
            pages.add_row(str(page), str(blob.get("hits") or 0), str(blob.get("errors") or 0))
        con.print(pages)


def _render_locale_catalog(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    messages = payload.get("messages")
    if isinstance(messages, dict):
        lang = payload.get("locale") or ""
        _console().print(f"{lang}  {len(messages)} keys  (pass --json to dump)")
        return
    glossary = payload.get("glossary")
    if isinstance(glossary, list):
        _console().print(f"{len(glossary)} glossary terms  (pass --json to dump)")
        return
    _render_kv(payload)
