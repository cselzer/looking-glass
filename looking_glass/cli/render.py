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
        "flag_url",
        "flag_html",
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
        "boot": _render_boot,
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
    if "keys" in payload and "count" in payload:
        return "auth"
    if "set" in payload and "ok" in payload and "result" not in payload:
        return "auth"
    if payload.get("removed") is not None and "ok" in payload and "keys" not in payload:
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
        "dnssec",
        "whois",
        "apex",
        "bgp",
        "ptr",
        "tcp",
        "pmtu",
        "reputation",
        "dnstrace",
    }:
        return "lookup"
    if payload.get("linger") is not None and payload.get("intel") is not None:
        return "boot"
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
    text = f"wrote {dest}" if dest else "wrote"
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


def _print_rows(con: Console, rows: Sequence[Tuple[str, Any]], title: str = "") -> None:
    if title:
        con.print(Text(title, style="dim"))
    for key, value in rows:
        if value in (None, "", [], {}):
            continue
        line = Text()
        line.append(str(key), style="dim cyan")
        line.append("  ")
        cell = _value_text(key, value)
        line.append(cell.plain, style=cell.style)
        con.print(line)


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
        if all(not isinstance(v, (dict, list)) for v in value):
            if len(value) > 8:
                return ", ".join(_cell(v) for v in value[:8]) + f" … +{len(value) - 8}"
            return ", ".join(_cell(v) for v in value)
        return f"{len(value)} items; --json"
    if isinstance(value, dict):
        if _small_value(value):
            return " ".join(f"{k}={_cell(v)}" for k, v in value.items())
        return f"{len(value)} keys; --json"
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
        if not https.get("running"):
            con.print(Text("https  stopped", style="dim"))
            _print_serve_error(https)
            return
        con.print(_serve_line("https", https))
        _print_serve_error(https)
        _print_serve_paths(https)
        return
    name = _daemon_name(payload)
    con.print(_serve_line(name, payload))
    _print_serve_error(payload)
    if name == "https" and (
        payload.get("running") or payload.get("issued") or str(payload.get("state") or "") == "issued"
    ):
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


def _boot_unit_line(name: str, blob: Any) -> str:
    if not isinstance(blob, dict):
        return f"{name}  no unit"
    if not blob.get("present"):
        return f"{name}  no unit"
    state = blob.get("active_state") or blob.get("enabled_state") or ""
    if blob.get("enabled"):
        return f"{name}  enabled  {state}".rstrip()
    return f"{name}  installed  {state}".rstrip()


def _render_boot(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    linger = payload.get("linger") if isinstance(payload.get("linger"), dict) else {}
    if linger.get("enabled"):
        linger_line = "linger  on"
    else:
        err = str(linger.get("error") or "")
        extra = "loginctl not found" if "not found" in err.lower() or not err else err
        linger_line = f"linger  off  {extra}".rstrip()
    con.print(Text(linger_line))
    con.print(Text(_boot_unit_line("intel", payload.get("intel"))))
    con.print(Text(_boot_unit_line("https", payload.get("https"))))


def _result_blob(payload: Dict[str, Any]) -> Dict[str, Any]:
    result = payload.get("result")
    return result if isinstance(result, dict) else {}


def _render_register_board(con: Console, result: Dict[str, Any], *, board: bool) -> None:
    label = result.get("label") or ""
    squares = result.get("squares") if isinstance(result.get("squares"), list) else []
    has_names = [
        str(item.get("tld") or "")
        for item in squares
        if isinstance(item, dict) and item.get("status") == "has-ns" and item.get("tld")
    ]
    shown = has_names[:8]
    ns_text = ", ".join(shown) if shown else "—"
    extra = len(has_names) - len(shown)
    if extra > 0:
        ns_text += f"  {extra} more; --json"
    _print_rows(
        con,
        [
            ("label", label),
            ("tlds", result.get("tlds")),
            ("no_dns", result.get("no_dns")),
            ("has_ns", result.get("has_ns")),
            ("unknown", result.get("unknown")),
            ("has_ns names", ns_text if has_names else None),
        ],
    )
    if not board:
        if squares:
            con.print(Text(f"{len(squares)} tlds; --json or --all", style="dim"))
        return
    if not squares:
        return
    con.print(Text("legend  green=no-dns red=has-ns yellow=unknown", style="dim"))
    styles = {"no-dns": "bold green", "has-ns": "red", "unknown": "yellow"}
    width = 80
    try:
        width = max(40, int(con.size.width or 80))
    except Exception:
        pass
    row = Text()
    used = 0
    for item in squares:
        if not isinstance(item, dict):
            continue
        tld = str(item.get("tld") or "")
        if not tld:
            continue
        piece = tld + " "
        if used and used + len(piece) > width:
            con.print(row)
            row = Text()
            used = 0
        row.append(piece, style=styles.get(str(item.get("status") or ""), "dim"))
        used += len(piece)
    if row.plain:
        con.print(row)


def _want_register_board() -> bool:
    try:
        ctx = click.get_current_context(silent=True)
    except RuntimeError:
        ctx = None
    if ctx is None:
        return False
    return bool(ctx.params.get("all_flag"))


def _via_short(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("python-"):
        return text.split("-", 1)[-1]
    return text or "tcp"


def _render_ping(con: Console, payload: Dict[str, Any], result: Dict[str, Any]) -> None:
    target = result.get("target") or payload.get("query") or ""
    ip = result.get("ip") or target
    tx = result.get("transmitted")
    rx = result.get("received")
    loss = result.get("loss_percent")
    via = _via_short(result.get("via") or payload.get("via"))
    stats = ""
    if result.get("min_ms") is not None:
        stats = f"  min/avg/max {result.get('min_ms')}/{result.get('avg_ms')}/{result.get('max_ms')} ms"
    loss_s = f"{loss}%" if loss is not None else ""
    counts = f"{rx}/{tx}" if tx is not None else ""
    con.print(Text(f"PING {target} ({ip})  {counts}  {loss_s}{stats}  via {via}"))
    for row in result.get("probes") or []:
        if not isinstance(row, dict):
            continue
        seq = row.get("seq")
        rtt = row.get("rtt_ms")
        rtt_s = f"{rtt} ms" if rtt is not None else (row.get("error") or "timeout")
        con.print(Text(f"seq {seq}  {rtt_s}"))


def _ip_line(result: Dict[str, Any], payload: Dict[str, Any]) -> Optional[str]:
    ip = result.get("ip") or payload.get("ip") or payload.get("query")
    if not ip:
        return None
    country = result.get("country") or ""
    name = result.get("country_name") or ""
    source = result.get("source") or ""
    flag = result.get("flag") or ""
    if not flag and country:
        try:
            from ..intel.flags import country_to_flag

            flag = country_to_flag(country)
        except Exception:
            flag = ""
    parts = [str(ip)]
    if country:
        parts.append(str(country))
    if name:
        parts.append(str(name))
    if source:
        parts.append(str(source))
    if flag:
        parts.append(str(flag))
    return "  ".join(parts)


def _dnssec_failed(result: Dict[str, Any]) -> bool:
    status = str(result.get("status") or "").lower()
    if status in {"bogus", "insecure", "indeterminate"}:
        return True
    if result.get("secure") is False:
        return True
    if result.get("broken") is True:
        return True
    return False


def _render_lookup(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    result = _result_blob(payload)
    kind = str(payload.get("kind") or result.get("kind") or "")
    if payload.get("ok") is False and not (kind == "ping" and result.get("probes")):
        _render_error(payload)
        return
    if kind == "ping" or result.get("probes"):
        _render_ping(con, payload, result or payload)
        return
    if kind == "register" or result.get("squares") is not None:
        _render_register_board(con, result, board=_want_register_board())
        return
    if kind in {"ip", "country"} or (
        result.get("ip") and result.get("country") and "hops" not in result
    ):
        line = _ip_line(result, payload)
        if line and kind in {"ip", "country", ""} and not result.get("subject") and not result.get("mx"):
            con.print(Text(line))
            return
    hops = result.get("hops") or payload.get("hops")
    answers = result.get("answers") or result.get("records") or payload.get("answers")
    if isinstance(hops, list) and hops:
        con.print(_hop_table(hops))
        return
    if isinstance(answers, list) and answers:
        con.print(_answer_table(answers))
        return
    if kind == "dnssec" and _dnssec_failed(result):
        status = result.get("status") or "bogus"
        con.print(Text(f"dnssec  {payload.get('query') or ''}  {status}", style="red"))
    fields = _lookup_fields(result or payload, kind=kind)
    if fields:
        _print_rows(con, fields)
    rbl = payload.get("rbl")
    if isinstance(rbl, dict):
        _print_rows(
            con,
            [
                ("status", rbl.get("status")),
                ("listed", rbl.get("listed")),
                ("listed_on", rbl.get("listed_on")),
                ("error", rbl.get("error")),
            ],
            title="rbl",
        )


def _lookup_fields(result: Dict[str, Any], kind: str = "") -> List[Tuple[str, Any]]:
    if kind in {"rdap", "whois"}:
        prefer = (
            "handle",
            "name",
            "cidr",
            "status",
            "contacts",
            "country",
            "country_name",
            "port43",
            "startAddress",
            "endAddress",
            "type",
        )
        cap = 12
    elif kind == "dnssec":
        prefer = (
            "status",
            "secure",
            "broken",
            "bogus",
            "qname",
            "algorithm",
            "ds",
            "dnskey",
        )
        cap = 12
    elif kind in {"tls", "tcp"}:
        prefer = (
            "peer",
            "port",
            "sni",
            "version",
            "cipher",
            "alpn",
            "subject",
            "issuer",
            "not_before",
            "not_after",
            "san",
            "verified",
            "issue",
            "rtt_ms",
        )
        cap = 16
    elif kind == "mail":
        prefer = (
            "mx",
            "spf",
            "dmarc",
            "dkim",
            "banner",
            "starttls",
            "ipv4",
            "ipv6",
        )
        cap = 16
    else:
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
        cap = 18
    rows: List[Tuple[str, Any]] = []
    seen = set()
    for key in prefer:
        if key in result and key not in _SKIP_FIELDS:
            rows.append((key, _short_field(key, result[key])))
            seen.add(key)
    extra = 0
    for key, value in result.items():
        if key in seen or key in _SKIP_FIELDS or key in {"ok", "error", "hops", "answers", "probes"}:
            continue
        if isinstance(value, (dict, list)) and not _small_value(value):
            extra += 1
            continue
        rows.append((key, _short_field(key, value)))
        if len(rows) >= cap:
            extra += 1
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


def _compact_map(value: Dict[str, Any]) -> str:
    return " ".join(f"{k}={_cell(v)}" for k, v in value.items())


def _headers_line(value: Dict[str, Any]) -> str:
    if value and all(v is True for v in value.values()):
        return "all true"
    if value and all(isinstance(v, bool) for v in value.values()):
        on = [k for k, v in value.items() if v]
        return ",".join(on) if on else "all false"
    return _compact_map(value)


def _render_config(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    skip = {"ok"}
    rows: List[Tuple[str, Any]] = []
    for key, value in payload.items():
        if key in skip:
            continue
        if key == "wall" and isinstance(value, dict):
            headers = value.get("headers") if isinstance(value.get("headers"), dict) else None
            rest = {k: v for k, v in value.items() if k != "headers"}
            if rest:
                rows.append(("wall", _compact_map(rest) if _small_value(rest) else rest))
            if headers:
                rows.append(("wall.headers", _headers_line(headers)))
            continue
        if isinstance(value, dict) and value:
            if all(not isinstance(v, (dict, list)) for v in value.values()):
                rows.append((key, _compact_map(value)))
            else:
                rows.append((key, f"config get {key}.*"))
            continue
        rows.append((key, value))
    _print_rows(con, rows)


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
    con = _console()
    if "removed" in payload and "keys" not in payload and "secret" not in payload:
        con.print(f"removed {payload.get('removed')} session(s)")
        return
    if payload.get("secret"):
        con.print(f"id {payload.get('id')}")
        if payload.get("name"):
            con.print(f"name {payload.get('name')}")
        con.print(str(payload.get("secret")))
        return
    if "keys" in payload:
        listed = payload.get("keys") or []
        con.print(f"{payload.get('count', len(listed))} key(s)")
        for item in listed:
            if not isinstance(item, dict):
                continue
            con.print(f"  {item.get('id')}  {item.get('name')}")
        return
    if payload.get("id") and "set" not in payload:
        con.print(f"revoked {payload.get('id')}")
        return
    if payload.get("set"):
        con.print("password is set")
        generated = payload.get("password")
        if generated:
            con.print(str(generated))
        return
    con.print("password is not set (login disabled)")


def _truncate(text: Any, limit: int = 36) -> str:
    raw = str(text or "")
    if limit <= 0:
        return ""
    if len(raw) <= limit:
        return raw
    if limit == 1:
        return "…"
    return raw[: limit - 1] + "…"


def _compress_ipv6(addr: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(addr) <= limit:
        return addr
    parts = addr.split(":")
    kept: List[str] = []
    for part in parts:
        trial = ":".join(kept + [part]) + ":…"
        if kept and len(trial) > limit:
            break
        kept.append(part)
    if not kept:
        return _truncate(addr, limit)
    out = ":".join(kept) + ":…"
    if len(out) > limit:
        return _truncate(addr, limit)
    return out


def _compress_check_name(name: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if len(name) <= limit:
        return name
    prefix, sep, addr = name.partition(" ")
    if not sep or ":" not in addr:
        return _truncate(name, limit)
    addr_limit = limit - len(prefix) - 1
    if addr_limit < 3:
        return _truncate(name, limit)
    return f"{prefix} {_compress_ipv6(addr, addr_limit)}"


def _fit_validate_line(name: str, mark: str, detail: str, width: int) -> str:
    sep = f"  {mark}  "
    name = str(name or "")
    detail = " ".join(str(detail or "").split())
    width = max(8, int(width))

    def pack(n: str, d: str) -> str:
        return f"{n}{sep}{d}".rstrip()

    line = pack(name, detail)
    if len(line) <= width:
        return line
    name_budget = width - len(sep) - len(detail)
    if name_budget < len(name):
        name = _compress_check_name(name, max(8, name_budget))
    line = pack(name, detail)
    if len(line) <= width:
        return line
    remain = width - len(name) - len(sep)
    return pack(name, _truncate(detail, remain))


def _render_validate(payload: Any) -> None:
    if not isinstance(payload, dict):
        _render_pretty(payload)
        return
    con = _console()
    width = 80
    try:
        width = max(40, int(con.size.width or 80))
    except Exception:
        pass
    failed = payload.get("failed")
    warned = payload.get("warned")
    head = f"validate  failed {failed}  warned {warned}"
    style = "green" if payload.get("ok") else "red"
    con.print(Text(head, style=style), overflow="ignore", no_wrap=True)
    for row in payload.get("checks") or []:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "")
        mark = {"ok": "ok", "failed": "FAIL", "warn": "WARN", "warning": "WARN"}.get(status, status.upper() or "?")
        name = str(row.get("check") or row.get("id") or "")
        detail = str(row.get("detail") or row.get("message") or "")
        color = "green" if status == "ok" else ("yellow" if "warn" in status else "red")
        line = _fit_validate_line(name, mark, detail, width)
        con.print(Text(line, style=color), overflow="ignore", no_wrap=True)


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
    if not day_a and not week_a:
        step = payload.get("step")
        con.print(Text(f"logs stats: empty (step {step}s)" if step is not None else "logs stats: empty"))
        return
    _print_rows(con, [("step", payload.get("step"))])
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
