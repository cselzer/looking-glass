"""looking-glass HTTP: GET / looks up the TCP peer; GET /<token> auto-detects IP, ASN, or country; GET /dns/<name> and GET /dns/<name>/<type> query DNS; GET /reputation/<name> checks domain or IP blocklists; GET /apex/<domain> is zone and mail health; GET /register/<name> is a TLD chessboard; GET /dnssec/<domain> walks the DNSSEC chain; GET /tls/<host> inspects a certificate; GET /rdap/<token> is RDAP; GET /ping/<host>, /traceroute/<host>, /mtr/<host>, and /tcptraceroute/<host>/<port> are Python path probes; GET /status is hostname, IP, time, uptime, load, and ASGI/WSGI."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import struct
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, quote, unquote

from ..intel import asn_org, flags
from ..net.host import restore_collapsed_slashes
from ..intel_server.pipeline import classify_query
from ..dns.apex import check_apex, check_apex_async, parse_apex_path
from ..dns.register import check_register, check_register_async, parse_label, parse_register_path
from ..dns.dnssec import check_dnssec, check_dnssec_async, parse_dnssec_path
from ..dns.resolve import (
    canonicalize_qtype,
    lookup_dns,
    lookup_dns_async,
    normalize_qname,
    parse_dns_path,
    parse_nameserver,
)
from ..intel.bgp import check_bgp, check_bgp_async, parse_bgp_path
from ..intel.rdap import _is_rdap_domain, lookup_rdap, lookup_rdap_async, parse_rdap_path
from ..intel.whois import lookup_whois, lookup_whois_async, parse_whois_path
from ..dns.ptr import check_ptr, check_ptr_async, parse_ptr_path
from ..dns.trace import trace_dns, trace_dns_async, parse_dnstrace_path
from ..net.httpinspect import (
    http_envelope_query,
    inspect_http,
    inspect_http_async,
    parse_http_path,
)
from ..net.mail import check_mail, check_mail_async, parse_mail_path
from ..net.pmtu import check_pmtu, check_pmtu_async, parse_pmtu_path
from ..net.tcpcheck import check_tcp, check_tcp_async, parse_tcp_path
from .cli_text import curl_line, httpie_line, wall_cli
from ..net.probe import parse_mtr_query_cycles, parse_probe_path, parse_tcp_trace_path, run_probe, run_probe_async
from ..net.tls import inspect_tls, inspect_tls_async, parse_tls_path
from . import render
from . import admin as http_admin
from .security import attach as attach_security, csp_nonce

SITE = "looking-glass"
_JSON = "application/json"
_HTML = "text/html; charset=utf-8"
_JS = "application/javascript; charset=utf-8"
ExtraHeaders = List[Tuple[str, str]]
HttpOut = Tuple[int, str, bytes, ExtraHeaders]
_COMMON_QTYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "PTR",
    "SRV",
    "CAA",
    "HTTPS",
    "SVCB",
    "DNSKEY",
    "DS",
    "TLSA",
    "NAPTR",
    "URI",
    "SSHFP",
)
_FALLBACK_QTYPES = (
    {"name": "A", "value": 1, "meaning": "a host address"},
    {"name": "NS", "value": 2, "meaning": "an authoritative name server"},
    {"name": "CNAME", "value": 5, "meaning": "the canonical name for an alias"},
    {"name": "SOA", "value": 6, "meaning": "marks the start of a zone of authority"},
    {"name": "PTR", "value": 12, "meaning": "a domain name pointer"},
    {"name": "MX", "value": 15, "meaning": "mail exchange"},
    {"name": "TXT", "value": 16, "meaning": "text strings"},
    {"name": "AAAA", "value": 28, "meaning": "IP6 Address"},
    {"name": "SRV", "value": 33, "meaning": "Server Selection"},
    {"name": "NAPTR", "value": 35, "meaning": "Naming Authority Pointer"},
    {"name": "SVCB", "value": 64, "meaning": "Service Binding"},
    {"name": "HTTPS", "value": 65, "meaning": "HTTPS Binding"},
    {"name": "DS", "value": 43, "meaning": "Delegation Signer"},
    {"name": "SSHFP", "value": 44, "meaning": "SSH Key Fingerprint"},
    {"name": "DNSKEY", "value": 48, "meaning": "DNSKEY"},
    {"name": "TLSA", "value": 52, "meaning": "TLSA"},
    {"name": "URI", "value": 256, "meaning": "URI"},
    {"name": "CAA", "value": 257, "meaning": "Certification Authority Restriction"},
)


def dns_type_choices() -> List[Dict[str, Any]]:
    """IANA lookup types for the GUI select. Common names first; meta-types omitted."""
    from ..dns.resolve import types

    try:
        rows = types(lookup_only=True)
    except Exception:
        rows = []
    if not rows:
        rows = [dict(row) for row in _FALLBACK_QTYPES]
    by_name = {str(row.get("name") or ""): row for row in rows}
    ordered: List[Dict[str, Any]] = []
    seen = set()
    for name in _COMMON_QTYPES:
        row = by_name.get(name)
        if not row:
            continue
        ordered.append({**row, "common": True})
        seen.add(name)
    rest = sorted(
        (row for row in rows if str(row.get("name") or "") not in seen),
        key=lambda row: str(row.get("name") or ""),
    )
    for row in rest:
        ordered.append({**row, "common": False})
    return ordered


def _out(status: int, ctype: str, body: bytes, headers: Optional[ExtraHeaders] = None) -> HttpOut:
    return int(status), str(ctype), body, list(headers or [])


def _from3(result: Tuple[int, str, bytes], headers: Optional[ExtraHeaders] = None) -> HttpOut:
    return _out(result[0], result[1], result[2], headers)


_PUBLIC_METHODS = frozenset({"GET", "HEAD", "POST"})


def _method_not_allowed() -> HttpOut:
    return _out(
        405,
        _JSON,
        json.dumps({"ok": False, "error": "method not allowed"}).encode("utf-8"),
        [("Allow", "GET, HEAD, POST")],
    )


def _serve_ui_i18n(method: str, token: str) -> HttpOut:
    """UI string map from disk catalogs. Not Click help, not inlined in HTML."""
    verb = (method or "GET").upper()
    if verb not in ("GET", "HEAD"):
        return _out(405, _JSON, json.dumps({"ok": False, "error": "use GET"}).encode("utf-8"))
    rest = token[5:] if token.startswith("i18n/") else ""
    if not rest or "/" in rest or ".." in rest:
        return _out(404, _JSON, json.dumps({"ok": False, "error": "not found"}).encode("utf-8"))
    if rest.endswith(".json"):
        lang, fmt = rest[:-5], "json"
    elif rest.endswith(".js"):
        lang, fmt = rest[:-3], "js"
    else:
        return _out(404, _JSON, json.dumps({"ok": False, "error": "not found"}).encode("utf-8"))
    from ..i18n import active_locale, available_locales, normalize_lang, set_locale, ui_messages_map

    lang = normalize_lang(lang)
    if lang not in set(available_locales()):
        return _out(404, _JSON, json.dumps({"ok": False, "error": "unknown locale"}).encode("utf-8"))
    prev = active_locale()
    set_locale(lang)
    try:
        messages = ui_messages_map("index")
    finally:
        set_locale(prev)
    extra: ExtraHeaders = [("Cache-Control", "public, max-age=300")]
    if fmt == "json":
        payload = json.dumps({"locale": lang, "messages": messages}, ensure_ascii=False)
        body = payload.encode("utf-8") if verb == "GET" else b""
        return _out(200, _JSON + "; charset=utf-8", body, extra)
    script = "window.__i18n = " + json.dumps(messages, ensure_ascii=False) + ";\n"
    body = script.encode("utf-8") if verb == "GET" else b""
    return _out(200, _JS, body, extra)


def _maybe_history_html(
    handled: HttpOut,
    *,
    html: bool,
    token: str,
    path: str,
    host: Optional[str],
    scheme: Optional[str],
    user: Optional[str],
    csp_nonce_value: str = "",
) -> Optional[HttpOut]:
    if not html or not token.startswith("history/") or token == "history":
        return None
    status, _ctype, raw, _extra = handled
    if int(status) != 200:
        return None
    try:
        blob = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None
    stored = blob.get("payload") if isinstance(blob, dict) else None
    if not isinstance(stored, dict):
        return None
    return _from3(
        _encode(
            200,
            stored,
            html=True,
            path=path or ("/" + token),
            host=host,
            scheme=scheme,
            user=user,
            csp_nonce_value=csp_nonce_value,
        )
    )


def _log_lookup(user: Optional[str], path: str, payload: Dict[str, Any], origin_url: str = "") -> None:
    if not isinstance(payload, dict):
        return
    kind = str(payload.get("kind") or "")
    try:
        from ..auth import history as action_history

        ident = action_history.append(
            user or "",
            path=path or "/",
            kind=kind,
            query=str(payload.get("query") or ""),
            payload=payload,
            visitor=str(payload.get("visitor") or ""),
        )
        if ident and origin_url:
            rel = str(payload.get("history") or f"/history/{ident}")
            if not rel.startswith("/"):
                rel = "/" + rel
            payload["history"] = f"{origin_url.rstrip('/')}{rel}"
    except OSError:
        return


def path_token(path: str) -> str:
    text = restore_collapsed_slashes(unquote(str(path or ""))).strip()
    if text.startswith("/"):
        text = text[1:]
    return text.rstrip("/")


def _is_root_path(path: str) -> bool:
    return unquote(str(path or "")) in ("", "/")


def _intel_token(path: str) -> str:
    """Path token for classify_query: no strip, no trailing-slash collapse."""
    text = restore_collapsed_slashes(unquote(str(path or "")))
    if text.startswith("/"):
        text = text[1:]
    return text


def _intel_client_error(query: str) -> bool:
    from ..net.host import parse_asn_number, unbracket_host

    raw = str(query or "")
    if raw != raw.strip() or raw.endswith("/"):
        return True
    text = unbracket_host(raw).strip()
    if "%" in text:
        return True
    token = text.upper()
    if token.startswith("AS"):
        return True
    if not token.isdigit():
        return False
    try:
        parse_asn_number(text)
    except ValueError:
        return True
    return False


def _status_hostname() -> str:
    from ..observe import hostname

    return hostname()


def _status_addrs() -> Dict[str, Optional[str]]:
    from ..observe import egress_addrs

    return egress_addrs()


def _usable_status_ip(ip: str, *, allow_link_local: bool) -> bool:
    from ..observe import _usable_ip

    return _usable_ip(ip, allow_link_local=allow_link_local)


def _status_ip() -> Optional[str]:
    addrs = _status_addrs()
    return addrs.get("ipv4") or addrs.get("ipv6")


def _status_uptime() -> Optional[float]:
    try:
        with open("/proc/uptime", encoding="ascii") as fh:
            return float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    try:
        import ctypes
        import ctypes.util

        lib = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
        lib.sysctlbyname.argtypes = [
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        lib.sysctlbyname.restype = ctypes.c_int
        buf = ctypes.create_string_buffer(16)
        size = ctypes.c_size_t(16)
        if lib.sysctlbyname(b"kern.boottime", buf, ctypes.byref(size), None, 0) != 0:
            return None
        boot = struct.unpack_from("@l", buf.raw)[0]
    except (AttributeError, OSError, struct.error, ValueError):
        return None
    if boot <= 0:
        return None
    return max(0.0, time.time() - float(boot))


def _status_clock(now: Optional[datetime] = None) -> Dict[str, Any]:
    current = now or datetime.now().astimezone()
    if current.tzinfo is None:
        current = current.astimezone()
    offset = current.utcoffset()
    utc_offset = int(offset.total_seconds()) if offset is not None else 0
    tz = (current.tzname() or "").strip()
    if not tz or " " in tz or len(tz) > 5:
        tz = current.strftime("%z") or "UTC"
    return {
        "time_epoch": current.timestamp(),
        "utc_offset": utc_offset,
        "tz": tz,
    }


def _status_http(protocol: str, user: Optional[str] = None) -> Tuple[int, str, bytes]:
    try:
        load = [round(float(n), 2) for n in os.getloadavg()]
    except (AttributeError, OSError):
        load = None
    addrs = _status_addrs()
    ipv4 = addrs.get("ipv4")
    ipv6 = addrs.get("ipv6")
    payload: Dict[str, Any] = {
        "hostname": _status_hostname(),
        "ip": ipv4 or ipv6,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "uptime": _status_uptime(),
        "load": load,
        "mode": "asgi" if str(protocol or "").lower() == "asgi" else "wsgi",
        "user": user,
        **_status_clock(),
    }
    from ..config import docs_enabled, docs_generated

    payload["docs"] = {"enabled": docs_enabled(), "generated": docs_generated()}
    if user:
        from ..intel_server import app as lookup_mod

        st = lookup_mod.status()
        payload["serve"] = {
            "running": bool(st.get("running")),
            "ready": bool(st.get("ready")),
        }
        if payload["serve"]["running"] and st.get("uptime") is not None:
            payload["serve"]["uptime"] = float(st["uptime"])
        from ..http import https_serve

        try:
            hs = https_serve.status()
        except Exception:
            hs = {"running": False}
        payload["https"] = {"running": bool(hs.get("running"))}
        if payload["https"]["running"]:
            if hs.get("uptime") is not None:
                payload["https"]["uptime"] = float(hs["uptime"])
            if hs.get("port") is not None:
                try:
                    payload["https"]["port"] = int(hs["port"])
                except (TypeError, ValueError):
                    pass
    return 200, _JSON, json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _bind_html_locale(
    html: bool,
    accept_language: Optional[str] = None,
    cookie: Optional[str] = None,
) -> None:
    from ..i18n import resolve_locale, set_locale

    if not html:
        set_locale(resolve_locale(html=False))
        return
    set_locale(resolve_locale(accept_language=accept_language, cookie=cookie, html=True))


def _docs_http(user: Optional[str] = None) -> Tuple[int, str, bytes]:
    from ..config import docs_enabled
    from ..docs.generate import default_docs_path, inject_live_status_bar
    from ..i18n import active_locale, t

    if not docs_enabled():
        body = (
            f"<!DOCTYPE html><html lang=\"{active_locale()}\"><head><meta charset=\"utf-8\">"
            f"<title>404</title></head><body>"
            f"<p>Not found.</p>"
            f"<p><a href=\"/\">{t('status.exit')}</a></p>"
            "</body></html>"
        )
        return 404, _HTML, inject_live_status_bar(body, user).encode("utf-8")

    path = default_docs_path()
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        text = inject_live_status_bar(text, user)
        return 200, _HTML, text.encode("utf-8")
    except OSError:
        from ..docs.generate import _CSS

        cmd = "<code>looking-glass docs</code>"
        body = (
            f"<!DOCTYPE html><html lang=\"{active_locale()}\"><head><meta charset=\"utf-8\">"
            f"<title>docs</title><style>{_CSS}</style></head><body class=\"docs-page\">"
            f"<p>{t('docs.missing', cmd=cmd)}</p>"
            f"<p><a href=\"/\">{t('status.exit')}</a> {t('docs.missing_exit')}</p>"
            "</body></html>"
        )
        return 404, _HTML, inject_live_status_bar(body, user).encode("utf-8")


def parse_reputation_path(path: str) -> str:
    """Parse /reputation/<name> into a domain or IP."""
    text = unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "reputation" and not text.startswith("reputation/"):
        raise ValueError("not a reputation path")
    rest = "" if text == "reputation" else text[len("reputation/") :]
    if not rest or "/" in rest:
        raise ValueError("reputation path needs a name, e.g. /reputation/example.com")
    return rest


def parse_apex_http_path(path: str) -> str:
    """Parse /apex/<domain>; IPs are not zone apexes."""
    name = parse_apex_path(path)
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("apex path needs a domain, e.g. /apex/example.com")


def parse_register_http_path(path: str) -> str:
    """Parse /register/<label>; IPs are not names."""
    return parse_label(parse_register_path(path))


def _register_query_tlds(query_string: str) -> List[str]:
    """Parse ?tlds=com,net. Reject any other query key."""
    qs = parse_qs(query_string or "", keep_blank_values=False)
    unknown = [key for key in qs if key != "tlds"]
    if unknown:
        raise ValueError(f"unknown query key {unknown[0]!r}")
    raw = ((qs.get("tlds") or [""])[0] or "").strip()
    if not raw:
        return []
    return [part.strip().lower().lstrip(".") for part in raw.split(",") if part.strip()]


def parse_dnssec_http_path(path: str) -> str:
    name = parse_dnssec_path(path)
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("dnssec path needs a domain, e.g. /dnssec/example.com")


def _bad_query(kind: str, token: str) -> str:
    """Envelope query on parse failure: the name, not `dns/not a domain`."""
    text = restore_collapsed_slashes(unquote(str(token or "")))
    prefix = f"{kind}/"
    if text.startswith(prefix):
        return text[len(prefix) :]
    return text


def _http_submitted_query(token: str, parsed: str, query_string: str) -> str:
    """Envelope query on HTTP 400: the submitted URL, not the tool name or leftover %2F."""
    qs = parse_qs(query_string or "", keep_blank_values=False)
    url_param = ((qs.get("url") or [""])[0]).strip()
    if url_param:
        return restore_collapsed_slashes(unquote(url_param))
    rest = restore_collapsed_slashes(unquote(str(parsed or "").strip()))
    if rest:
        return rest
    stripped = _bad_query("http", token)
    if stripped and stripped != "http":
        return stripped
    return rest


def parse_tls_http_path(path: str) -> Tuple[str, int]:
    from ..net.host import unbracket_host

    host, port = parse_tls_path(path)
    host = unbracket_host(host)
    try:
        return str(ipaddress.ip_address(host)), port
    except ValueError:
        return normalize_qname(host, qtype="A").rstrip("."), port


def parse_mail_http_path(path: str) -> str:
    name = parse_mail_path(path)
    return normalize_qname(name, qtype="MX").rstrip(".")


def _kind_plan(
    protocol: str,
    visitor: Optional[str],
    token: str,
    kind: str,
    parse,
    query_string: str = "",
) -> Tuple[Optional[Tuple[int, str, bytes]], Optional[str], Optional[str], Dict[str, Any]]:
    """Parse a /<kind>/... path into (error, kind, value, base)."""
    base: Dict[str, Any] = {"protocol": protocol, "visitor": visitor, "query": token}
    try:
        parsed = parse("/" + token)
    except ValueError as e:
        return (
            _error_body(
                400,
                _envelope(
                    ok=False,
                    protocol=protocol,
                    kind=kind,
                    visitor=visitor,
                    query=_bad_query(kind, token),
                    error=str(e),
                    include_result=False,
                ),
            ),
            None,
            None,
            base,
        )
    value: Any = parsed
    if isinstance(parsed, tuple):
        if kind == "dnstrace":
            value, qtype = parsed
            base["qtype"] = qtype
        elif kind == "tcp":
            value, port = parsed
            base["port"] = int(port)
    if kind == "whois":
        raw = ((parse_qs(query_string or "", keep_blank_values=False).get("legacy") or [""])[0]).lower()
        if raw in {"1", "true", "yes", "legacy", "whois"}:
            base["legacy"] = True
    if kind == "http":
        parsed_rest = str(value)
        try:
            value = http_envelope_query(parsed_rest, query_string)
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind=kind,
                        visitor=visitor,
                        query=_http_submitted_query(token, parsed_rest, query_string),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
    base["query"] = value
    return None, kind, str(value), base


def parse_tcp_trace_http_path(path: str) -> Tuple[str, int]:
    from ..net.host import unbracket_host

    host, port = parse_tcp_trace_path(path)
    host = unbracket_host(host)
    try:
        return str(ipaddress.ip_address(host)), port
    except ValueError:
        return normalize_qname(host, qtype="A").rstrip("."), port


def parse_probe_http_path(path: str) -> Tuple[str, str]:
    """Parse /ping|/traceroute|/mtr/<host> into (kind, host)."""
    from ..net.host import unbracket_host

    kind, target = parse_probe_path(path)
    target = unbracket_host(target)
    try:
        return kind, str(ipaddress.ip_address(target))
    except ValueError:
        return kind, normalize_qname(target, qtype="A").rstrip(".")


def wants_html(accept: Optional[str]) -> bool:
    """Browsers sending text/html get HTML; curl's */* stays JSON."""
    html_q: Optional[float] = None
    json_q: Optional[float] = None
    for part in (accept or "").split(","):
        media, *params = [p.strip().lower() for p in part.split(";")]
        q = 1.0
        for param in params:
            if param.startswith("q="):
                try:
                    q = float(param[2:])
                except ValueError:
                    q = 0.0
        if media == "text/html" and html_q is None:
            html_q = q
        elif media == "application/json" and json_q is None:
            json_q = q
    if html_q is None or html_q <= 0:
        return False
    if json_q is None:
        return True
    return html_q >= json_q


def origin(host: Optional[str], scheme: Optional[str]) -> str:
    host = (host or "").split(",")[0].strip() or SITE
    scheme = (scheme or "").split(",")[0].strip().lower()
    if scheme not in {"http", "https"}:
        scheme = "http"
    return f"{scheme}://{host}"


def display_site(host: Optional[str]) -> str:
    """Header/footer brand: the request Host, falling back to SITE."""
    return (host or "").split(",")[0].strip() or SITE


def _with_via(payload: Dict[str, Any], via: str) -> Dict[str, Any]:
    out = dict(payload)
    out.setdefault("via", via)
    return out


def _running_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def _daemon_unavailable(value: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "ip": value,
        "result": None,
        "via": None,
        "error": "intel server unavailable",
    }


def _rbl_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    if not raw.get("ok"):
        return {
            "ok": False,
            "result": None,
            "fetched_at": raw.get("fetched_at"),
            "error": raw.get("error") or "reputation lookup failed",
        }
    result: Dict[str, Any] = {
        "status": raw.get("status"),
        "listed": raw.get("listed"),
        "listed_on": raw.get("listed_on") or [],
        "flags": raw.get("flags") or [],
        "txt": raw.get("txt") or [],
        "errors": raw.get("errors") or 0,
        "cached": raw.get("cached"),
        "lists": raw.get("result") or {},
    }
    if raw.get("ip"):
        result["ip"] = raw["ip"]
    if raw.get("domain"):
        result["domain"] = raw["domain"]
    if raw.get("resolver") is not None:
        result["resolver"] = raw["resolver"]
    if "sender_score" in raw:
        result["sender_score"] = raw.get("sender_score")
    return {
        "ok": True,
        "result": result,
        "fetched_at": raw.get("fetched_at"),
        "error": None,
    }


def lookup_classified(
    kind: str,
    value: str,
    qtype: Optional[str] = None,
    *,
    port: Optional[int] = None,
    sni: Optional[str] = None,
    server: Optional[str] = None,
    ns_port: Optional[int] = None,
    legacy: bool = False,
    timeout: Optional[float] = None,
    cycles: Any = None,
    tlds: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    if kind == "dns":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for DNS")
        kwargs: Dict[str, Any] = {}
        if server:
            kwargs["server"] = server
        if ns_port is not None:
            kwargs["port"] = ns_port
        if timeout is not None:
            kwargs["timeout"] = timeout
        return lookup_dns(value, qtype or "A", **kwargs)
    if kind == "reputation":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for reputation")
        return _rbl_payload(_reputation_sync(value))
    if kind == "apex":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for apex")
        return check_apex(value)
    if kind == "register":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for register")
        kwargs: Dict[str, Any] = {}
        if tlds:
            kwargs["tlds"] = list(tlds)
        return check_register(value, **kwargs)
    if kind in {"ping", "traceroute", "mtr"}:
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for path probes")
        if kind == "mtr":
            return run_probe(kind, value, cycles=cycles)
        return run_probe(kind, value)
    if kind == "tcptraceroute":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for path probes")
        return run_probe(kind, value, port=port or 443)
    if kind == "dnssec":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for dnssec")
        return check_dnssec(value)
    if kind == "tls":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for tls")
        return inspect_tls(value, port=port or 443, sni=sni)
    if kind == "rdap":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for rdap")
        return lookup_rdap(value)
    if kind == "bgp":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for bgp")
        return check_bgp(value)
    if kind == "dnstrace":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for dnstrace")
        return trace_dns(value, qtype or "A")
    if kind == "http":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for http")
        return inspect_http(value)
    if kind == "ptr":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for ptr")
        return check_ptr(value)
    if kind == "mail":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for mail")
        return check_mail(value)
    if kind == "tcp":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for tcp")
        return check_tcp(value, port=port or 443)
    if kind == "pmtu":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for pmtu")
        return check_pmtu(value)
    if kind == "whois":
        if _running_loop():
            raise RuntimeError("use lookup_classified_async for whois")
        return lookup_whois(value, legacy=bool(legacy))
    if kind == "ip":
        # Datasets live in the intel server. Never load RIR in this process.
        # asyncio.run() cannot run inside uvicorn's loop; ASGI uses
        # lookup_classified_async instead.
        if not _running_loop():
            from ..intel_server.client import lookup_json

            data = lookup_json(value)
            if data:
                return _with_via(data, "intel")
        return _daemon_unavailable(value)
    if kind == "country":
        if not _running_loop():
            from ..intel_server.client import lookup_json

            data = lookup_json(value, timeout=5.0)
            if data:
                return _with_via(data, "intel")
        info = flags.flag_info(value)
        fields = flags.lookup_fields(value)
        return {
            "ok": True,
            "country": value,
            "result": {
                "country": value,
                "country_name": info.name,
                **fields,
            },
            "error": None,
        }
    if kind == "asn":
        try:
            asn_i = int(str(value).strip().lstrip("ASas"))
        except ValueError:
            asn_i = None
        try:
            result = asn_org.find_org(value)
            fetched_at = int(asn_org.get_fetched_at() or 0)
        except Exception as e:
            return {
                "ok": False,
                "asn": value,
                "result": None,
                "fetched_at": None,
                "error": str(e),
            }
        if result is None:
            result = {"asn": asn_i or value, "name": None}
        try:
            from ..intel.rdap import rdap_for_asn

            rdap = rdap_for_asn(result.get("asn") or value)
            if rdap:
                result = dict(result)
                result["rdap"] = rdap
        except Exception:
            pass
        return {
            "ok": True,
            "asn": value,
            "result": result,
            "fetched_at": fetched_at,
            "error": None,
        }
    raise ValueError(f"unknown lookup kind {kind!r}")


def _reputation_sync(value: str) -> Dict[str, Any]:
    from ..dns.reputation import check_domain, check_rbls

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return check_domain(value)
    return check_rbls(value)


async def _reputation_async(value: str) -> Dict[str, Any]:
    from ..dns.reputation import check_domain_cached_async, check_rbl_cached_async

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return await check_domain_cached_async(value)
    return await check_rbl_cached_async(value)


async def lookup_classified_async(
    kind: str,
    value: str,
    qtype: Optional[str] = None,
    *,
    port: Optional[int] = None,
    sni: Optional[str] = None,
    server: Optional[str] = None,
    ns_port: Optional[int] = None,
    legacy: bool = False,
    timeout: Optional[float] = None,
    cycles: Any = None,
    tlds: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    if kind == "dns":
        kwargs: Dict[str, Any] = {}
        if server:
            kwargs["server"] = server
        if ns_port is not None:
            kwargs["port"] = ns_port
        if timeout is not None:
            kwargs["timeout"] = timeout
        return await lookup_dns_async(value, qtype or "A", **kwargs)
    if kind == "reputation":
        return _rbl_payload(await _reputation_async(value))
    if kind == "apex":
        return await check_apex_async(value)
    if kind == "register":
        kwargs = {}
        if tlds:
            kwargs["tlds"] = list(tlds)
        return await check_register_async(value, **kwargs)
    if kind == "dnssec":
        return await check_dnssec_async(value)
    if kind == "tls":
        return await inspect_tls_async(value, port=port or 443, sni=sni)
    if kind == "rdap":
        return await lookup_rdap_async(value)
    if kind == "bgp":
        return await check_bgp_async(value)
    if kind == "dnstrace":
        return await trace_dns_async(value, qtype or "A")
    if kind == "http":
        return await inspect_http_async(value)
    if kind == "ptr":
        return await check_ptr_async(value)
    if kind == "mail":
        return await check_mail_async(value)
    if kind == "tcp":
        return await check_tcp_async(value, port=port or 443)
    if kind == "pmtu":
        return await check_pmtu_async(value)
    if kind == "whois":
        return await lookup_whois_async(value, legacy=bool(legacy))
    if kind in {"ping", "traceroute", "mtr"}:
        if kind == "mtr":
            return await run_probe_async(kind, value, cycles=cycles)
        return await run_probe_async(kind, value)
    if kind == "tcptraceroute":
        return await run_probe_async(kind, value, port=port or 443)
    if kind in ("ip", "country"):
        from ..intel_server.client import lookup_json_async

        data = await lookup_json_async(value, timeout=5.0 if kind == "country" else 0.5)
        if data:
            return _with_via(data, "intel")
        if kind == "ip":
            return _daemon_unavailable(value)
    return lookup_classified(
        kind,
        value,
        qtype=qtype,
        port=port,
        sni=sni,
        server=server,
        ns_port=ns_port,
        legacy=legacy,
        timeout=timeout,
        cycles=cycles,
    )


def _envelope(
    *,
    ok: bool,
    protocol: Optional[str] = None,
    kind: Optional[str] = None,
    visitor: Optional[str] = None,
    query: Optional[str] = None,
    result: Any = None,
    extra: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    include_result: bool = True,
) -> Dict[str, Any]:
    """Stable key order: query immediately above result."""
    out: Dict[str, Any] = {"ok": ok}
    if protocol is not None:
        out["protocol"] = protocol
    if kind is not None:
        out["kind"] = kind
    out["visitor"] = visitor
    out["query"] = query
    if include_result:
        out["result"] = result
    extra = extra or {}
    for key in (
        "via",
        "timings",
        "errors",
        "total_ms",
        "fetched_at",
        "qtype",
        "url",
        "http_status",
        "retry_after",
    ):
        if key in extra:
            out[key] = extra[key]
    if error is not None:
        out["error"] = error
    from ..observe import attach_observation

    attach_observation(out)
    return out


def _dns_upstream(query_string: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse ?server=1.1.1.1&port=5353 for DNS lookups."""
    qs = parse_qs(query_string or "", keep_blank_values=False)
    raw_server = (qs.get("server") or [None])[0]
    raw_port = (qs.get("port") or [None])[0]
    if raw_server is None and raw_port is None:
        return None, None
    port = None
    if raw_port not in (None, ""):
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            raise ValueError("nameserver port must be 1–65535") from None
    host, ns_port = parse_nameserver(raw_server, port)
    return host, ns_port


def _lookup_kwargs(base: Dict[str, Any]) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {"qtype": base.get("qtype")}
    if base.get("port") is not None:
        kwargs["port"] = base["port"]
    if base.get("sni"):
        kwargs["sni"] = base["sni"]
    if base.get("server"):
        kwargs["server"] = base["server"]
    if base.get("ns_port") is not None:
        kwargs["ns_port"] = base["ns_port"]
    if base.get("legacy"):
        kwargs["legacy"] = True
    if "cycles" in base:
        kwargs["cycles"] = base["cycles"]
    if base.get("tlds"):
        kwargs["tlds"] = base["tlds"]
    return kwargs


def _plan(
    protocol: str,
    visitor: Optional[str],
    path: str,
    wall_hdrs: Dict[str, str],
    query_string: str = "",
) -> Tuple[Optional[Tuple[int, str, bytes]], Optional[str], Optional[str], Dict[str, Any]]:
    token = path_token(path)
    if token == "dns" or token.startswith("dns/"):
        base: Dict[str, Any] = {
            "protocol": protocol,
            "visitor": visitor,
            "query": token,
        }
        try:
            name, qtype = parse_dns_path("/" + token)
            canonicalize_qtype(qtype)
            normalize_qname(name, qtype=qtype)
            server, ns_port = _dns_upstream(query_string)
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind="dns",
                        visitor=visitor,
                        query=_bad_query("dns", token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
        base["query"] = name
        base["qtype"] = qtype
        if server:
            base["server"] = server
        if ns_port is not None and (server or "port=" in (query_string or "")):
            base["ns_port"] = ns_port
        return None, "dns", name, base
    if token == "reputation" or token.startswith("reputation/"):
        base = {
            "protocol": protocol,
            "visitor": visitor,
            "query": token,
        }
        try:
            name = parse_reputation_path("/" + token)
            try:
                from ..net.host import unbracket_host

                value = str(ipaddress.ip_address(unbracket_host(name)))
            except ValueError:
                if not _is_rdap_domain(name):
                    raise ValueError(
                        "reputation path needs a domain or IP, e.g. /reputation/example.com"
                    )
                value = normalize_qname(name, qtype="A").rstrip(".")
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind="reputation",
                        visitor=visitor,
                        query=_bad_query("reputation", token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
        base["query"] = value
        return None, "reputation", value, base
    if token == "apex" or token.startswith("apex/"):
        base = {
            "protocol": protocol,
            "visitor": visitor,
            "query": token,
        }
        try:
            name = parse_apex_http_path("/" + token)
            value = normalize_qname(name, qtype="A").rstrip(".")
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind="apex",
                        visitor=visitor,
                        query=_bad_query("apex", token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
        base["query"] = value
        return None, "apex", value, base
    if token == "register" or token.startswith("register/"):
        try:
            tlds = _register_query_tlds(query_string)
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind="register",
                        visitor=visitor,
                        query=_bad_query("register", token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                {"protocol": protocol, "visitor": visitor, "query": token},
            )
        err, kind, value, base = _kind_plan(
            protocol, visitor, token, "register", parse_register_http_path, query_string
        )
        if err is None and tlds:
            base["tlds"] = tlds
        return err, kind, value, base
    if token == "dnssec" or token.startswith("dnssec/"):
        base = {"protocol": protocol, "visitor": visitor, "query": token}
        try:
            name = parse_dnssec_http_path("/" + token)
            value = normalize_qname(name, qtype="A").rstrip(".")
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind="dnssec",
                        visitor=visitor,
                        query=_bad_query("dnssec", token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
        base["query"] = value
        return None, "dnssec", value, base
    if token == "tls" or token.startswith("tls/"):
        base = {"protocol": protocol, "visitor": visitor, "query": token}
        try:
            value, port = parse_tls_http_path("/" + token)
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind="tls",
                        visitor=visitor,
                        query=_bad_query("tls", token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
        base["query"] = value
        base["port"] = port
        sni = ((parse_qs(query_string or "", keep_blank_values=False).get("sni") or [""])[0]).strip()
        if sni:
            base["sni"] = sni
        return None, "tls", value, base
    if token == "rdap" or token.startswith("rdap/"):
        base = {"protocol": protocol, "visitor": visitor, "query": token}
        try:
            value = parse_rdap_path("/" + token)
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind="rdap",
                        visitor=visitor,
                        query=_bad_query("rdap", token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
        base["query"] = value
        return None, "rdap", value, base
    if token == "whois" or token.startswith("whois/"):
        return _kind_plan(protocol, visitor, token, "whois", parse_whois_path, query_string)
    if token == "bgp" or token.startswith("bgp/"):
        return _kind_plan(protocol, visitor, token, "bgp", parse_bgp_path, query_string)
    if token == "dnstrace" or token.startswith("dnstrace/"):
        return _kind_plan(protocol, visitor, token, "dnstrace", parse_dnstrace_path, query_string)
    if token == "http" or token.startswith("http/"):
        return _kind_plan(protocol, visitor, token, "http", parse_http_path, query_string)
    if token == "ptr" or token.startswith("ptr/"):
        return _kind_plan(protocol, visitor, token, "ptr", parse_ptr_path, query_string)
    if token == "mail" or token.startswith("mail/"):
        return _kind_plan(protocol, visitor, token, "mail", parse_mail_http_path, query_string)
    if token == "tcp" or token.startswith("tcp/"):
        return _kind_plan(protocol, visitor, token, "tcp", parse_tcp_path, query_string)
    if token == "pmtu" or token.startswith("pmtu/"):
        return _kind_plan(protocol, visitor, token, "pmtu", parse_pmtu_path, query_string)
    if token == "tcptraceroute" or token.startswith("tcptraceroute/"):
        base = {"protocol": protocol, "visitor": visitor, "query": token}
        try:
            value, port = parse_tcp_trace_http_path(path)
        except ValueError as e:
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind="tcptraceroute",
                        visitor=visitor,
                        query=_bad_query("tcptraceroute", token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
        base["query"] = value
        base["port"] = port
        return None, "tcptraceroute", value, base
    if token.split("/", 1)[0] in {"ping", "traceroute", "mtr"}:
        base = {
            "protocol": protocol,
            "visitor": visitor,
            "query": token,
        }
        try:
            kind, value = parse_probe_http_path("/" + token)
        except ValueError as e:
            tool = token.split("/", 1)[0]
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        kind=tool if tool in {"ping", "traceroute", "mtr"} else None,
                        visitor=visitor,
                        query=_bad_query(tool, token),
                        error=str(e),
                        include_result=False,
                    ),
                ),
                None,
                None,
                base,
            )
        base["query"] = value
        if kind == "mtr":
            raw = ((parse_qs(query_string or "", keep_blank_values=True).get("cycles") or [None])[0])
            if raw is not None:
                try:
                    base["cycles"] = parse_mtr_query_cycles(raw)
                except ValueError as e:
                    return (
                        _error_body(
                            400,
                            _envelope(
                                ok=False,
                                protocol=protocol,
                                kind="mtr",
                                visitor=visitor,
                                query=value,
                                error=str(e),
                                include_result=False,
                            ),
                        ),
                        None,
                        None,
                        base,
                    )
        return None, kind, value, base
    if not token:
        if not _is_root_path(path):
            intel = _intel_token(path)
            return (
                _error_body(
                    400,
                    _envelope(
                        ok=False,
                        protocol=protocol,
                        visitor=visitor,
                        query=intel,
                        error="not an IP address, ASN, or country code",
                        include_result=False,
                    ),
                ),
                None,
                None,
                {"protocol": protocol, "visitor": visitor, "query": intel},
            )
        query = visitor
    else:
        query = _intel_token(path)
    base = {
        "protocol": protocol,
        "visitor": visitor,
        "query": query,
    }
    if not query:
        return (
            _error_body(
                400,
                _envelope(
                    ok=False,
                    protocol=protocol,
                    visitor=visitor,
                    query=query,
                    error="no client ip",
                    include_result=False,
                ),
            ),
            None,
            None,
            base,
        )
    try:
        kind, value = classify_query(query)
    except ValueError as e:
        status = 400 if _intel_client_error(query) else 404
        return (
            _error_body(
                status,
                _envelope(
                    ok=False,
                    protocol=protocol,
                    kind=None,
                    visitor=visitor,
                    query=query,
                    error=str(e),
                    include_result=False,
                ),
            ),
            None,
            None,
            base,
        )
    return None, kind, value, base


def _finish(
    payload: Dict[str, Any], kind: str, value: str, base: Dict[str, Any]
) -> Tuple[int, Dict[str, Any]]:
    extra = {
        key: payload[key]
        for key in (
            "via",
            "timings",
            "errors",
            "total_ms",
            "fetched_at",
            "qtype",
            "url",
            "http_status",
            "retry_after",
        )
        if key in payload
    }
    body = _envelope(
        ok=bool(payload.get("ok")),
        protocol=base.get("protocol"),
        kind=kind,
        visitor=base.get("visitor"),
        query=value,
        result=payload.get("result"),
        extra=extra,
        error=None if payload.get("ok") else payload.get("error"),
        include_result=payload.get("error") != "link-local is not a probe target",
    )
    status = 200
    if payload.get("error") == "intel server unavailable":
        status = 503
    elif payload.get("error") == "link-local is not a probe target":
        status = 400
    elif kind == "rdap" and not payload.get("ok"):
        try:
            status = int(payload.get("status") or 502)
        except (TypeError, ValueError):
            status = 502
        if status < 400:
            status = 502
    return status, body


def _cli_blocks(origin_url: str, path: str) -> Tuple[str, str, str]:
    return curl_line(origin_url, path), httpie_line(origin_url, path), wall_cli(path)


def _encode_index(
    visitor: Optional[str],
    host: Optional[str],
    scheme: Optional[str],
    user: Optional[str] = None,
    csp_nonce_value: str = "",
) -> Tuple[int, str, bytes]:
    origin_url = origin(host, scheme)
    try:
        from ..config import load as load_config

        mtr_cfg = dict(load_config().get("mtr") or {})
    except Exception:
        mtr_cfg = {"cycles": 10, "max_cycles": 30}
    text = render.render(
        "index.html",
        site=display_site(host),
        visitor=visitor,
        origin=origin_url,
        dns_types=dns_type_choices(),
        cache_gui=bool(user),
        user=user,
        mtr=mtr_cfg,
        csp_nonce=csp_nonce_value,
    )
    return 200, _HTML, text.encode("utf-8")


def _howto_path(path: str, payload: Dict[str, Any]) -> str:
    """Put full http URLs in ?url= so Apache never sees %2F in PATH.

    TLS/TCP howto uses the stripped host (and port) so collapsed `https:/`
    does not become `looking-glass tls https: -p example.com`.
    """
    kind = payload.get("kind")
    query = str(payload.get("query") or "").strip()
    if kind == "http" and query and "://" in query:
        return "/http?url=" + quote(query, safe="")
    if kind in {"tls", "tcp"} and query and "://" not in query:
        result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
        port = result.get("port") if result else None
        try:
            port_n = int(port) if port is not None else None
        except (TypeError, ValueError):
            port_n = None
        if kind == "tls":
            if port_n and port_n != 443:
                return f"/tls/{query}/{port_n}"
            return f"/tls/{query}"
        return f"/tcp/{query}/{port_n or 443}"
    return path or "/"


def _encode(
    status: int,
    payload: Dict[str, Any],
    *,
    html: bool,
    path: str,
    host: Optional[str],
    scheme: Optional[str],
    user: Optional[str] = None,
    not_found: bool = False,
    csp_nonce_value: str = "",
) -> Tuple[int, str, bytes]:
    if not html:
        return status, _JSON, json.dumps(payload, ensure_ascii=False).encode("utf-8")
    origin_url = origin(host, scheme)
    if not_found:
        text = render.render(
            "not_found.html",
            site=display_site(host),
            payload=payload,
            path=path or "/",
            origin=origin_url,
            user=user,
            csp_nonce=csp_nonce_value,
        )
        return status, _HTML, text.encode("utf-8")
    curl_block, httpie_block, url_block = _cli_blocks(origin_url, _howto_path(path, payload))
    template = "report.html" if payload.get("result") is not None else "result.html"
    text = render.render(
        template,
        site=display_site(host),
        payload=payload,
        path=path or "/",
        origin=origin_url,
        curl_block=curl_block,
        httpie_block=httpie_block,
        url_block=url_block,
        user=user,
        csp_nonce=csp_nonce_value,
    )
    return status, _HTML, text.encode("utf-8")


def _error_body(status: int, payload: Dict[str, Any]) -> Tuple[int, str, bytes]:
    """Placeholder; respond() re-encodes with Accept/host once those are known."""
    return status, _JSON, json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _audit_http(
    out: HttpOut,
    *,
    started: float,
    path: str,
    method: str,
    visitor: Optional[str],
    cookie: Optional[str],
    correlation_id: Optional[str] = None,
    authorization: Optional[str] = None,
) -> HttpOut:
    from . import weblog

    try:
        status, _ctype, body, _extra = out
        user = http_admin.current_user(cookie, authorization)
        err = None
        if int(status) >= 500:
            try:
                payload = json.loads(body.decode("utf-8"))
                if isinstance(payload, dict):
                    err = str(payload.get("error") or "") or None
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
                err = f"HTTP {status}"
        weblog.record_response(
            method=method,
            path=path,
            status=int(status),
            body=body,
            peer=visitor,
            user=user,
            ms=(time.perf_counter() - started) * 1000,
            error=err,
            correlation_id=correlation_id,
        )
    except OSError:
        pass
    return out


def _respond_impl(
    protocol: str,
    visitor: Optional[str],
    path: str,
    wall_hdrs: Dict[str, str],
    *,
    accept: Optional[str] = None,
    host: Optional[str] = None,
    scheme: Optional[str] = None,
    query_string: str = "",
    method: str = "GET",
    accept_language: Optional[str] = None,
    cookie: Optional[str] = None,
    body: bytes = b"",
    authorization: Optional[str] = None,
    csp_nonce_value: str = "",
) -> HttpOut:
    html = wants_html(accept)
    _bind_html_locale(html, accept_language, cookie)
    token = path_token(path)
    if token == "static" or token.startswith("static/"):
        from .static_files import serve as serve_static

        return serve_static(method, token)
    if token == "i18n" or token.startswith("i18n/"):
        return _serve_ui_i18n(method, token)
    user = http_admin.current_user(cookie, authorization)
    handled = http_admin.dispatch(
        method, token, cookie, body or b"", scheme, query_string, visitor, authorization
    )
    if handled is not None:
        html_out = _maybe_history_html(
            handled,
            html=html,
            token=token,
            path=path,
            host=host,
            scheme=scheme,
            user=user,
            csp_nonce_value=csp_nonce_value,
        )
        return html_out if html_out is not None else handled
    if (method or "GET").upper() not in _PUBLIC_METHODS:
        return _method_not_allowed()
    if token == "status":
        return _from3(_status_http(protocol, user))
    if token == "docs":
        return _from3(_docs_http(user), [("Cache-Control", "no-store")])
    if html and not token and _is_root_path(path):
        return _from3(_encode_index(visitor, host, scheme, user=user, csp_nonce_value=csp_nonce_value))
    err, kind, value, base = _plan(protocol, visitor, path, wall_hdrs, query_string)
    if err is not None:
        status, _ctype, raw = err
        payload = json.loads(raw.decode("utf-8"))
        return _from3(
            _encode(
                status,
                payload,
                html=html,
                path=path,
                host=host,
                scheme=scheme,
                user=user,
                not_found=int(status) == 404 and payload.get("kind") is None,
                csp_nonce_value=csp_nonce_value,
            )
        )
    try:
        payload = dict(lookup_classified(kind, value, **_lookup_kwargs(base)))
    except Exception as e:
        encoded = _encode(
            502,
            _envelope(
                ok=False,
                protocol=base.get("protocol"),
                kind=kind,
                visitor=base.get("visitor"),
                query=value,
                error=str(e),
                include_result=False,
            ),
            html=html,
            path=path,
            host=host,
            scheme=scheme,
            user=user,
            csp_nonce_value=csp_nonce_value,
        )
        return _from3(encoded)
    status, body_payload = _finish(payload, kind, value, base)
    _log_lookup(user, path, body_payload, origin(host, scheme))
    return _from3(
        _encode(
            status,
            body_payload,
            html=html,
            path=path,
            host=host,
            scheme=scheme,
            user=user,
            csp_nonce_value=csp_nonce_value,
        )
    )


async def _respond_async_impl(
    protocol: str,
    visitor: Optional[str],
    path: str,
    wall_hdrs: Dict[str, str],
    *,
    accept: Optional[str] = None,
    host: Optional[str] = None,
    scheme: Optional[str] = None,
    query_string: str = "",
    method: str = "GET",
    accept_language: Optional[str] = None,
    cookie: Optional[str] = None,
    body: bytes = b"",
    authorization: Optional[str] = None,
    csp_nonce_value: str = "",
) -> HttpOut:
    html = wants_html(accept)
    _bind_html_locale(html, accept_language, cookie)
    token = path_token(path)
    if token == "static" or token.startswith("static/"):
        from .static_files import serve as serve_static

        return serve_static(method, token)
    if token == "i18n" or token.startswith("i18n/"):
        return _serve_ui_i18n(method, token)
    user = http_admin.current_user(cookie, authorization)
    handled = http_admin.dispatch(
        method, token, cookie, body or b"", scheme, query_string, visitor, authorization
    )
    if handled is not None:
        html_out = _maybe_history_html(
            handled,
            html=html,
            token=token,
            path=path,
            host=host,
            scheme=scheme,
            user=user,
            csp_nonce_value=csp_nonce_value,
        )
        return html_out if html_out is not None else handled
    if (method or "GET").upper() not in _PUBLIC_METHODS:
        return _method_not_allowed()
    if token == "status":
        return _from3(_status_http(protocol, user))
    if token == "docs":
        return _from3(_docs_http(user), [("Cache-Control", "no-store")])
    if html and not token and _is_root_path(path):
        return _from3(_encode_index(visitor, host, scheme, user=user, csp_nonce_value=csp_nonce_value))
    err, kind, value, base = _plan(protocol, visitor, path, wall_hdrs, query_string)
    if err is not None:
        status, _ctype, raw = err
        payload = json.loads(raw.decode("utf-8"))
        return _from3(
            _encode(
                status,
                payload,
                html=html,
                path=path,
                host=host,
                scheme=scheme,
                user=user,
                not_found=int(status) == 404 and payload.get("kind") is None,
                csp_nonce_value=csp_nonce_value,
            )
        )
    try:
        payload = dict(await lookup_classified_async(kind, value, **_lookup_kwargs(base)))
    except Exception as e:
        encoded = _encode(
            502,
            _envelope(
                ok=False,
                protocol=base.get("protocol"),
                kind=kind,
                visitor=base.get("visitor"),
                query=value,
                error=str(e),
                include_result=False,
            ),
            html=html,
            path=path,
            host=host,
            scheme=scheme,
            user=user,
            csp_nonce_value=csp_nonce_value,
        )
        return _from3(encoded)
    status, body_payload = _finish(payload, kind, value, base)
    _log_lookup(user, path, body_payload, origin(host, scheme))
    return _from3(
        _encode(
            status,
            body_payload,
            html=html,
            path=path,
            host=host,
            scheme=scheme,
            user=user,
            csp_nonce_value=csp_nonce_value,
        )
    )


def respond(
    protocol: str,
    visitor: Optional[str],
    path: str,
    wall_hdrs: Dict[str, str],
    *,
    accept: Optional[str] = None,
    host: Optional[str] = None,
    scheme: Optional[str] = None,
    query_string: str = "",
    method: str = "GET",
    accept_language: Optional[str] = None,
    cookie: Optional[str] = None,
    body: bytes = b"",
    correlation_id: Optional[str] = None,
    authorization: Optional[str] = None,
    origin: Optional[str] = None,
) -> HttpOut:
    started = time.perf_counter()
    nonce = csp_nonce()
    try:
        out = _respond_impl(
            protocol,
            visitor,
            path,
            wall_hdrs,
            accept=accept,
            host=host,
            scheme=scheme,
            query_string=query_string,
            method=method,
            accept_language=accept_language,
            cookie=cookie,
            body=body,
            authorization=authorization,
            csp_nonce_value=nonce,
        )
    except Exception as exc:
        from . import weblog

        try:
            weblog.write_error(
                path=path,
                status=500,
                error=str(exc),
                peer=visitor,
                user=http_admin.current_user(cookie, authorization),
            )
        except OSError:
            pass
        raise
    audited = _audit_http(
        out,
        started=started,
        path=path,
        method=method,
        visitor=visitor,
        cookie=cookie,
        correlation_id=correlation_id,
        authorization=authorization,
    )
    return attach_security(audited, scheme, nonce, origin=origin)


async def respond_async(
    protocol: str,
    visitor: Optional[str],
    path: str,
    wall_hdrs: Dict[str, str],
    *,
    accept: Optional[str] = None,
    host: Optional[str] = None,
    scheme: Optional[str] = None,
    query_string: str = "",
    method: str = "GET",
    accept_language: Optional[str] = None,
    cookie: Optional[str] = None,
    body: bytes = b"",
    correlation_id: Optional[str] = None,
    authorization: Optional[str] = None,
    origin: Optional[str] = None,
) -> HttpOut:
    started = time.perf_counter()
    nonce = csp_nonce()
    try:
        out = await _respond_async_impl(
            protocol,
            visitor,
            path,
            wall_hdrs,
            accept=accept,
            host=host,
            scheme=scheme,
            query_string=query_string,
            method=method,
            accept_language=accept_language,
            cookie=cookie,
            body=body,
            authorization=authorization,
            csp_nonce_value=nonce,
        )
    except Exception as exc:
        from . import weblog

        try:
            weblog.write_error(
                path=path,
                status=500,
                error=str(exc),
                peer=visitor,
                user=http_admin.current_user(cookie, authorization),
            )
        except OSError:
            pass
        raise
    audited = _audit_http(
        out,
        started=started,
        path=path,
        method=method,
        visitor=visitor,
        cookie=cookie,
        correlation_id=correlation_id,
        authorization=authorization,
    )
    return attach_security(audited, scheme, nonce, origin=origin)

