"""Request wall: wrap any WSGI or ASGI app.

    from looking_glass.wall import wall
    app = wall(app)

Call it last. Lists are checked in memory first; ASN/country lookup runs only
on a miss. Unknown visitors are allowed. Challenge is a first-party puzzle.
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum, auto
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

from ..intel_server import client as lookup_client
from . import challenge as wall_challenge
from . import lists as wall_lists
from . import traffic as wall_traffic
from ..intel.flags import canonical_country
from .lists import default_lists_path

_JSON = json.dumps
_IP_TIE = {"block": 3, "challenge": 2, "allow": 1}


class Decision(Enum):
    ALLOW = auto()
    BLOCK = auto()
    CHALLENGE = auto()


def wall(app, config: dict | None = None, **kwargs):
    """Wrap a WSGI or ASGI app. This is the only call you need."""
    cfg = dict(config or {})
    cfg.update(kwargs)
    if _protocol(app) == "asgi":
        return WallASGI(app, cfg)
    return WallWSGI(app, cfg)


def _protocol(app) -> str:
    call = getattr(type(app), "__call__", None)
    if inspect.iscoroutinefunction(call) or inspect.iscoroutinefunction(app):
        return "asgi"
    return "wsgi"


def _status_line(code: int) -> str:
    try:
        return f"{code} {HTTPStatus(code).phrase}"
    except ValueError:
        return f"{code} Status"


def _asn_number(ctx: Any) -> Optional[int]:
    asn = getattr(ctx, "asn", None) if ctx is not None else None
    if asn is False or asn is None:
        return None
    try:
        return int(asn)
    except (TypeError, ValueError):
        return None


def _peer_ip(peer: Optional[str]) -> Optional[str]:
    text = (peer or "").strip()
    if not text:
        return None
    try:
        ip_obj = ipaddress.ip_address(text)
    except ValueError:
        return text
    mapped = getattr(ip_obj, "ipv4_mapped", None)
    if mapped is not None:
        return str(mapped)
    return str(ip_obj)


def _is_acme_http01(path: Any) -> bool:
    text = str(path or "")
    return text.startswith("/.well-known/acme-challenge/")


def _header_safe(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text.encode("latin-1", "replace").decode("latin-1")


def _file_stamp(path: Optional[str]) -> Optional[Tuple[int, int]]:
    if not path:
        return None
    try:
        st = os.stat(path)
    except OSError:
        return None
    mtime_ns = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
    return (int(mtime_ns), int(st.st_size))


def _request_scheme(connection: Optional[str], forwarded: Optional[str]) -> str:
    from ..auth.session import effective_scheme

    return effective_scheme(connection, forwarded)


@dataclass(frozen=True)
class _ListSnap:
    allow_exact: frozenset
    allow_nets: tuple
    block_exact: frozenset
    block_nets: tuple
    challenge_exact: frozenset
    challenge_nets: tuple
    block_asns: frozenset
    challenge_asns: frozenset
    block_countries: frozenset
    reasons: dict


_EMPTY_SNAP = _ListSnap(
    allow_exact=frozenset(),
    allow_nets=(),
    block_exact=frozenset(),
    block_nets=(),
    challenge_exact=frozenset(),
    challenge_nets=(),
    block_asns=frozenset(),
    challenge_asns=frozenset(),
    block_countries=frozenset(),
    reasons={},
)


def _wants_html(accept: Optional[str]) -> bool:
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


def _correlation_id() -> str:
    return str(uuid.uuid4())


def _is_wall_admin_path(path: str) -> bool:
    text = str(path or "/")
    if not text.startswith("/"):
        text = "/" + text
    return text == "/wall" or text.startswith("/wall/")


def _header_value(headers: Any, name: str) -> Optional[str]:
    want = name.lower()
    for raw_name, raw_value in headers or []:
        key = raw_name.decode("latin-1") if isinstance(raw_name, (bytes, bytearray)) else str(raw_name)
        if key.lower() == want:
            val = raw_value.decode("latin-1") if isinstance(raw_value, (bytes, bytearray)) else str(raw_value)
            return val
    return None


def _admin_user(cookie: Optional[str], authorization: Optional[str] = None) -> Optional[str]:
    try:
        from ..http.admin import current_user

        return current_user(cookie, authorization)
    except Exception:
        return None


class Wall:
    """WSGI/ASGI wrapper. Construct with wall(app), not by reaching into a framework."""

    def __init__(self, app, config: dict | None = None):
        if app is None:
            raise ValueError("app is required")
        self.app = app
        self._protocol = _protocol(app)
        self.config = dict(config or {})
        if "lists" in self.config:
            self.lists_path = self.config.get("lists")
        else:
            self.lists_path = default_lists_path()
        self.challenge_status = int(self.config.get("challenge_status", 403))
        self.challenge_ttl_days = self._setting("challenge_ttl_days", wall_challenge.DEFAULT_TTL_DAYS)
        self.challenge_bits = wall_challenge.clamp_bits(
            self.config.get("challenge_bits", self._cfg_get("challenge_bits", wall_challenge.DEFAULT_BITS))
        )
        self._hdr = str(self.config.get("header_prefix", "X-Wall")).rstrip("-")
        self._snap_lock = threading.Lock()
        self._snap: _ListSnap = _EMPTY_SNAP
        self._lists_stamp: Optional[Tuple[int, int]] = None
        self._secret_path = str(
            self.config.get("secret_path") or wall_challenge.secret_path(self.lists_path)
        )
        raw_secret = self.config.get("secret")
        if isinstance(raw_secret, (bytes, bytearray)):
            self._mem_secret: Optional[bytes] = bytes(raw_secret)
        elif not self.lists_path and "secret_path" not in self.config:
            self._mem_secret = secrets.token_bytes(32)
        else:
            self._mem_secret = None
        self._aio = None
        self._lists_loaded = False
        try:
            wall_traffic.configure(self.lists_path)
        except Exception:
            pass
        self.reload_lists()

    def _cfg_get(self, name: str, default: Any) -> Any:
        try:
            from ..config import get as config_get

            return config_get(f"wall.{name}")
        except Exception:
            return default

    def _default_is_block(self) -> bool:
        raw = self.config.get("default", self._cfg_get("default", "allow"))
        return str(raw or "allow").strip().lower() == "block"

    def _header_on(self, name: str) -> bool:
        blob = self.config.get("headers")
        if isinstance(blob, dict) and name in blob:
            val = blob[name]
            if isinstance(val, bool):
                return val
            text = str(val).strip().lower()
            if text in {"0", "false", "no", "off"}:
                return False
            if text in {"1", "true", "yes", "on"}:
                return True
            return bool(val)
        try:
            return bool(self._cfg_get(f"headers.{name}", True))
        except Exception:
            return True

    def _setting(self, name: str, default: int) -> int:
        raw = self.config.get(name, self._cfg_get(name, default))
        try:
            value = int(raw)
        except (TypeError, ValueError):
            return int(default)
        return value if value >= 1 else int(default)

    def _secret(self) -> bytes:
        if self._mem_secret:
            return self._mem_secret
        key = wall_challenge.load_secret(self._secret_path)
        self._mem_secret = key
        return key

    def _current_snap(self) -> _ListSnap:
        with self._snap_lock:
            return self._snap

    def reload_lists(self) -> None:
        if self.lists_path:
            if not os.path.isfile(self.lists_path) and self._lists_loaded:
                return
            try:
                data = wall_lists.load_lists(self.lists_path)
                stamp = _file_stamp(self.lists_path)
            except (OSError, ValueError, json.JSONDecodeError):
                if self._lists_loaded:
                    return
                data = {key: list(vals) for key, vals in wall_lists.DEFAULT_LISTS.items()}
                data["reasons"] = {}
                stamp = None
        else:
            data = {key: list(vals) for key, vals in wall_lists.DEFAULT_LISTS.items()}
            stamp = None
        cfg = self.config

        def pick(key: str) -> Any:
            return cfg.get(key, data.get(key) or [])

        allow_exact, allow_nets = wall_lists.as_networks(pick("allow_ips"))
        block_exact, block_nets = wall_lists.as_networks(pick("block_ips"))
        challenge_exact, challenge_nets = wall_lists.as_networks(pick("challenge_ips"))
        snap = _ListSnap(
            allow_exact=frozenset(allow_exact),
            allow_nets=tuple(allow_nets),
            block_exact=frozenset(block_exact),
            block_nets=tuple(block_nets),
            challenge_exact=frozenset(challenge_exact),
            challenge_nets=tuple(challenge_nets),
            block_asns=frozenset(wall_lists.as_asns(pick("block_asns"))),
            challenge_asns=frozenset(wall_lists.as_asns(pick("challenge_asns"))),
            block_countries=frozenset(wall_lists.as_countries(pick("block_countries"))),
            reasons=dict(data.get("reasons") or {}),
        )
        with self._snap_lock:
            self._snap = snap
            self._lists_stamp = stamp
            self._lists_loaded = True

    def check(
        self,
        *,
        ip: str,
        ctx: Any = None,
        method: Any = None,
        path: Any = None,
        headers: Any = None,
    ) -> Tuple[Decision, Dict[str, Any]]:
        """Return (decision, meta) for this client IP using lists and lookup data."""
        try:
            ip_obj = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return Decision.BLOCK, {"reason": "invalid_ip"}
        mapped = getattr(ip_obj, "ipv4_mapped", None)
        if mapped is not None:
            ip_obj = mapped

        snap = self._current_snap()
        ip_hit = self._ip_list_decision(ip_obj, snap)
        if ip_hit is not None:
            decision, meta = ip_hit
            return decision, self._stored_reason(ip_obj, meta, snap)

        asn_n = _asn_number(ctx)
        if asn_n is not None and asn_n in snap.block_asns:
            return Decision.BLOCK, {"reason": "block_asn", "asn": asn_n}

        country = canonical_country(
            getattr(ctx, "country", None) if ctx is not None else None
        )
        if country and country in snap.block_countries:
            return Decision.BLOCK, {"reason": "block_country", "country": country}

        if asn_n is not None and asn_n in snap.challenge_asns:
            return Decision.CHALLENGE, {"reason": "challenge_asn", "asn": asn_n}

        if self._default_is_block():
            if ip_obj.is_loopback:
                return Decision.ALLOW, {"reason": "loopback"}
            if _is_acme_http01(path):
                return Decision.ALLOW, {"reason": "acme"}
            return Decision.BLOCK, {"reason": "default"}
        return Decision.ALLOW, {"reason": "default"}

    def _ip_list_decision(
        self, ip_obj: ipaddress._BaseAddress, snap: Optional[_ListSnap] = None
    ) -> Optional[Tuple[Decision, Dict[str, Any]]]:
        snap = snap if snap is not None else self._current_snap()
        candidates: List[Tuple[int, int, Decision, str]] = []
        for name, exact, nets, decision, reason in (
            ("allow", snap.allow_exact, snap.allow_nets, Decision.ALLOW, "allow_ip"),
            ("block", snap.block_exact, snap.block_nets, Decision.BLOCK, "block_ip"),
            (
                "challenge",
                snap.challenge_exact,
                snap.challenge_nets,
                Decision.CHALLENGE,
                "challenge_ip",
            ),
        ):
            plen = wall_lists.best_prefixlen(ip_obj, exact, nets)
            if plen is None:
                continue
            candidates.append((plen, _IP_TIE[name], decision, reason))
        if not candidates:
            return None
        candidates.sort()
        _plen, _tie, decision, reason = candidates[-1]
        return decision, {"reason": reason}

    def _stored_reason(
        self,
        ip_obj: ipaddress._BaseAddress,
        meta: Dict[str, Any],
        snap: Optional[_ListSnap] = None,
    ) -> Dict[str, Any]:
        snap = snap if snap is not None else self._current_snap()
        reason = meta.get("reason")
        if reason == "allow_ip":
            exact, nets = snap.allow_exact, snap.allow_nets
        elif reason == "block_ip":
            exact, nets = snap.block_exact, snap.block_nets
        elif reason == "challenge_ip":
            exact, nets = snap.challenge_exact, snap.challenge_nets
        else:
            return meta
        entry = wall_lists.best_entry(ip_obj, exact, nets)
        stored = snap.reasons.get(entry or "")
        if not stored:
            return meta
        out = dict(meta)
        out["entry"] = entry
        if stored.get("reason"):
            out["reason"] = stored["reason"]
        out.update(stored.get("detail") or {})
        return out

    def _maybe_reload(self) -> None:
        path = self.lists_path
        if not path:
            return
        if _file_stamp(path) != self._lists_stamp:
            self.reload_lists()

    def _lists_only(self, ip: Optional[str]) -> Optional[Tuple[Decision, Dict[str, Any]]]:
        self._maybe_reload()
        if not ip:
            return Decision.BLOCK, {"reason": "no_ip"}
        try:
            ip_obj = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return Decision.BLOCK, {"reason": "invalid_ip"}
        mapped = getattr(ip_obj, "ipv4_mapped", None)
        if mapped is not None:
            ip_obj = mapped
        snap = self._current_snap()
        hit = self._ip_list_decision(ip_obj, snap)
        if hit is None:
            return None
        decision, meta = hit
        return decision, self._stored_reason(ip_obj, meta, snap)

    def _lookup_miss(self, snap: _ListSnap) -> Optional[Tuple[Decision, Dict[str, Any]]]:
        if snap.block_asns or snap.block_countries:
            return Decision.BLOCK, {"reason": "lookup_failed"}
        if snap.challenge_asns:
            return Decision.CHALLENGE, {"reason": "lookup_failed"}
        return None

    def _finish_sync(self, ip: Optional[str], path: str = "/") -> Tuple[Decision, Dict[str, Any], Any]:
        settled = self._lists_only(ip)
        if settled is not None:
            return settled[0], settled[1], None
        ctx = None
        try:
            ctx = lookup_client.lookup_ip(ip)
        except Exception:
            ctx = None
        if ctx is None:
            miss = self._lookup_miss(self._current_snap())
            if miss is not None:
                return miss[0], miss[1], None
        decision, meta = self.check(ip=ip, ctx=ctx, path=path)
        return decision, meta, ctx

    async def _finish_async(self, ip: Optional[str], path: str = "/") -> Tuple[Decision, Dict[str, Any], Any]:
        settled = self._lists_only(ip)
        if settled is not None:
            return settled[0], settled[1], None
        ctx = None
        try:
            ctx = await lookup_client.lookup_ip_async(ip, session=await self._session())
        except Exception:
            ctx = None
        if ctx is None:
            miss = self._lookup_miss(self._current_snap())
            if miss is not None:
                return miss[0], miss[1], None
        decision, meta = self.check(ip=ip, ctx=ctx, path=path)
        return decision, meta, ctx

    async def _session(self):
        session = self._aio
        if session is not None and not session.closed:
            return session
        import aiohttp

        self._aio = aiohttp.ClientSession(
            connector=aiohttp.UnixConnector(path=lookup_client.LOOKUP_SOCKET)
        )
        return self._aio

    def _soften_challenge(
        self, decision: Decision, meta: Dict[str, Any], ip: Optional[str], cookie: Optional[str]
    ) -> Tuple[Decision, Dict[str, Any]]:
        if decision != Decision.CHALLENGE:
            return decision, meta
        if ip and wall_challenge.cookie_valid(cookie, ip, self._secret()):
            out = dict(meta)
            out["reason"] = "pass"
            return Decision.ALLOW, out
        return decision, meta

    def _admin_wall_allow(
        self,
        decision: Decision,
        meta: Dict[str, Any],
        path: str,
        cookie: Optional[str],
        authorization: Optional[str] = None,
    ) -> Tuple[Decision, Dict[str, Any]]:
        if decision != Decision.CHALLENGE:
            return decision, meta
        if not _is_wall_admin_path(path):
            return decision, meta
        if not _admin_user(cookie, authorization):
            return decision, meta
        out = dict(meta)
        out["reason"] = "session"
        return Decision.ALLOW, out

    def _header_items(
        self,
        ctx: Any,
        decision: Optional[Decision],
        meta: Dict[str, Any],
        corr: str,
    ) -> List[Tuple[str, str]]:
        pref = self._hdr
        items: List[Tuple[str, str]] = [("X-Correlation-Id", corr)]
        if decision is not None and self._header_on("decision"):
            items.append((f"{pref}-Decision", decision.name.lower()))
        reason = meta.get("reason")
        if reason and self._header_on("reason"):
            items.append((f"{pref}-Reason", str(reason)))
        if ctx is None:
            return [(_header_safe(k), _header_safe(v)) for k, v in items]
        if getattr(ctx, "asn", None) not in (None, False) and self._header_on("asn"):
            items.append((f"{pref}-ASN", str(ctx.asn)))
        if getattr(ctx, "org_name", None) and self._header_on("org"):
            items.append((f"{pref}-Org", str(ctx.org_name)))
        if getattr(ctx, "prefix", None) and self._header_on("prefix"):
            items.append((f"{pref}-Prefix", str(ctx.prefix)))
        if getattr(ctx, "country", None) and self._header_on("country"):
            items.append((f"{pref}-Country", str(ctx.country)))
        if getattr(ctx, "flag_url", None) and self._header_on("flag_url"):
            items.append((f"{pref}-Flag-Url", str(ctx.flag_url)))
        if getattr(ctx, "timings", None) and self._header_on("timings"):
            items.append((f"{pref}-Timings", _JSON(ctx.timings)))
        if getattr(ctx, "iana", None) and self._header_on("iana"):
            items.append((f"{pref}-IANA", _JSON(ctx.iana)))
        return [(_header_safe(k), _header_safe(v)) for k, v in items]

    def _deny_payload(self, decision: Decision, meta: Dict[str, Any], nxt: str = "/") -> bytes:
        if decision == Decision.CHALLENGE:
            return _JSON(wall_challenge.deny_json(meta, nxt)).encode("utf-8")
        body: Dict[str, Any] = {
            "ok": False,
            "decision": decision.name.lower(),
            "reason": meta.get("reason"),
        }
        for key in ("asn", "country", "entry"):
            value = meta.get(key)
            if value not in (None, "", []):
                body[key] = value
        return _JSON(body).encode("utf-8")

    def _peer_prefix(self, ctx: Any, ip: Optional[str]) -> Optional[str]:
        prefix = getattr(ctx, "prefix", None) if ctx is not None else None
        if prefix not in (None, "", False):
            return str(prefix)
        if not ip:
            return None
        try:
            from ..http.weblog import compact_intel

            intel = compact_intel(ip)
        except Exception:
            intel = None
        if isinstance(intel, dict) and intel.get("prefix"):
            return str(intel["prefix"])
        return None

    def _record(
        self,
        *,
        corr: str,
        ip: Optional[str],
        method: str,
        path: str,
        decision: Decision,
        status: int,
        started: float,
        reason: Optional[str],
        ctx: Any = None,
    ) -> None:
        try:
            wall_traffic.record(
                id=corr,
                peer=ip,
                method=method,
                path=path,
                decision=decision.name.lower(),
                status=status,
                ms=(time.perf_counter() - started) * 1000,
                reason=reason,
                prefix=self._peer_prefix(ctx, ip),
            )
        except Exception:
            pass

    def _record_challenge(
        self,
        *,
        corr: str,
        ip: Optional[str],
        event: str,
        reason: Optional[str],
        ctx: Any = None,
        path: str = "/",
    ) -> None:
        try:
            wall_traffic.record_challenge(
                id=corr,
                peer=ip,
                event=event,
                reason=reason,
                bits=self.challenge_bits,
                prefix=self._peer_prefix(ctx, ip),
                path=path,
            )
        except Exception:
            pass

    def _secure_headers(
        self,
        headers: List[Tuple[str, str]],
        scheme: Optional[str],
        origin: Optional[str],
        nonce: Optional[str] = None,
    ) -> Tuple[List[Tuple[str, str]], str]:
        from ..http.security import csp_nonce, merge_security_headers

        token = nonce if nonce is not None else csp_nonce()
        return merge_security_headers(list(headers or []), scheme, token, origin=origin), token

    def _issue_challenge(
        self,
        ip: Optional[str],
        nxt: str,
        accept: Optional[str],
        meta: Optional[Dict[str, Any]] = None,
        *,
        scheme: Optional[str] = None,
        origin: Optional[str] = None,
    ) -> Tuple[int, List[Tuple[str, str]], bytes]:
        from ..http.security import csp_nonce

        ticket = wall_challenge.issue_ticket(ip or "", self._secret(), self.challenge_bits)
        nonce = csp_nonce()
        if _wants_html(accept):
            body = wall_challenge.page_html(ticket, nxt, nonce=nonce)
            headers, _ = self._secure_headers(
                [("Content-Type", "text/html; charset=utf-8")],
                scheme,
                origin,
                nonce=nonce,
            )
            return self.challenge_status, headers, body
        payload = wall_challenge.deny_json(meta or {}, nxt)
        payload["ticket"] = ticket["ticket"]
        payload["bits"] = ticket["bits"]
        headers, _ = self._secure_headers(
            [("Content-Type", "application/json")],
            scheme,
            origin,
            nonce=nonce,
        )
        return self.challenge_status, headers, _JSON(payload).encode("utf-8")

    def _handle_challenge_endpoint(
        self,
        *,
        ip: Optional[str],
        method: str,
        query: str,
        accept: Optional[str],
        scheme: Optional[str],
        content_type: str,
        raw: bytes,
        decision: Decision,
        meta: Dict[str, Any],
        origin: Optional[str] = None,
    ) -> Optional[Tuple[int, List[Tuple[str, str]], bytes]]:
        if decision == Decision.BLOCK:
            return None
        qs = parse_qs(query or "", keep_blank_values=True)
        nxt = wall_challenge._safe_next((qs.get("next") or ["/"])[0])
        verb = (method or "GET").upper()
        if verb == "GET":
            return self._issue_challenge(ip, nxt, accept, meta, scheme=scheme, origin=origin)
        if verb != "POST":
            headers, _ = self._secure_headers(
                [("Content-Type", "application/json")],
                scheme,
                origin,
            )
            return 405, headers, _JSON({"ok": False, "error": "use GET or POST"}).encode("utf-8")
        data = wall_challenge.parse_body(raw, content_type)
        nxt = wall_challenge._safe_next(data.get("next") or nxt)
        ticket = str(data.get("ticket") or "")
        if not ip or not wall_challenge.verify_solution(ticket, data.get("counter"), ip, self._secret()):
            payload = {"ok": False, "error": "challenge failed"}
            headers, _ = self._secure_headers(
                [("Content-Type", "application/json")],
                scheme,
                origin,
            )
            return 403, headers, _JSON(payload).encode("utf-8")
        ttl = wall_challenge.ttl_seconds(self.challenge_ttl_days)
        token = wall_challenge.cookie_value(ip, self._secret(), ttl)
        headers, _ = self._secure_headers(
            [
                ("Content-Type", "application/json"),
                ("Set-Cookie", wall_challenge.set_cookie_header(token, ttl, scheme=scheme)),
            ],
            scheme,
            origin,
        )
        body = _JSON({"ok": True, "decision": "allow", "next": nxt}).encode("utf-8")
        return 200, headers, body

    def _wsgi(self, environ, start_response):
        started = time.perf_counter()
        ip = _peer_ip(environ.get("REMOTE_ADDR"))
        method = str(environ.get("REQUEST_METHOD") or "GET")
        path = str(environ.get("PATH_INFO") or "/")
        query = str(environ.get("QUERY_STRING") or "")
        accept = environ.get("HTTP_ACCEPT")
        cookie = environ.get("HTTP_COOKIE")
        authorization = environ.get("HTTP_AUTHORIZATION")
        scheme = _request_scheme(
            environ.get("wsgi.url_scheme"),
            environ.get("HTTP_X_FORWARDED_PROTO"),
        )
        origin = environ.get("HTTP_ORIGIN")
        corr = _correlation_id()
        decision, meta, ctx = self._finish_sync(ip, path=path)
        decision, meta = self._soften_challenge(decision, meta, ip, cookie)
        decision, meta = self._admin_wall_allow(decision, meta, path, cookie, authorization)
        items = self._header_items(ctx, decision, meta, corr)
        if wall_challenge.is_challenge_path(path) and decision != Decision.BLOCK:
            try:
                length = int(environ.get("CONTENT_LENGTH") or 0)
            except (TypeError, ValueError):
                length = 0
            raw = environ["wsgi.input"].read(length) if length > 0 else b""
            handled = self._handle_challenge_endpoint(
                ip=ip,
                method=method,
                query=query,
                accept=accept,
                scheme=scheme,
                content_type=str(environ.get("CONTENT_TYPE") or ""),
                raw=raw,
                decision=decision,
                meta=meta,
                origin=origin,
            )
            if handled is not None:
                code, extra, body = handled
                headers = [
                    ("Content-Length", str(len(body))),
                ]
                headers.extend(extra)
                headers.extend(items)
                rec = Decision.ALLOW if code < 400 else decision
                if (method or "GET").upper() == "GET":
                    self._record_challenge(
                        corr=corr, ip=ip, event="issued", reason=meta.get("reason"), ctx=ctx, path=path
                    )
                elif code < 400:
                    self._record_challenge(
                        corr=corr, ip=ip, event="solved", reason="pass", ctx=ctx, path=path
                    )
                else:
                    self._record_challenge(
                        corr=corr, ip=ip, event="failed", reason="challenge failed", ctx=ctx, path=path
                    )
                self._record(
                    corr=corr, ip=ip, method=method, path=path, decision=rec,
                    status=code, started=started, reason=meta.get("reason"), ctx=ctx,
                )
                start_response(_status_line(code), headers)
                return [body]
        if decision == Decision.CHALLENGE:
            nxt = path if path.startswith("/") else "/"
            code, extra, body = self._issue_challenge(
                ip, nxt, accept, meta, scheme=scheme, origin=origin
            )
            headers = [("Content-Length", str(len(body)))]
            headers.extend(extra)
            headers.extend(items)
            self._record_challenge(
                corr=corr, ip=ip, event="issued", reason=meta.get("reason"), ctx=ctx, path=path
            )
            self._record(
                corr=corr, ip=ip, method=method, path=path, decision=decision,
                status=code, started=started, reason=meta.get("reason"), ctx=ctx,
            )
            start_response(_status_line(code), headers)
            return [body]
        if decision == Decision.BLOCK:
            body = self._deny_payload(decision, meta)
            headers, _ = self._secure_headers(
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(body))),
                ],
                scheme,
                origin,
            )
            headers.extend(items)
            self._record(
                corr=corr, ip=ip, method=method, path=path, decision=decision,
                status=403, started=started, reason=meta.get("reason"), ctx=ctx,
            )
            start_response(_status_line(403), headers)
            return [body]
        for key, value in items:
            environ["HTTP_" + key.upper().replace("-", "_")] = value
        captured = {"status": 200}

        def _start(status, headers, exc_info=None):
            captured["status"] = int(str(status).split()[0])
            merged = list(headers) + list(items)
            return start_response(status, merged, exc_info)

        app_iter = self.app(environ, _start)

        def _iter():
            try:
                yield from app_iter
            finally:
                closer = getattr(app_iter, "close", None)
                if closer:
                    try:
                        closer()
                    except Exception:
                        pass
                self._record(
                    corr=corr, ip=ip, method=method, path=path, decision=decision,
                    status=int(captured.get("status") or 200), started=started, reason=meta.get("reason"), ctx=ctx,
                )

        return _iter()

    async def _asgi(self, scope, receive, send):
        if scope["type"] != "http":
            await self._asgi_other(scope, receive, send)
            return
        started = time.perf_counter()
        peer = None
        client = scope.get("client")
        if client:
            peer = client[0]
        ip = _peer_ip(peer)
        method = str(scope.get("method") or "GET")
        path = str(scope.get("path") or "/")
        raw_qs = scope.get("query_string") or b""
        query = raw_qs.decode("latin-1") if isinstance(raw_qs, (bytes, bytearray)) else str(raw_qs)
        accept = _header_value(scope.get("headers"), "accept")
        cookie = _header_value(scope.get("headers"), "cookie")
        authorization = _header_value(scope.get("headers"), "authorization")
        scheme = _request_scheme(
            scope.get("scheme"),
            _header_value(scope.get("headers"), "x-forwarded-proto"),
        )
        origin = _header_value(scope.get("headers"), "origin")
        corr = _correlation_id()
        decision, meta, ctx = await self._finish_async(ip, path=path)
        decision, meta = self._soften_challenge(decision, meta, ip, cookie)
        decision, meta = self._admin_wall_allow(decision, meta, path, cookie, authorization)
        items = self._header_items(ctx, decision, meta, corr)
        extra = [
            (k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in items
        ]

        async def _reply(code: int, headers: List[Tuple[str, str]], body: bytes, rec_decision: Decision) -> None:
            out = [
                (name.lower().encode("latin-1"), _header_safe(value).encode("latin-1"))
                for name, value in headers
            ]
            await send(
                {
                    "type": "http.response.start",
                    "status": code,
                    "headers": out + extra + [(b"content-length", str(len(body)).encode("latin-1"))],
                }
            )
            await send({"type": "http.response.body", "body": body})
            if wall_challenge.is_challenge_path(path):
                if (method or "GET").upper() == "GET":
                    self._record_challenge(
                        corr=corr, ip=ip, event="issued", reason=meta.get("reason"), ctx=ctx, path=path
                    )
                elif code < 400:
                    self._record_challenge(
                        corr=corr, ip=ip, event="solved", reason="pass", ctx=ctx, path=path
                    )
                else:
                    self._record_challenge(
                        corr=corr, ip=ip, event="failed", reason="challenge failed", ctx=ctx, path=path
                    )
            elif rec_decision == Decision.CHALLENGE:
                self._record_challenge(
                    corr=corr, ip=ip, event="issued", reason=meta.get("reason"), ctx=ctx, path=path
                )
            self._record(
                corr=corr, ip=ip, method=method, path=path, decision=rec_decision,
                status=code, started=started, reason=meta.get("reason"), ctx=ctx,
            )

        if wall_challenge.is_challenge_path(path) and decision != Decision.BLOCK:
            chunks: List[bytes] = []
            more = True
            while more:
                message = await receive()
                if message.get("type") != "http.request":
                    break
                chunks.append(message.get("body") or b"")
                more = bool(message.get("more_body"))
            raw = b"".join(chunks)
            handled = self._handle_challenge_endpoint(
                ip=ip,
                method=method,
                query=query,
                accept=accept,
                scheme=scheme,
                content_type=_header_value(scope.get("headers"), "content-type") or "",
                raw=raw,
                decision=decision,
                meta=meta,
                origin=origin,
            )
            if handled is not None:
                code, headers, body = handled
                rec = Decision.ALLOW if code < 400 else decision
                await _reply(code, headers, body, rec)
                return
        if decision == Decision.CHALLENGE:
            nxt = path if path.startswith("/") else "/"
            code, headers, body = self._issue_challenge(
                ip, nxt, accept, meta, scheme=scheme, origin=origin
            )
            await _reply(code, headers, body, decision)
            return
        if decision == Decision.BLOCK:
            body = self._deny_payload(decision, meta)
            headers, _ = self._secure_headers(
                [("Content-Type", "application/json")],
                scheme,
                origin,
            )
            await _reply(403, headers, body, decision)
            return
        scope = dict(scope)
        scope["headers"] = list(scope.get("headers") or []) + extra
        captured = {"status": 200, "done": False}

        async def _send(message):
            if message.get("type") == "http.response.start":
                captured["status"] = int(message.get("status") or 200)
                message = dict(message)
                message["headers"] = list(message.get("headers") or []) + extra
            if message.get("type") == "http.response.body" and not message.get("more_body"):
                if not captured["done"]:
                    captured["done"] = True
                    self._record(
                        corr=corr, ip=ip, method=method, path=path, decision=decision,
                        status=int(captured.get("status") or 200), started=started, reason=meta.get("reason"), ctx=ctx,
                    )
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            if not captured["done"]:
                self._record(
                    corr=corr, ip=ip, method=method, path=path, decision=decision,
                    status=int(captured.get("status") or 200), started=started, reason=meta.get("reason"), ctx=ctx,
                )

    async def _asgi_other(self, scope, receive, send) -> None:
        peer = None
        client = scope.get("client")
        if client:
            peer = client[0]
        ip = _peer_ip(peer)
        decision, meta, _ctx = await self._finish_async(ip, path=str(scope.get("path") or "/"))
        cookie = _header_value(scope.get("headers"), "cookie")
        decision, meta = self._soften_challenge(decision, meta, ip, cookie)
        if decision == Decision.ALLOW:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 403})


class WallWSGI(Wall):
    """WSGI: gunicorn, uwsgi, wsgiref, Flask."""

    def __call__(self, environ, start_response):
        return self._wsgi(environ, start_response)


class WallASGI(Wall):
    """ASGI3: uvicorn, hypercorn, Litestar, FastAPI."""

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self._lifespan(scope, receive, send)
            return
        await self._asgi(scope, receive, send)

    async def _lifespan(self, scope, receive, send):
        if inspect.iscoroutinefunction(self.app) or inspect.isfunction(self.app):
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    session = self._aio
                    self._aio = None
                    if session is not None:
                        await session.close()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return
        await self.app(scope, receive, send)
