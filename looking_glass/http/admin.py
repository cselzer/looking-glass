"""Session-gated HTTP: login, history, cache gate, intel server start/stop."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs

from ..auth import history, keys, password, session
from .. import cache as query_cache

_JSON = "application/json"
ExtraHeaders = List[Tuple[str, str]]
HttpOut = Tuple[int, str, bytes, ExtraHeaders]


def _pack(status: int, payload: Dict[str, Any], headers: Optional[ExtraHeaders] = None) -> HttpOut:
    return (
        int(status),
        _JSON,
        json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        list(headers or []),
    )


def current_user(cookie: Optional[str], authorization: Optional[str] = None) -> Optional[str]:
    name = keys.verify_authorization(authorization)
    if name:
        return name
    return session.user_from_cookie(cookie)


def _need_user(
    cookie: Optional[str], authorization: Optional[str] = None
) -> Tuple[Optional[str], Optional[HttpOut]]:
    user = current_user(cookie, authorization)
    if user:
        return user, None
    return None, _pack(401, {"ok": False, "error": "login required"})


def _parse_password(raw: bytes) -> str:
    text = (raw or b"").decode("utf-8", "replace").strip()
    if not text:
        return ""
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return ""
        if not isinstance(data, dict):
            return ""
        return str(data.get("password") or "")
    qs = parse_qs(text, keep_blank_values=True)
    return (qs.get("password") or [""])[0]


def _record(user: str, path: str, payload: Dict[str, Any]) -> None:
    if not user or not payload.get("ok"):
        return
    stored = {
        key: value
        for key, value in payload.items()
        if key not in {"secret", "password", "password_hash"}
    }
    history.append(
        user,
        path=path,
        kind=str(stored.get("kind") or ""),
        query=str(stored.get("query") or ""),
        payload=stored,
    )


def handle_login(raw: bytes, scheme: Optional[str], visitor: Optional[str] = None) -> HttpOut:
    from . import weblog

    secret = _parse_password(raw)
    if not password.is_set() or not secret:
        weblog.write_login(ok=False, peer=visitor, reason="invalid credentials")
        return _pack(401, {"ok": False, "error": "invalid credentials"})
    if not password.verify(secret):
        weblog.write_login(ok=False, peer=visitor, reason="invalid credentials")
        return _pack(401, {"ok": False, "error": "invalid credentials"})
    try:
        token = session.create()
    except OSError as exc:
        weblog.write_login(ok=False, peer=visitor, reason=str(exc))
        return _pack(500, {"ok": False, "error": str(exc)})
    payload = {"ok": True, "kind": "auth", "query": "login", "user": "admin", "admin": True}
    _record("admin", "/login", payload)
    weblog.write_login(ok=True, peer=visitor, reason="ok")
    return _pack(200, payload, session.set_cookie_headers(token, scheme=scheme))


def handle_logout(
    cookie: Optional[str], scheme: Optional[str], authorization: Optional[str] = None
) -> HttpOut:
    token = session.parse_token(cookie) or ""
    user = current_user(cookie, authorization)
    if token:
        session.delete(token)
    payload = {"ok": True, "kind": "auth", "query": "logout", "user": user, "admin": bool(user)}
    if user:
        _record(user, "/logout", payload)
    return _pack(200, payload, session.set_cookie_headers("", scheme=scheme, clear=True))


def handle_session(cookie: Optional[str], authorization: Optional[str] = None) -> HttpOut:
    user = current_user(cookie, authorization)
    return _pack(200, {"ok": True, "user": user, "admin": bool(user)})


def handle_auth_keys(
    method: str,
    token: str,
    cookie: Optional[str],
    body: bytes = b"",
    authorization: Optional[str] = None,
) -> HttpOut:
    user, denied = _need_user(cookie, authorization)
    if denied:
        return denied
    verb = (method or "GET").upper()
    rest = token[len("auth/keys") :].lstrip("/")
    if verb == "GET" and not rest:
        listed = keys.list_keys()
        return _pack(
            200,
            {
                "ok": True,
                "kind": "auth",
                "query": "keys",
                "keys": listed,
                "count": len(listed),
                "password_set": password.is_set(),
            },
        )
    if verb == "POST" and not rest:
        data = _config_body(body)
        try:
            created = keys.create(str(data.get("name") or ""))
        except ValueError as exc:
            return _pack(400, {"ok": False, "error": str(exc)})
        payload = {"ok": True, "kind": "auth", "query": "keys", **created}
        _record(user or "", "/auth/keys", payload)
        return _pack(200, payload)
    if verb == "DELETE" and rest:
        if not keys.revoke(rest):
            return _pack(404, {"ok": False, "error": "not found"})
        payload = {"ok": True, "kind": "auth", "query": "keys", "id": rest}
        _record(user or "", "/auth/keys/" + rest, payload)
        return _pack(200, payload)
    if rest:
        return _pack(404, {"ok": False, "error": "not found"})
    return _pack(405, {"ok": False, "error": "use GET, POST, or DELETE"})


def handle_auth_password(
    method: str,
    token: str,
    cookie: Optional[str],
    body: bytes = b"",
    authorization: Optional[str] = None,
) -> HttpOut:
    user, denied = _need_user(cookie, authorization)
    if denied:
        return denied
    verb = (method or "GET").upper()
    if verb != "POST":
        return _pack(405, {"ok": False, "error": "use POST"})
    if token == "auth/password/clear":
        password.clear()
        payload = {"ok": True, "kind": "auth", "query": "password", "set": False}
        _record(user or "", "/auth/password/clear", payload)
        return _pack(200, payload)
    secret = _parse_password(body)
    try:
        password.set_password(secret)
    except ValueError as exc:
        return _pack(400, {"ok": False, "error": str(exc)})
    payload = {"ok": True, "kind": "auth", "query": "password", "set": True}
    _record(user or "", "/auth/password", payload)
    return _pack(200, payload)


def handle_history(
    method: str, token: str, cookie: Optional[str], authorization: Optional[str] = None
) -> HttpOut:
    verb = (method or "GET").upper()
    if verb != "GET":
        return _pack(405, {"ok": False, "error": "use GET"})
    rest = token[len("history") :].lstrip("/")
    if not rest:
        user, denied = _need_user(cookie, authorization)
        if denied:
            return denied
        return _pack(200, {"ok": True, "files": history.list_entries(user or "")})
    entry = history.get_entry("", rest)
    if not entry:
        return _pack(404, {"ok": False, "error": "not found"})
    return _pack(200, {"ok": True, **entry})


def handle_serve(
    method: str, token: str, cookie: Optional[str], authorization: Optional[str] = None
) -> HttpOut:
    user, denied = _need_user(cookie, authorization)
    if denied:
        return denied
    verb = (method or "GET").upper()
    if verb != "POST":
        return _pack(405, {"ok": False, "error": "use POST"})
    from ..intel_server import app as lookup_mod

    if token == "serve/start":
        from ..datasets import due_keys

        due = list(due_keys())
        report = lookup_mod.start(wait_ready=False)
        building = list(report.get("building") if report.get("building") is not None else due)
        payload = {
            "ok": bool(report.get("ok")),
            "kind": "serve",
            "query": "start",
            "running": bool(report.get("running")),
            "ready": bool(report.get("ready")),
            "result": {
                "running": bool(report.get("running")),
                "ready": bool(report.get("ready")),
                "state": report.get("state") or "starting",
                "building": building,
            },
        }
        if payload["ok"]:
            _record(user or "", "/serve/start", payload)
        status = 200 if payload["ok"] else 500
        return _pack(status, payload)
    if token == "serve/stop":
        report = lookup_mod.stop()
        payload = {
            "ok": bool(report.get("ok")),
            "kind": "serve",
            "query": "stop",
            "running": bool(report.get("running")),
            "result": {"running": bool(report.get("running")), "state": report.get("state")},
        }
        if payload["ok"]:
            _record(user or "", "/serve/stop", payload)
        status = 200 if payload["ok"] else 500
        return _pack(status, payload)
    return _pack(404, {"ok": False, "error": "not found"})


def handle_cache(
    method: str, token: str, cookie: Optional[str], authorization: Optional[str] = None
) -> HttpOut:
    user, denied = _need_user(cookie, authorization)
    if denied:
        return denied
    verb = (method or "GET").upper()
    rest = token[len("cache") :].lstrip("/")
    parts = [part for part in rest.split("/") if part]
    if verb == "GET" and not parts:
        payload = query_cache.stats()
        payload["ok"] = True
        return _pack(200, payload)
    if verb == "GET" and len(parts) == 1:
        ns = parts[0]
        if ns not in query_cache.NAMESPACES:
            return _pack(404, {"ok": False, "error": "unknown cache"})
        payload = query_cache.stats(ns)
        payload["ok"] = True
        return _pack(200, payload)
    if verb in {"DELETE", "POST"}:
        if not parts:
            payload = query_cache.clear()
        else:
            ns = parts[0]
            if ns not in query_cache.NAMESPACES:
                return _pack(404, {"ok": False, "error": "unknown cache"})
            target = parts[1] if len(parts) > 1 else None
            payload = query_cache.clear(ns, None if target in {None, "", "all"} else target)
        envelope = {
            "ok": bool(payload.get("ok")),
            "kind": "cache",
            "query": "clear",
            "path": "/" + token,
            "result": payload,
        }
        if envelope["ok"]:
            _record(user or "", "/" + token, envelope)
        status = 200 if payload.get("ok") else 404
        payload = dict(payload)
        payload.setdefault("kind", "cache")
        payload.setdefault("query", "clear")
        return _pack(status, payload)
    return _pack(405, {"ok": False, "error": "use GET or DELETE"})


def handle_docs(method: str, cookie: Optional[str], authorization: Optional[str] = None) -> HttpOut:
    user, denied = _need_user(cookie, authorization)
    if denied:
        return denied
    verb = (method or "GET").upper()
    if verb != "POST":
        return _pack(405, {"ok": False, "error": "use POST"})
    from ..docs.generate import write_docs

    try:
        dest = write_docs()
    except OSError as exc:
        return _pack(500, {"ok": False, "error": str(exc)})
    payload = {"ok": True, "kind": "docs", "query": "regenerate", "path": dest}
    _record(user or "", "/docs", payload)
    return _pack(200, payload)


def _config_body(raw: bytes) -> Dict[str, Any]:
    text = (raw or b"").decode("utf-8", "replace").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    if isinstance(data.get("values"), dict):
        return dict(data["values"])
    skip = {"ok", "path", "docs_generated", "kind", "query"}
    return {str(key): value for key, value in data.items() if str(key) not in skip}


def handle_config(
    method: str, cookie: Optional[str], body: bytes = b"", authorization: Optional[str] = None
) -> HttpOut:
    user, denied = _need_user(cookie, authorization)
    if denied:
        return denied
    from .. import config as app_config

    verb = (method or "GET").upper()
    if verb == "GET":
        cfg = app_config.load()
        payload = {
            "ok": True,
            "kind": "config",
            "path": app_config.path(),
            "docs_generated": app_config.docs_generated(),
            **cfg,
        }
        return _pack(200, payload)
    if verb != "POST":
        return _pack(405, {"ok": False, "error": "use GET or POST"})
    updates = _config_body(body)
    if not updates:
        return _pack(400, {"ok": False, "error": "no config values"})
    try:
        cfg = app_config.apply_values(updates)
    except KeyError as exc:
        return _pack(400, {"ok": False, "error": f"unknown key {exc.args[0]!r}"})
    except ValueError as exc:
        return _pack(400, {"ok": False, "error": str(exc)})
    payload = {
        "ok": True,
        "kind": "config",
        "query": "set",
        "path": app_config.path(),
        "docs_generated": app_config.docs_generated(),
        **cfg,
    }
    _record(user or "", "/config", payload)
    return _pack(200, payload)


def handle_logs(
    method: str,
    token: str,
    cookie: Optional[str],
    query_string: str = "",
    authorization: Optional[str] = None,
) -> HttpOut:
    user, denied = _need_user(cookie, authorization)
    if denied:
        return denied
    if (method or "GET").upper() != "GET":
        return _pack(405, {"ok": False, "error": "use GET"})
    from . import weblog

    qs = parse_qs(query_string or "", keep_blank_values=True)
    rest = token[len("logs") :].lstrip("/")
    if rest == "stats":
        return _pack(200, weblog.stats_payload())
    kind = rest or (qs.get("kind") or ["access"])[0] or "access"
    try:
        limit = int((qs.get("limit") or ["200"])[0])
    except (TypeError, ValueError):
        limit = 200
    ok_filter: Optional[bool] = None
    if qs.get("ok"):
        raw_ok = str((qs.get("ok") or [""])[0]).strip().lower()
        if raw_ok in {"1", "true", "yes"}:
            ok_filter = True
        elif raw_ok in {"0", "false", "no"}:
            ok_filter = False
    payload = weblog.tail(kind, limit=limit, ok=ok_filter)
    return _pack(200 if payload.get("ok") else 400, payload)


def _wall_body(raw: bytes) -> Dict[str, Any]:
    text = (raw or b"").decode("utf-8", "replace").strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}
    qs = parse_qs(text, keep_blank_values=True)
    return {key: (vals[0] if vals else "") for key, vals in qs.items()}


def handle_wall(
    method: str,
    token: str,
    cookie: Optional[str],
    body: bytes = b"",
    query_string: str = "",
    authorization: Optional[str] = None,
) -> HttpOut:
    user, denied = _need_user(cookie, authorization)
    if denied:
        return denied
    from ..wall import lists as wall_lists
    from ..wall import traffic as wall_traffic

    verb = (method or "GET").upper()
    rest = token[len("wall") :].lstrip("/")
    qs = parse_qs(query_string or "", keep_blank_values=True)
    if verb == "GET" and rest in {"", "list"}:
        kind = (qs.get("kind") or [""])[0].strip().lower() or None
        if kind and kind not in {"ip", "asn", "country"}:
            return _pack(400, {"ok": False, "error": "kind must be ip, asn, or country"})
        try:
            payload = wall_lists.snapshot(kind)
        except ValueError as exc:
            return _pack(400, {"ok": False, "error": str(exc)})
        return _pack(200, payload)
    if verb == "GET" and rest == "traffic":
        after = (qs.get("after") or [""])[0].strip() or None
        try:
            limit = int((qs.get("limit") or ["200"])[0])
        except (TypeError, ValueError):
            limit = 200
        rows = wall_traffic.tail(after=after, limit=limit)
        return _pack(200, {"ok": True, "rows": rows, "count": len(rows)})
    if verb == "GET" and rest == "challenge":
        after = (qs.get("after") or [""])[0].strip() or None
        try:
            limit = int((qs.get("limit") or ["200"])[0])
        except (TypeError, ValueError):
            limit = 200
        rows = wall_traffic.tail_challenge(after=after, limit=limit)
        return _pack(200, {"ok": True, "rows": rows, "count": len(rows)})
    if verb == "GET" and rest == "log":
        try:
            limit = int((qs.get("limit") or ["100"])[0])
        except (TypeError, ValueError):
            limit = 100
        cap = None if limit == 0 else max(limit, 0)
        path = wall_lists.default_lists_path()
        actions = wall_lists.read_actions(path, limit=cap)
        return _pack(
            200,
            {
                "ok": True,
                "path": wall_lists.actions_path(path),
                "count": len(actions),
                "actions": actions,
            },
        )
    if verb == "POST" and rest in {"allow", "block", "challenge", "remove"}:
        data = _wall_body(body)
        kind = str(data.get("kind") or "").strip().lower()
        value = data.get("value")
        try:
            if rest == "remove":
                payload = wall_lists.remove(kind, value, source="gui", note=data.get("note"))
            else:
                payload = wall_lists.add(rest, kind, value, source="gui", note=data.get("note"))
        except ValueError as exc:
            return _pack(400, {"ok": False, "error": str(exc)})
        envelope = dict(payload)
        envelope["kind"] = "wall"
        envelope["query"] = rest
        if envelope.get("ok"):
            _record(user or "", "/" + token, envelope)
        return _pack(200, payload)
    if rest:
        return _pack(404, {"ok": False, "error": "not found"})
    return _pack(405, {"ok": False, "error": "use GET or POST"})


def dispatch(
    method: str,
    token: str,
    cookie: Optional[str],
    body: bytes,
    scheme: Optional[str],
    query_string: str = "",
    visitor: Optional[str] = None,
    authorization: Optional[str] = None,
) -> Optional[HttpOut]:
    verb = (method or "GET").upper()
    if token == "login":
        if verb != "POST":
            return _pack(405, {"ok": False, "error": "use POST"})
        return handle_login(body, scheme, visitor)
    if token == "logout":
        if verb != "POST":
            return _pack(405, {"ok": False, "error": "use POST"})
        return handle_logout(cookie, scheme, authorization)
    if token == "session":
        if verb != "GET":
            return _pack(405, {"ok": False, "error": "use GET"})
        return handle_session(cookie, authorization)
    if token == "auth/keys" or token.startswith("auth/keys/"):
        return handle_auth_keys(method, token, cookie, body, authorization)
    if token in {"auth/password", "auth/password/clear"}:
        return handle_auth_password(method, token, cookie, body, authorization)
    if token == "docs":
        if verb != "POST":
            return None
        return handle_docs(method, cookie, authorization)
    if token == "logs" or token.startswith("logs/"):
        return handle_logs(method, token, cookie, query_string, authorization)
    if token == "history" or token.startswith("history/"):
        return handle_history(method, token, cookie, authorization)
    if token == "serve/start" or token == "serve/stop":
        return handle_serve(method, token, cookie, authorization)
    if token == "cache" or token.startswith("cache/"):
        return handle_cache(method, token, cookie, authorization)
    if token == "config":
        return handle_config(method, cookie, body, authorization)
    if token == "wall" or token.startswith("wall/"):
        return handle_wall(method, token, cookie, body, query_string, authorization)
    return None
