"""First-party proof-of-work challenge and IP-bound pass cookie."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs

from ..utility import get_data_dir
from .lists import default_lists_path
from ..auth.session import effective_scheme

COOKIE = "looking_glass_pass"
PATH = "/_wall/challenge"
DEFAULT_TTL_DAYS = 5
DEFAULT_BITS = 16
MIN_BITS = 8
MAX_BITS = 24
_TICKET_TTL_S = 15 * 60

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Checking your browser</title>
  <style nonce="__NONCE__">
    :root { color-scheme: dark; --bg:#0b0d10; --fg:#e8edf2; --muted:#8b98a5; --line:#243040; --accent:#7eb8ff; --ok:#8ee29a; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--fg);
      font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; }
    main { width: min(28rem, calc(100vw - 2rem)); border: 1px solid var(--line); border-radius: 14px; padding: 1.25rem 1.35rem; }
    h1 { margin: 0 0 0.35rem; font-size: 1.05rem; }
    p { margin: 0 0 0.85rem; color: var(--muted); font-size: 0.9rem; }
    .bar { height: 0.45rem; border-radius: 999px; background: rgb(255 255 255 / 8%); overflow: hidden; }
    .bar > span { display: block; height: 100%; width: 8%; background: var(--accent); transition: width 0.2s; }
    .bar.done > span { width: 100%; background: var(--ok); }
    .err { color: #ff8d8d; }
  </style>
</head>
<body>
  <main>
    <h1 id="title">Checking your browser</h1>
    <p id="msg">Solve a short puzzle to continue. This takes a moment.</p>
    <div class="bar" id="bar"><span></span></div>
  </main>
  <script nonce="__NONCE__">
    const payload = __PAYLOAD__;
    const bar = document.getElementById("bar");
    const fill = bar.firstElementChild;
    const msg = document.getElementById("msg");
    function bitsOk(bytes, bits) {
      let need = bits;
      for (const b of bytes) {
        if (need >= 8) { if (b !== 0) return false; need -= 8; continue; }
        return (b >> (8 - need)) === 0;
      }
      return need === 0;
    }
    async function digest(text) {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
      return new Uint8Array(buf);
    }
    async function solve() {
      const ticket = payload.ticket;
      const bits = payload.bits;
      const cap = 1 << Math.min(bits + 6, 26);
      for (let n = 0; n < cap; n++) {
        if ((n & 1023) === 0) fill.style.width = Math.min(92, (n / cap) * 100) + "%";
        if (bitsOk(await digest(ticket + ":" + n), bits)) return n;
      }
      throw new Error("puzzle");
    }
    async function run() {
      try {
        const counter = await solve();
        bar.classList.add("done");
        msg.textContent = "Verified. Continuing…";
        const res = await fetch(payload.path, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          body: JSON.stringify({ ticket: payload.ticket, counter: counter, next: payload.next })
        });
        const data = await res.json().catch(function () { return {}; });
        if (!res.ok || data.ok === false) throw new Error(data.error || "challenge");
        location.replace(data.next || payload.next || "/");
      } catch (err) {
        msg.className = "err";
        msg.textContent = "Could not verify this browser. Reload to try again.";
      }
    }
    run();
  </script>
</body>
</html>
"""


def secret_path(lists_path: Optional[str] = None) -> str:
    target = lists_path if lists_path else default_lists_path()
    directory = os.path.dirname(target) if target else ""
    if not directory:
        return os.path.join(get_data_dir(), "wall.key")
    return os.path.join(directory, "wall.key")


def load_secret(path: Optional[str] = None) -> bytes:
    dest = path or secret_path()
    try:
        raw = open(dest, "rb").read().strip()
        if raw:
            return raw
    except OSError:
        pass
    key = secrets.token_bytes(32)
    try:
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
    except FileExistsError:
        try:
            return open(dest, "rb").read().strip() or key
        except OSError:
            return key
    except OSError:
        return key
    return key


def clamp_bits(value: Any) -> int:
    try:
        bits = int(value)
    except (TypeError, ValueError):
        return DEFAULT_BITS
    return max(MIN_BITS, min(MAX_BITS, bits))


def ttl_seconds(days: Any) -> int:
    try:
        n = int(days)
    except (TypeError, ValueError):
        n = DEFAULT_TTL_DAYS
    if n < 1:
        n = DEFAULT_TTL_DAYS
    return n * 24 * 60 * 60


def _mac(secret: bytes, text: str) -> str:
    return hmac.new(secret, text.encode("utf-8"), hashlib.sha256).hexdigest()


def _safe_next(value: Any) -> str:
    text = str(value or "/").strip() or "/"
    if not text.startswith("/") or text.startswith("//") or "\\" in text:
        return "/"
    if text.startswith("/_wall/"):
        return "/"
    return text


def leading_zero_bits(digest: bytes, bits: int) -> bool:
    full, rem = divmod(int(bits), 8)
    if digest[:full] != b"\x00" * full:
        return False
    if rem == 0:
        return True
    if full >= len(digest):
        return False
    return digest[full] >> (8 - rem) == 0


def issue_ticket(ip: str, secret: bytes, bits: int = DEFAULT_BITS) -> Dict[str, Any]:
    nonce = secrets.token_urlsafe(16)
    ts = int(time.time())
    bits = clamp_bits(bits)
    mac = _mac(secret, f"{nonce}|{bits}|{ts}|{ip}")
    ticket = f"{nonce}.{bits}.{ts}.{mac}"
    return {"ticket": ticket, "nonce": nonce, "bits": bits, "ts": ts}


def parse_ticket(ticket: str) -> Optional[Tuple[str, int, int, str]]:
    parts = str(ticket or "").split(".")
    if len(parts) != 4:
        return None
    nonce, bits_s, ts_s, mac = parts
    if not nonce or not mac:
        return None
    try:
        bits = int(bits_s)
        ts = int(ts_s)
    except ValueError:
        return None
    return nonce, bits, ts, mac


def verify_ticket(ticket: str, ip: str, secret: bytes, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    parsed = parse_ticket(ticket)
    if parsed is None:
        return None
    nonce, bits, ts, mac = parsed
    stamp = now if now is not None else time.time()
    if stamp - ts > _TICKET_TTL_S or ts > stamp + 60:
        return None
    expect = _mac(secret, f"{nonce}|{bits}|{ts}|{ip}")
    if not hmac.compare_digest(mac, expect):
        return None
    return {"nonce": nonce, "bits": bits, "ts": ts, "ticket": ticket}


def solve_ticket(ticket: str, bits: int, limit: Optional[int] = None) -> int:
    bits = clamp_bits(bits)
    cap = int(limit) if limit is not None else (1 << min(bits + 6, 26))
    prefix = f"{ticket}:".encode("utf-8")
    for n in range(cap):
        digest = hashlib.sha256(prefix + str(n).encode("utf-8")).digest()
        if leading_zero_bits(digest, bits):
            return n
    raise ValueError("no solution")


def verify_solution(ticket: str, counter: Any, ip: str, secret: bytes) -> bool:
    parsed = verify_ticket(ticket, ip, secret)
    if parsed is None:
        return False
    try:
        n = int(counter)
    except (TypeError, ValueError):
        return False
    if n < 0:
        return False
    digest = hashlib.sha256(f"{ticket}:{n}".encode("utf-8")).digest()
    return leading_zero_bits(digest, parsed["bits"])


def cookie_value(ip: str, secret: bytes, ttl_s: int, now: Optional[float] = None) -> str:
    expiry = int((now if now is not None else time.time()) + ttl_s)
    mac = _mac(secret, f"{ip}|{expiry}")
    return f"{expiry}.{mac}"


def cookie_valid(header: Optional[str], ip: str, secret: bytes, now: Optional[float] = None) -> bool:
    token = parse_cookie(header)
    if not token:
        return False
    expiry_s, _, mac = token.partition(".")
    try:
        expiry = int(expiry_s)
    except ValueError:
        return False
    stamp = now if now is not None else time.time()
    if expiry <= stamp:
        return False
    expect = _mac(secret, f"{ip}|{expiry}")
    return hmac.compare_digest(mac, expect)


def parse_cookie(header: Optional[str]) -> Optional[str]:
    if not header:
        return None
    for part in str(header).split(";"):
        item = part.strip()
        if not item:
            continue
        name, _, value = item.partition("=")
        if name.strip() == COOKIE:
            token = value.strip()
            return token or None
    return None


def set_cookie_header(
    value: str,
    ttl_s: int,
    *,
    scheme: Optional[str] = None,
    forwarded: Optional[str] = None,
) -> str:
    secure = " Secure;" if effective_scheme(scheme, forwarded) == "https" else ""
    return f"{COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax;{secure} Max-Age={int(ttl_s)}"


def is_challenge_path(path: str) -> bool:
    token = (path or "").split("?", 1)[0].rstrip("/") or "/"
    return token == PATH


def parse_body(raw: bytes, content_type: str = "") -> Dict[str, Any]:
    text = (raw or b"").decode("utf-8", "replace").strip()
    if not text:
        return {}
    if "json" in (content_type or "").lower() or text.startswith("{"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}
    qs = parse_qs(text, keep_blank_values=True)
    return {key: (vals[0] if vals else "") for key, vals in qs.items()}


def page_html(ticket: Dict[str, Any], nxt: str, nonce: str = "") -> bytes:
    payload = {
        "ticket": ticket["ticket"],
        "bits": ticket["bits"],
        "path": PATH,
        "next": _safe_next(nxt),
    }
    blob = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    return (
        _HTML.replace("__PAYLOAD__", blob)
        .replace("__NONCE__", nonce or "")
        .encode("utf-8")
    )


def deny_json(meta: Dict[str, Any], nxt: str) -> Dict[str, Any]:
    body = {
        "ok": False,
        "decision": "challenge",
        "reason": meta.get("reason"),
        "challenge": PATH,
        "next": _safe_next(nxt),
    }
    for key in ("asn", "country", "entry"):
        value = meta.get(key)
        if value not in (None, "", []):
            body[key] = value
    return body
