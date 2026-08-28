"""Mail path: MX, SPF, DMARC, DKIM selectors, SMTP banner and STARTTLS."""

from __future__ import annotations

import asyncio
import smtplib
import socket
import ssl
import time
import urllib.parse
from typing import Any, Dict, List

COMMON_DKIM = ("default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail")


def is_null_mx(rows: List[Dict[str, Any]]) -> bool:
    """RFC 7505: sole MX with preference 0 and exchange the root (`.`)."""
    if len(rows) != 1:
        return False
    row = rows[0]
    pref = row.get("preference")
    host = str(row.get("host") or row.get("exchange") or "").strip().rstrip(".").lower()
    try:
        pref_n = int(pref) if pref is not None else None
    except (TypeError, ValueError):
        pref_n = None
    return pref_n == 0 and host == ""


def parse_mail_path(path: str) -> str:
    text = urllib.parse.unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "mail" and not text.startswith("mail/"):
        raise ValueError("not a mail path")
    rest = "" if text == "mail" else text[len("mail/") :]
    if not rest:
        raise ValueError("mail path needs a domain, e.g. /mail/example.com")
    return rest


def _txt(rows: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for row in rows or []:
        data = str(row.get("data") or "").strip().strip('"')
        if data:
            out.append(data.replace('" "', "").replace('"', ""))
    return out


async def _answers(name: str, qtype: str, timeout: float) -> List[Dict[str, Any]]:
    from ..dns.resolve import lookup_dns_async

    payload = await lookup_dns_async(name, qtype, timeout=timeout)
    return list((payload.get("result") or {}).get("answers") or [])


def _smtp_probe(host: str, port: int = 25, timeout: float = 6.0) -> Dict[str, Any]:
    banner = None
    ehlo = None
    starttls = False
    error = None
    elapsed_ms = None
    t0 = time.perf_counter()
    try:
        with smtplib.SMTP(timeout=timeout) as smtp:
            smtp._host = host
            code, msg = smtp.connect(host, port)
            banner = f"{code} {msg.decode('utf-8', 'replace') if isinstance(msg, bytes) else msg}".strip()
            code, msg = smtp.ehlo()
            ehlo = f"{code} {msg.decode('utf-8', 'replace') if isinstance(msg, bytes) else msg}".strip()
            starttls_offered = smtp.has_extn("starttls")
            if starttls_offered:
                ctx = ssl.create_default_context()
                smtp.starttls(context=ctx)
                smtp.ehlo()
                starttls = True
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        error = str(exc) or exc.__class__.__name__
        if banner is None:
            try:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    banner = sock.recv(512).decode("utf-8", "replace").strip()
            except Exception:
                pass
    return {
        "host": host,
        "port": port,
        "banner": banner,
        "ehlo": ehlo,
        "starttls": starttls,
        "error": error,
        "elapsed_ms": elapsed_ms,
    }


async def check_mail_async(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    from ..dns.resolve import normalize_qname

    start = time.time()
    try:
        name = normalize_qname(domain, qtype="MX").rstrip(".")
    except ValueError as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": 0.0}
    mx_rows = await _answers(name, "MX", timeout)
    mx = []
    for row in mx_rows:
        data = str(row.get("data") or "")
        bits = data.split(None, 1)
        pref = int(bits[0]) if bits and bits[0].isdigit() else None
        raw_host = bits[1].strip() if len(bits) > 1 else data
        if raw_host.rstrip(".") == "":
            host = "."
        else:
            host = raw_host.rstrip(".")
        mx.append({"preference": pref, "host": host, "ttl": row.get("ttl")})
    mx.sort(key=lambda row: (row["preference"] is None, row["preference"] or 0))
    spf = [line for line in _txt(await _answers(name, "TXT", timeout)) if line.lower().startswith("v=spf1")]
    dmarc = _txt(await _answers(f"_dmarc.{name}", "TXT", timeout))
    dkim: List[Dict[str, Any]] = []
    for selector in COMMON_DKIM:
        records = _txt(await _answers(f"{selector}._domainkey.{name}", "TXT", timeout))
        if records:
            dkim.append({"selector": selector, "records": records})
    smtp = None
    smtp_error = None
    null_mx = is_null_mx(mx)
    if mx and not null_mx:
        smtp = await asyncio.to_thread(_smtp_probe, mx[0]["host"], 25, max(timeout, 6.0))
        smtp_error = smtp.get("error")
    result = {
        "domain": name,
        "mx": mx,
        "null_mx": null_mx,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "smtp": smtp,
    }
    return {
        "ok": smtp_error is None,
        "result": result,
        "error": smtp_error,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


def check_mail(domain: str, timeout: float = 5.0) -> Dict[str, Any]:
    return asyncio.run(check_mail_async(domain, timeout=timeout))
