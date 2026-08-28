"""looking-glass CLI lines that match a GUI lookup path."""

from __future__ import annotations

from typing import List
from urllib.parse import parse_qs, unquote


def _tokens(path: str) -> List[str]:
    text = unquote(str(path or "")).split("?", 1)[0]
    return [part for part in text.strip("/").split("/") if part]


def wall_cli(path: str) -> str:
    """Return the `looking-glass` command that reproduces this HTTP lookup."""
    raw = str(path or "/")
    query = ""
    if "?" in raw:
        raw, query = raw.split("?", 1)
    qs = parse_qs(query, keep_blank_values=False)
    parts = _tokens(raw)
    if not parts:
        return "looking-glass ip"
    head = parts[0].lower()
    if head == "as" and len(parts) == 1:
        return "looking-glass asn"
    if head.startswith("as") and head[2:].isdigit():
        return f"looking-glass asn {head[2:]}"
    if head == "dns":
        name = parts[1] if len(parts) > 1 else "example.com"
        qtype = parts[2] if len(parts) > 2 else "A"
        server = (qs.get("server") or [None])[0]
        port = (qs.get("port") or [None])[0]
        bits = ["looking-glass", "dns"]
        if server:
            bits.append(f"@{server}" + (f":{port}" if port else ""))
        bits.append(name)
        if qtype and qtype.upper() != "A":
            bits.append(qtype)
        elif port and not server:
            bits.extend(["-p", port])
        return " ".join(bits)
    if head == "register":
        name = parts[1] if len(parts) > 1 else "example"
        bits = ["looking-glass", "register", name]
        tlds = ((qs.get("tlds") or [""])[0]).strip()
        if tlds:
            bits.extend(["--tlds", tlds])
        return " ".join(bits)
    mapping = {
        "dnssec": "dnssec",
        "tls": "tls",
        "apex": "apex",
        "ping": "ping",
        "traceroute": "traceroute",
        "mtr": "mtr",
        "tcptraceroute": "tcptraceroute",
        "rdap": "rdap",
        "whois": "whois",
        "reputation": "reputation",
        "bgp": "bgp",
        "dnstrace": "dnstrace",
        "http": "http",
        "ptr": "ptr",
        "mail": "mail",
        "tcp": "tcp",
        "pmtu": "pmtu",
    }
    if head in mapping:
        cmd = ["looking-glass", mapping[head]]
        if len(parts) > 1:
            cmd.append(parts[1])
        if head in {"tls", "tcptraceroute", "tcp"} and len(parts) > 2:
            cmd.extend(["-p", parts[2]])
        if head == "whois" and (qs.get("legacy") or [""])[0].lower() in {
            "1",
            "true",
            "yes",
            "legacy",
            "whois",
        }:
            cmd.append("--legacy")
        if head == "tls":
            sni = ((qs.get("sni") or [""])[0]).strip()
            if sni:
                cmd.extend(["--sni", sni])
        if head == "http":
            url_param = ((qs.get("url") or [""])[0]).strip()
            if url_param:
                return " ".join(["looking-glass", "http", url_param])
            extra = parts[1:]
            if extra and extra[0].lower() in {"http:", "https:"} and len(extra) > 1:
                target = extra[0] + "//" + "/".join(extra[1:])
            else:
                target = "/".join(extra) if extra else ""
            scheme = (qs.get("scheme") or [""])[0].lower()
            if scheme in {"http", "https"} and target and "://" not in target:
                target = f"{scheme}://{target}"
            return " ".join(["looking-glass", "http", target] if target else ["looking-glass", "http"])
        if head == "dnstrace" and len(parts) > 2:
            cmd = ["looking-glass", "dnstrace", parts[1], "-t", parts[2]]
            return " ".join(cmd)
        if head == "mtr":
            cycles = ((qs.get("cycles") or [""])[0]).strip()
            if cycles:
                cmd.extend(["--cycles", cycles])
        return " ".join(cmd)
    return f"looking-glass ip {parts[0]}"


def httpie_line(origin_url: str, path: str) -> str:
    origin_url = origin_url.rstrip("/")
    this = path if str(path).startswith("/") else f"/{path}"
    if this != "/":
        this = this.rstrip("/") or "/"
    host = origin_url.split("://", 1)[-1]
    prog = "https" if origin_url.startswith("https://") else "http"
    tail = "/" if this == "/" else this
    return f"{prog} {host}{tail} Accept:application/json"


def curl_line(origin_url: str, path: str) -> str:
    origin_url = origin_url.rstrip("/")
    this = path if str(path).startswith("/") else f"/{path}"
    if this != "/":
        this = this.rstrip("/") or "/"
    url = origin_url + ("/" if this == "/" else this)
    return f"curl -sS -H 'Accept: application/json' {url}"
