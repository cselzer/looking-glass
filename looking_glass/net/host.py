"""IPv6 literals, host:port display, and public-address preference."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any, List, Optional, Sequence, Tuple

_COLLAPSED_SLASH = re.compile(r"([a-z][a-z0-9+.-]*):/(?!/)", re.I)
_SCHEME_PREFIX = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)
_ASN_MAX = 4294967295


def restore_collapsed_slashes(text: str) -> str:
    """Undo proxy collapse of `https:/host` back to `https://host`."""
    return _COLLAPSED_SLASH.sub(r"\1://", str(text or ""))


def unbracket_host(value: str) -> str:
    """Strip one pair of RFC 3986 brackets from an IP literal."""
    text = str(value or "").strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        return text[1:-1]
    return text


def reject_bogus_ipv4(text: str) -> None:
    """Four decimal labels that are not a valid IPv4 are not a domain."""
    raw = unbracket_host(text).strip().rstrip(".")
    labels = raw.split(".")
    if len(labels) != 4 or not all(part.isdigit() for part in labels):
        return
    try:
        ipaddress.IPv4Address(raw)
    except ValueError as exc:
        raise ValueError("not a valid IPv4 address") from exc


def reject_url_as_host(text: str) -> None:
    """Host fields are hosts, not URLs."""
    raw = str(text or "").strip()
    if "://" in raw or raw.lower().startswith("//"):
        raise ValueError("host is not a URL")
    match = _SCHEME_PREFIX.match(raw)
    if not match:
        return
    rest = raw[match.end() :]
    if rest.isdigit():
        return
    try:
        ipaddress.ip_address(unbracket_host(raw.split("%", 1)[0]))
    except ValueError as exc:
        raise ValueError("host is not a URL") from exc


def reject_probe_target(host: str) -> None:
    """Probes do not take NULs, zone-ids, link-local, multicast, or IPv4 lookalikes."""
    if "\x00" in str(host or ""):
        raise ValueError("host is not a URL")
    text = unbracket_host(host).strip()
    if not text:
        raise ValueError("host is required")
    if "%" in text:
        raise ValueError("zone-id is not a probe target")
    reject_url_as_host(text)
    reject_bogus_ipv4(text)
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return
    if ip.is_link_local:
        raise ValueError("link-local is not a probe target")
    if ip.is_multicast:
        raise ValueError("multicast is not a probe target")


def parse_asn_number(text: str) -> int:
    raw = str(text or "")
    if raw != raw.strip():
        raise ValueError("ASN must be 1–4294967295")
    if raw.upper().startswith("AS"):
        raw = raw[2:]
    if not raw.isdigit():
        raise ValueError("ASN must be 1–4294967295")
    number = int(raw)
    if not 1 <= number <= _ASN_MAX:
        raise ValueError("ASN must be 1–4294967295")
    return number


def _port_int(raw: str) -> int:
    try:
        port = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port must be 1–65535")
    return port


def split_host_port(text: str, default_port: int = 443) -> Tuple[str, int]:
    """Split `host:port`, `[ipv6]:port`, or a bare host.

    Unbracketed IPv6 is a host with ``default_port``. An explicit port must
    be 1–65535.
    """
    raw = str(text or "").strip()
    if not raw:
        raise ValueError("host is required")
    if raw.startswith("["):
        close = raw.find("]")
        if close < 2:
            raise ValueError("invalid IPv6 literal")
        host = raw[1:close]
        rest = raw[close + 1 :]
        if not rest:
            return host, int(default_port)
        if not rest.startswith(":"):
            raise ValueError("invalid host:port")
        return host, _port_int(rest[1:])
    try:
        if ipaddress.ip_address(raw).version == 6:
            return raw, int(default_port)
    except ValueError:
        pass
    if ":" in raw:
        host, _, port_s = raw.rpartition(":")
        if not host:
            raise ValueError("host is required")
        return unbracket_host(host), _port_int(port_s)
    return unbracket_host(raw), int(default_port)


def is_ipv6_literal(value: str) -> bool:
    try:
        return ipaddress.ip_address(unbracket_host(value)).version == 6
    except ValueError:
        return False


def format_hostport(host: str, port: int) -> str:
    """RFC 3986 host:port — IPv6 is always [addr]:port."""
    ip = unbracket_host(host)
    try:
        if ipaddress.ip_address(ip).version == 6:
            return f"[{ip}]:{int(port)}"
    except ValueError:
        pass
    return f"{ip}:{int(port)}"


def bracket_host(host: str) -> str:
    ip = unbracket_host(host)
    try:
        if ipaddress.ip_address(ip).version == 6:
            return f"[{ip}]"
    except ValueError:
        pass
    return ip


def _usable_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    )


def pick_addrinfo(infos: Sequence[Any]) -> Any:
    """Prefer global unicast over link-local over loopback (nsswitch hosts)."""
    if not infos:
        raise socket.gaierror("getaddrinfo returned no addresses")
    ranked: List[Tuple[int, Any]] = []
    for info in infos:
        sockaddr = info[4]
        raw = str(sockaddr[0]).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            ranked.append((3, info))
            continue
        if addr.is_unspecified or addr.is_multicast:
            rank = 3
        elif addr.is_loopback:
            rank = 2
        elif addr.is_link_local:
            rank = 1
        else:
            rank = 0
        ranked.append((rank, info))
    ranked.sort(key=lambda row: row[0])
    return ranked[0][1]


def public_from_addrinfo(infos: Sequence[Any]) -> Optional[Tuple[str, int]]:
    """Public (ip, family) from getaddrinfo, or None if only loopback/link-local."""
    if not infos:
        return None
    info = pick_addrinfo(infos)
    ip = str(info[4][0]).split("%", 1)[0]
    if not _usable_public(ip):
        return None
    return ip, int(info[0])


def public_ip_from_addrinfo(infos: Sequence[Any]) -> Tuple[str, int]:
    """Return (ip, family) from getaddrinfo results, skipping loopback when possible."""
    public = public_from_addrinfo(infos)
    if public:
        return public
    info = pick_addrinfo(infos)
    ip = str(info[4][0]).split("%", 1)[0]
    return ip, int(info[0])


def dns_public_host(name: str, timeout: float = 2.0) -> Optional[Tuple[str, int]]:
    """A/AAAA via resolv.conf nameservers, ignoring /etc/hosts (nsswitch files)."""
    host = unbracket_host(str(name or "")).rstrip(".")
    if not host:
        return None
    try:
        import dns.resolver
    except ImportError:
        return None
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = timeout

    def _answers(qtype: str) -> List[str]:
        try:
            found = resolver.resolve(host, qtype, search=False)
        except Exception:
            return []
        out: List[str] = []
        for rr in found:
            text = str(rr).split("%", 1)[0]
            if _usable_public(text):
                out.append(text)
        return out

    v4 = _answers("A")
    if v4:
        return v4[0], socket.AF_INET
    v6 = _answers("AAAA")
    if v6:
        return v6[0], socket.AF_INET6
    return None


def resolve_probe_host(
    name: str,
    *,
    port: Optional[int] = None,
    socktype: int = socket.SOCK_STREAM,
) -> Tuple[str, int, Any]:
    """Prefer a public A/AAAA over a Debian 127.0.1.1 hosts alias.

    Returns (ip, family, sockaddr) suitable for connect(). Explicit loopback
    literals are kept; names that only resolve via nsswitch files fall back to DNS.
    """
    host = unbracket_host(str(name or "")).strip().rstrip(".")
    try:
        parsed = ipaddress.ip_address(host)
        ip = str(parsed)
        family = socket.AF_INET if parsed.version == 4 else socket.AF_INET6
        infos = socket.getaddrinfo(ip, port, family=family, type=socktype)
        info = pick_addrinfo(infos)
        return ip, family, info[4]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, port, type=socktype)
    public = public_from_addrinfo(infos)
    if public is None:
        dns = dns_public_host(host)
        if dns is not None:
            ip, family = dns
            infos = socket.getaddrinfo(ip, port, family=family, type=socktype)
            info = pick_addrinfo(infos)
            return ip, family, info[4]
    info = pick_addrinfo(infos)
    ip = str(info[4][0]).split("%", 1)[0]
    return ip, int(info[0]), info[4]
