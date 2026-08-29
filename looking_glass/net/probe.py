"""Pure-Python path probes: ICMP ping, traceroute, and MTR.

No ping(8), traceroute(8), or mtr(8). Echo requests are RFC 792 ICMP
(RFC 4443 for IPv6). Traceroute raises TTL/hop-limit; MTR repeats that
and aggregates loss and RTT like mtr --report.

Sockets: ICMP datagram (unprivileged ping socket) when the OS allows it,
otherwise SOCK_RAW. Traceroute/MTR send connected UDP (SOCK_DGRAM) with
IP_TTL and IP_RECVERR, then recvmsg MSG_ERRQUEUE for ICMP time-exceeded
(the hop's address is SO_EE_OFFENDER). That is unprivileged and matches
modern traceroute(8). Do not recvfrom waiting for a UDP payload — hops
do not speak UDP. Linux poll reports POLLERR for the error queue even
though POLLERR is ignored in the event mask; select() exceptfds is
POLLPRI and will miss those ICMP errors. TCP connect on 443 is dest-only
(ping and tcptraceroute). Hop rows are enriched with ASN, org, country,
flag, and PTR from the intel server.
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import os
import random
import re
import select
import socket
import statistics
import struct
import sys
import time
try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol, Tuple
from urllib.parse import unquote

from .host import dns_public_host, public_from_addrinfo, public_ip_from_addrinfo, reject_probe_target, unbracket_host

TOOLS = ("ping", "traceroute", "mtr")
_UDP_BASE_PORT = 33434
PING_COUNT = 4
PING_TIMEOUT = 1.0
TRACE_MAX_HOPS = 30
TRACE_TIMEOUT = 1.0
TRACE_STOP_TIMEOUTS = 5
TRACE_PROBES = 3
TRACE_NQUERIES = 16  # traceroute(8) -N: probe packets in flight
MTR_CYCLES = 10
MTR_HARD_CEILING = 50
MTR_TIMEOUT = 1.0
MTR_STOP_TIMEOUTS = 5

ICMP_ECHO = 8
ICMP_ECHOREPLY = 0
ICMP_UNREACH = 3
ICMP_TIMXCEED = 11
ICMP6_ECHO = 128
ICMP6_ECHOREPLY = 129
ICMP6_UNREACH = 1
ICMP6_TIMXCEED = 3

# linux/in.h, linux/in6.h, bits/socket.h. CPython exports these only in 3.14+.
_LINUX_IP_RECVERR = 11
_LINUX_IPV6_RECVERR = 25
_LINUX_MSG_ERRQUEUE = 0x2000


def _linux_ip_recverr() -> Optional[int]:
    opt = getattr(socket, "IP_RECVERR", None)
    if opt is not None:
        return int(opt)
    if sys.platform.startswith("linux"):
        return _LINUX_IP_RECVERR
    return None


def _linux_ipv6_recverr() -> Optional[int]:
    opt = getattr(socket, "IPV6_RECVERR", None)
    if opt is not None:
        return int(opt)
    if sys.platform.startswith("linux"):
        return _LINUX_IPV6_RECVERR
    return None


def _msg_errqueue() -> Optional[int]:
    opt = getattr(socket, "MSG_ERRQUEUE", None)
    if opt is not None:
        return int(opt)
    if sys.platform.startswith("linux"):
        return _LINUX_MSG_ERRQUEUE
    return None


def parse_probe_path(path: str) -> Tuple[str, str]:
    """Parse /ping/<target>, /traceroute/<target>, or /mtr/<target>."""
    text = unquote(str(path or "")).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    for tool in TOOLS:
        if text == tool:
            raise ValueError(f"{tool} path needs a host, e.g. /{tool}/1.1.1.1")
        prefix = f"{tool}/"
        if text.startswith(prefix):
            rest = text[len(prefix) :]
            if not rest:
                raise ValueError(f"{tool} path needs a host, e.g. /{tool}/1.1.1.1")
            if "/" in rest and not (rest.startswith("[") and "]" in rest):
                raise ValueError(f"{tool} path needs a host, e.g. /{tool}/1.1.1.1")
            host = unbracket_host(rest)
            reject_probe_target(host)
            return tool, host
    raise ValueError("not a ping, traceroute, or mtr path")


def tcp_trace_has_encoded_slash(raw_path: str) -> bool:
    """True when the request-target still has %2F in the tcptraceroute tail."""
    text = str(raw_path or "").split("?", 1)[0]
    lower = text.lower()
    marker = "tcptraceroute/"
    idx = lower.find(marker)
    if idx < 0:
        return False
    return "%2f" in lower[idx + len(marker) :]


def parse_tcp_trace_path(path: str) -> Tuple[str, int]:
    """Parse /tcptraceroute/<host> or /tcptraceroute/<host>/<port>."""
    text = str(path or "")
    if text.startswith("/"):
        text = text[1:]
    segs = text.split("/")
    if segs and segs[-1] == "":
        segs = segs[:-1]
    if not segs or segs[0] != "tcptraceroute":
        raise ValueError("not a tcptraceroute path")
    rest = segs[1:]
    if not rest:
        raise ValueError("tcptraceroute path needs a host, e.g. /tcptraceroute/1.1.1.1/443")
    if len(rest) > 2:
        raise ValueError("tcptraceroute path is /tcptraceroute/<host> or /tcptraceroute/<host>/<port>")
    host = unquote(rest[0])
    if "/" in host:
        raise ValueError("tcptraceroute path needs a host, e.g. /tcptraceroute/1.1.1.1/443")
    host = unbracket_host(host)
    port = 443
    if len(rest) == 2:
        try:
            port = int(unquote(rest[1]))
        except ValueError as exc:
            raise ValueError("tcptraceroute port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("tcptraceroute port must be 1–65535")
    if not host:
        raise ValueError("tcptraceroute path needs a host, e.g. /tcptraceroute/1.1.1.1/443")
    reject_probe_target(host)
    return host, port


def internet_checksum(data: bytes) -> int:
    """RFC 1071 ones-complement checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _bare_ip(addr: str) -> str:
    text = str(addr or "")
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    return text.split("%", 1)[0]


def _dest(ip: str, family: int, port: int = 0) -> Tuple[Any, ...]:
    if family == socket.AF_INET:
        return (ip, port)
    return (ip, port, 0, 0)


def _set_hops(sock: socket.socket, family: int, ttl: int) -> None:
    if family == socket.AF_INET:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, int(ttl))
        return
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, int(ttl))


def _enable_recverr(sock: socket.socket, family: int) -> bool:
    if family == socket.AF_INET:
        opt = _linux_ip_recverr()
        if opt is None:
            return False
        try:
            sock.setsockopt(socket.IPPROTO_IP, opt, 1)
            return True
        except OSError:
            return False
    opt = _linux_ipv6_recverr()
    if opt is None:
        return False
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, opt, 1)
        return True
    except OSError:
        return False


def apply_icmp6_checksum(packet: bytes, src: str, dst: str) -> bytes:
    """RFC 4443 ICMPv6 checksum over the IPv6 pseudo-header."""
    src_b = socket.inet_pton(socket.AF_INET6, _bare_ip(src))
    dst_b = socket.inet_pton(socket.AF_INET6, _bare_ip(dst))
    body = bytearray(packet)
    body[2:4] = b"\x00\x00"
    pseudo = src_b + dst_b + struct.pack("!I", len(body)) + b"\x00\x00\x00" + bytes([58]) + bytes(body)
    return bytes(body[:2] + struct.pack("!H", internet_checksum(pseudo)) + body[4:])


def build_echo(
    family: int,
    ident: int,
    seq: int,
    payload: bytes,
    *,
    src: Optional[str] = None,
    dst: Optional[str] = None,
) -> bytes:
    icmp_type = ICMP_ECHO if family == socket.AF_INET else ICMP6_ECHO
    header = struct.pack("!BBHHH", icmp_type, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    packet = header + payload
    if family == socket.AF_INET:
        cksum = internet_checksum(packet)
        packet = struct.pack("!BBHHH", icmp_type, 0, cksum, ident & 0xFFFF, seq & 0xFFFF) + payload
    elif src and dst:
        packet = apply_icmp6_checksum(packet, src, dst)
    return packet


def _ip_payload(packet: bytes) -> Tuple[bytes, Optional[str]]:
    """Strip an IPv4/IPv6 header if present. Return (icmp, ip_src_from_header)."""
    if len(packet) < 8:
        return packet, None
    ver = packet[0] >> 4
    if ver == 4 and len(packet) >= 20:
        ihl = (packet[0] & 0x0F) * 4
        if ihl >= 20 and len(packet) >= ihl + 8:
            src = socket.inet_ntop(socket.AF_INET, packet[12:16])
            return packet[ihl:], src
    if ver == 6 and len(packet) >= 48:
        src = socket.inet_ntop(socket.AF_INET6, packet[8:24])
        return packet[40:], src
    return packet, None


def parse_icmp(family: int, packet: bytes, from_addr: Any) -> Optional[Dict[str, Any]]:
    """Parse an echo reply, time-exceeded, or unreachable that wraps our echo."""
    icmp, hdr_src = _ip_payload(packet)
    if len(icmp) < 8:
        return None
    icmp_type, code = icmp[0], icmp[1]
    hop = hdr_src
    if not hop:
        hop = from_addr[0] if from_addr else None
    echo_type = ICMP_ECHO if family == socket.AF_INET else ICMP6_ECHO
    reply_type = ICMP_ECHOREPLY if family == socket.AF_INET else ICMP6_ECHOREPLY
    exceed_type = ICMP_TIMXCEED if family == socket.AF_INET else ICMP6_TIMXCEED
    unreach_type = ICMP_UNREACH if family == socket.AF_INET else ICMP6_UNREACH

    if icmp_type == reply_type:
        ident, seq = struct.unpack("!HH", icmp[4:8])
        return {"kind": "reply", "ident": ident, "seq": seq, "addr": hop, "code": code}
    if icmp_type in (exceed_type, unreach_type):
        inner, _inner_src = _ip_payload(icmp[8:])
        if len(inner) < 8:
            return {
                "kind": "ttl" if icmp_type == exceed_type else "unreach",
                "ident": None,
                "seq": None,
                "addr": hop,
                "code": code,
            }
        if inner[0] == echo_type:
            ident, seq = struct.unpack("!HH", inner[4:8])
        else:
            ident, seq = None, None
        return {
            "kind": "ttl" if icmp_type == exceed_type else "unreach",
            "ident": ident,
            "seq": seq,
            "addr": hop,
            "code": code,
        }
    return None


def guard_ip(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.is_multicast or ip.is_unspecified:
        raise ValueError("cannot probe multicast or unspecified addresses")
    return str(ip)


def _stdev(samples: List[float]) -> Optional[float]:
    if len(samples) < 2:
        return 0.0 if samples else None
    return round(statistics.pstdev(samples), 3)


@dataclass
class ProbeHit:
    kind: str  # reply, ttl, unreach, timeout
    addr: Optional[str]
    rtt_ms: Optional[float]
    seq: int
    ttl: int
    error: Optional[str] = None
    via: str = "icmp"


def probe_matches(parsed: Optional[Dict[str, Any]], ident: int, seq: int, *, dgram: bool) -> bool:
    """Linux ping sockets rewrite ICMP ident; match seq (and ident only on raw sockets)."""
    if not parsed:
        return False
    got_seq = parsed.get("seq")
    got_id = parsed.get("ident")
    if got_seq not in (None, seq):
        return False
    if dgram:
        return True
    return got_id in (None, ident)


class ProbeEngine(Protocol):
    async def resolve(self, target: str) -> Tuple[str, int, str]:
        """Return (ip, family, queried_name)."""

    async def echo(
        self,
        ip: str,
        family: int,
        *,
        ttl: int,
        ident: int,
        seq: int,
        timeout: float,
        payload: bytes,
    ) -> ProbeHit:
        ...


TCP_PORTS = (443, 80, 53)


def _errno(exc: BaseException) -> Optional[int]:
    err = getattr(exc, "errno", None)
    if err is not None:
        return int(err)
    inner = getattr(exc, "__cause__", None) or getattr(exc, "os_error", None)
    return getattr(inner, "errno", None)


class SocketEngine:
    """ICMP echo (blocking sockets in a worker thread) plus TCP/UDP fallbacks."""

    def _open(self, family: int, *, raw: bool = False) -> Tuple[socket.socket, int]:
        proto = socket.IPPROTO_ICMP if family == socket.AF_INET else socket.IPPROTO_ICMPV6
        last: Optional[BaseException] = None
        kinds = (socket.SOCK_RAW,) if raw else (socket.SOCK_DGRAM, socket.SOCK_RAW)
        for sock_kind in kinds:
            try:
                sock = socket.socket(family, sock_kind, proto)
            except OSError as exc:
                last = exc
                continue
            try:
                if family == socket.AF_INET:
                    sock.bind(("", 0))
                else:
                    sock.bind(("::", 0, 0, 0))
            except OSError:
                pass
            return sock, sock_kind
        raise PermissionError(
            "ICMP sockets are not available (need an unprivileged ping socket or CAP_NET_RAW). "
            "This probe is Python ICMP, not ping(8)."
        ) from last

    async def resolve(self, target: str) -> Tuple[str, int, str]:
        text = unbracket_host(str(target).strip())
        try:
            ip = guard_ip(text)
            family = socket.AF_INET if ipaddress.ip_address(ip).version == 4 else socket.AF_INET6
            return ip, family, ip
        except ValueError as exc:
            if "multicast" in str(exc) or "unspecified" in str(exc):
                raise
        infos = await asyncio.get_running_loop().getaddrinfo(
            text.rstrip("."),
            None,
            type=socket.SOCK_DGRAM,
        )
        if not infos:
            raise ValueError(f"could not resolve {text}")
        if public_from_addrinfo(infos) is None:
            dns = await asyncio.to_thread(dns_public_host, text.rstrip("."))
            if dns is not None:
                return dns[0], dns[1], text.rstrip(".")
        ip, family = public_ip_from_addrinfo(infos)
        return ip, family, text.rstrip(".")

    async def echo(
        self,
        ip: str,
        family: int,
        *,
        ttl: int,
        ident: int,
        seq: int,
        timeout: float,
        payload: bytes,
    ) -> ProbeHit:
        try:
            return await asyncio.to_thread(
                self._echo_sync, ip, family, ttl, ident, seq, timeout, payload
            )
        except PermissionError:
            raise
        except OSError as exc:
            return ProbeHit("timeout", None, None, seq, ttl, str(exc) or "network error")

    def _echo_sync(
        self,
        ip: str,
        family: int,
        ttl: int,
        ident: int,
        seq: int,
        timeout: float,
        payload: bytes,
        raw: bool = False,
    ) -> ProbeHit:
        sock, sock_kind = self._open(family, raw=raw)
        dgram = sock_kind == socket.SOCK_DGRAM
        try:
            try:
                port = sock.getsockname()[1]
                if dgram and port:
                    ident = int(port) & 0xFFFF
            except OSError:
                pass
            _set_hops(sock, family, ttl)
            dest = _dest(ip, family)
            packet = build_echo(family, ident, seq, payload)
            if family == socket.AF_INET6:
                try:
                    sock.connect(dest)
                    packet = apply_icmp6_checksum(packet, sock.getsockname()[0], ip)
                except OSError:
                    pass
            sock.settimeout(max(timeout, 0.05))
            t0 = time.perf_counter()
            sock.sendto(packet, dest)
            while True:
                remaining = timeout - (time.perf_counter() - t0)
                if remaining <= 0:
                    return ProbeHit("timeout", None, None, seq, ttl, "timeout")
                sock.settimeout(max(remaining, 0.01))
                try:
                    data, addr = sock.recvfrom(4096)
                except (socket.timeout, TimeoutError, BlockingIOError):
                    return ProbeHit("timeout", None, None, seq, ttl, "timeout")
                except OSError as exc:
                    return ProbeHit("timeout", None, None, seq, ttl, str(exc) or "timeout")
                parsed = parse_icmp(family, data, addr)
                if not probe_matches(parsed, ident, seq, dgram=dgram):
                    continue
                rtt = round((time.perf_counter() - t0) * 1000.0, 3)
                kind = parsed["kind"]
                hop = parsed.get("addr")
                if kind == "reply":
                    return ProbeHit("reply", hop or ip, rtt, seq, ttl, via="icmp")
                if kind == "ttl":
                    return ProbeHit("ttl", hop, rtt, seq, ttl, via="icmp")
                if kind == "unreach":
                    return ProbeHit("unreach", hop or ip, rtt, seq, ttl, via="icmp")
        finally:
            sock.close()
        return ProbeHit("timeout", None, None, seq, ttl, "timeout")

    async def echo_or_udp(
        self,
        ip: str,
        family: int,
        *,
        ttl: int,
        ident: int,
        seq: int,
        timeout: float,
        payload: bytes,
    ) -> ProbeHit:
        """UDP traceroute hop, or ICMP/TCP race when pinging (ttl >= 64).

        Traceroute and MTR send UDP only — no TCP SYN/443 race and no
        parallel ICMP-echo TTL probe. Ping still uses ``_ping_with_tcp``.
        """
        if ttl >= 64:
            return await self._ping_with_tcp(
                ip, family, ttl=ttl, ident=ident, seq=seq, timeout=timeout, payload=payload
            )
        return await asyncio.to_thread(_udp_probe_wait, ip, ttl, seq, timeout, family)

    async def _ping_with_tcp(
        self,
        ip: str,
        family: int,
        *,
        ttl: int,
        ident: int,
        seq: int,
        timeout: float,
        payload: bytes,
    ) -> ProbeHit:
        """Race ICMP with TCP so a filtered ping socket does not wait the full timeout."""

        async def icmp_hit() -> ProbeHit:
            try:
                return await self.echo(
                    ip, family, ttl=ttl, ident=ident, seq=seq, timeout=timeout, payload=payload
                )
            except PermissionError:
                return ProbeHit("timeout", None, None, seq, ttl, "timeout")

        icmp_task = asyncio.create_task(icmp_hit())
        tcp_task = asyncio.create_task(
            asyncio.to_thread(_tcp_probe_sync, ip, family, ttl, seq, timeout, (443,))
        )
        pending = {icmp_task, tcp_task}
        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    if task.cancelled():
                        continue
                    if task.exception() is not None:
                        continue
                    hit = task.result()
                    if hit.kind != "timeout":
                        for other in pending:
                            other.cancel()
                        return hit
            return ProbeHit("timeout", None, None, seq, ttl, "timeout")
        finally:
            for task in (icmp_task, tcp_task):
                if not task.done():
                    task.cancel()

    async def echo_tcp(
        self,
        ip: str,
        family: int,
        *,
        ttl: int,
        ident: int,
        seq: int,
        timeout: float,
        payload: bytes,
        port: int,
    ) -> ProbeHit:
        return await asyncio.to_thread(
            _tcp_probe_sync, ip, family, ttl, seq, timeout, (int(port),)
        )


def _tcp_probe_sync(
    ip: str,
    family: int,
    ttl: int,
    seq: int,
    timeout: float,
    ports: Optional[Tuple[int, ...]] = None,
) -> ProbeHit:
    """SYN RTT: connect or RST both mean the host (or a hop) answered."""
    ports = ports or TCP_PORTS
    per_port = max(timeout / max(len(ports), 1), 0.25) if len(ports) > 1 else timeout
    last_err = "timeout"
    for port in ports:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            _set_hops(sock, family, ttl)
            _enable_recverr(sock, family)
            sock.settimeout(per_port)
            dest = _dest(ip, family, port)
            t0 = time.perf_counter()
            try:
                sock.connect(dest)
                rtt = round((time.perf_counter() - t0) * 1000.0, 3)
                return ProbeHit("reply", ip, rtt, seq, ttl, via="tcp")
            except ConnectionRefusedError:
                rtt = round((time.perf_counter() - t0) * 1000.0, 3)
                return ProbeHit("reply", ip, rtt, seq, ttl, via="tcp")
            except (socket.timeout, TimeoutError, asyncio.TimeoutError):
                last_err = "timeout"
                hop = _errqueue_hop(sock, ip)
                if hop:
                    rtt = round((time.perf_counter() - t0) * 1000.0, 3)
                    kind = "reply" if hop == ip else "ttl"
                    return ProbeHit(kind, hop, rtt, seq, ttl, via="tcp")
                continue
            except OSError as exc:
                err = _errno(exc)
                rtt = round((time.perf_counter() - t0) * 1000.0, 3)
                hop = _errqueue_hop(sock, ip)
                if err in {errno.ECONNREFUSED}:
                    return ProbeHit("reply", hop or ip, rtt, seq, ttl, via="tcp")
                if ttl < 64 and err in {
                    errno.EHOSTUNREACH,
                    errno.ENETUNREACH,
                    errno.ECONNRESET,
                    errno.ETIMEDOUT,
                }:
                    if hop == ip:
                        return ProbeHit("reply", hop, rtt, seq, ttl, via="tcp")
                    return ProbeHit("ttl", hop, rtt, seq, ttl, via="tcp")
                last_err = errno.errorcode.get(err, str(exc)) if err else (str(exc) or "timeout")
                continue
        finally:
            sock.close()
    return ProbeHit("timeout", None, None, seq, ttl, last_err, via="tcp")


def _errqueue_hop(sock: socket.socket, dest: str) -> Optional[str]:
    hop, _kind = _read_udp_error(sock, dest)
    return hop


ICMP6_UNREACH_PORT = 4


def _udp_err_poll_mask() -> int:
    """MSG_ERRQUEUE is POLLPRI/exceptfds. Linux poll ignores POLLERR in events."""
    mask = select.POLLIN
    pri = getattr(select, "POLLPRI", 0)
    if pri:
        mask |= pri
    return mask


def _open_raw_icmp(family: int) -> Optional[socket.socket]:
    proto = socket.IPPROTO_ICMP if family == socket.AF_INET else socket.IPPROTO_ICMPV6
    try:
        sock = socket.socket(family, socket.SOCK_RAW, proto)
    except OSError:
        return None
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    except OSError:
        pass
    return sock


def _quoted_udp_ports(family: int, quoted: bytes) -> Optional[Tuple[int, int]]:
    """Sport/dport from the IP+UDP header quoted in ICMP time-exceeded."""
    if family == socket.AF_INET:
        if len(quoted) < 20 or quoted[0] >> 4 != 4:
            return None
        ihl = (quoted[0] & 0x0F) * 4
        if quoted[9] != 17 or len(quoted) < ihl + 4:
            return None
        return struct.unpack("!HH", quoted[ihl : ihl + 4])
    if len(quoted) < 44 or quoted[0] >> 4 != 6:
        return None
    if quoted[6] != 17:
        return None
    return struct.unpack("!HH", quoted[40:44])


def _match_udp_trace(
    family: int,
    data: bytes,
    from_addr: Any,
    dest: str,
    sport: int,
    dport: int,
) -> Optional[Tuple[str, Optional[str]]]:
    """Match an ICMP time-exceeded / port-unreach to our UDP probe."""
    icmp, hdr_src = _ip_payload(data)
    if len(icmp) < 8:
        return None
    hop = hdr_src or (from_addr[0] if from_addr else None)
    icmp_type, code = icmp[0], icmp[1]
    if family == socket.AF_INET:
        exceed, unreach, port_code = ICMP_TIMXCEED, ICMP_UNREACH, ICMP_UNREACH_PORT
    else:
        exceed, unreach, port_code = ICMP6_TIMXCEED, ICMP6_UNREACH, ICMP6_UNREACH_PORT
    if icmp_type not in {exceed, unreach}:
        return None
    ports = _quoted_udp_ports(family, icmp[8:])
    if ports is None or ports != (sport, dport):
        return None
    if icmp_type == exceed:
        return "ttl", hop
    if code == port_code or hop == dest:
        return "reply", hop or dest
    return "unreach", hop


def _icmp_ttl_probe_sync(
    ip: str,
    family: int,
    ttl: int,
    ident: int,
    seq: int,
    timeout: float,
    payload: bytes,
) -> ProbeHit:
    """traceroute -I: SOCK_RAW ICMP echo with TTL. Ping datagram sockets cannot do this."""
    try:
        return SocketEngine()._echo_sync(
            ip, family, ttl, ident, seq, timeout, payload, raw=True
        )
    except PermissionError:
        return ProbeHit("timeout", None, None, seq, ttl, "timeout", via="icmp")


def _udp_probe_wait(
    ip: str, ttl: int, seq: int, timeout: float, family: int = socket.AF_INET
) -> ProbeHit:
    """tracepath(8): connected UDP + IP_RECVERR, recvmsg MSG_ERRQUEUE.

    connect() is required so the kernel queues ICMP time-exceeded on this
    socket. Wait with poll() so POLLERR (error queue) wakes us — select()
    exceptfds is POLLPRI and misses those ICMP errors. Do not recvfrom a
    UDP payload; hops send ICMP, not UDP. No SOCK_RAW.
    """
    if _msg_errqueue() is None:
        return ProbeHit("timeout", None, None, seq, ttl, "timeout", via="udp")
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if not _enable_recverr(sock, family):
            return ProbeHit("timeout", None, None, seq, ttl, "timeout", via="udp")
        try:
            _set_hops(sock, family, ttl)
        except OSError:
            return ProbeHit("timeout", None, None, seq, ttl, "timeout", via="udp")
        try:
            if family == socket.AF_INET:
                sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 3)
        except OSError:
            pass
        port = _UDP_BASE_PORT + (int(seq) % 256)
        sock.connect(_dest(ip, family, port))
        t0 = time.perf_counter()
        try:
            sock.send(b"\x00" * 32)
        except OSError:
            hop, kind = _read_udp_error(sock, ip)
            if kind:
                rtt = round((time.perf_counter() - t0) * 1000.0, 3)
                return ProbeHit(kind, hop, rtt, seq, ttl, via="udp")
        sock.setblocking(False)
        deadline = t0 + timeout

        def _hit(kind: str, hop: Optional[str]) -> ProbeHit:
            rtt = round((time.perf_counter() - t0) * 1000.0, 3)
            return ProbeHit(kind, hop, rtt, seq, ttl, via="udp")

        poller = select.poll()
        poller.register(sock, _udp_err_poll_mask())
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                hop, kind = _read_udp_error(sock, ip)
                if kind:
                    return _hit(kind, hop)
                return ProbeHit("timeout", None, None, seq, ttl, "timeout", via="udp")
            hop, kind = _read_udp_error(sock, ip)
            if kind:
                return _hit(kind, hop)
            try:
                events = poller.poll(max(int(remaining * 1000), 1))
            except (OSError, ValueError):
                continue
            hop, kind = _read_udp_error(sock, ip)
            if kind:
                return _hit(kind, hop)
            if not events:
                hop, kind = _read_udp_error(sock, ip)
                if kind:
                    return _hit(kind, hop)
                return ProbeHit("timeout", None, None, seq, ttl, "timeout", via="udp")
    finally:
        sock.close()
    return ProbeHit("timeout", None, None, seq, ttl, "timeout", via="udp")


def _trace_probe_sync(
    ip: str,
    family: int,
    ttl: int,
    ident: int,
    seq: int,
    timeout: float,
    payload: bytes,
) -> ProbeHit:
    """Sync fallback used by tests and IPv6. Prefer ICMP -I, then UDP."""
    icmp = _icmp_ttl_probe_sync(ip, family, ttl, ident, seq, timeout, payload)
    if icmp.kind != "timeout":
        return icmp
    return _udp_probe_wait(ip, ttl, seq, timeout, family)


def _udp_ttl_probe_sync(
    ip: str, ttl: int, seq: int, timeout: float, family: int = socket.AF_INET
) -> Optional[ProbeHit]:
    """Same unprivileged UDP+errqueue path as traceroute/MTR."""
    if _msg_errqueue() is None:
        return None
    return _udp_probe_wait(ip, ttl, seq, timeout, family)


def _read_udp_error(sock: socket.socket, dest: str) -> Tuple[Optional[str], Optional[str]]:
    """Drain ICMP time-exceeded / port-unreach from MSG_ERRQUEUE.

    Same recv as TCP traceroute (``_errqueue_hop``). Never recvfrom — UDP
    hops do not return a payload; the hop IP is SO_EE_OFFENDER.
    """
    flags = _msg_errqueue()
    if flags is None:
        return None, None
    try:
        _data, anc, _flags, addr = sock.recvmsg(4096, 4096, flags)
    except (BlockingIOError, InterruptedError, OSError):
        return None, None
    return _parse_errqueue(anc, addr, dest)


SO_EE_ORIGIN_ICMP = 2
SO_EE_ORIGIN_ICMP6 = 3
ICMP_UNREACH_PORT = 3


def _offender_ip(data: bytes) -> Optional[str]:
    """SO_EE_OFFENDER: sockaddr immediately after sock_extended_err (16 bytes)."""
    if len(data) < 18:
        return None
    family = struct.unpack_from("@H", data, 16)[0]
    if family == socket.AF_INET and len(data) >= 24:
        hop = socket.inet_ntop(socket.AF_INET, data[20:24])
        return hop if hop and hop != "0.0.0.0" else None
    if family == socket.AF_INET6 and len(data) >= 40:
        hop = socket.inet_ntop(socket.AF_INET6, data[24:40])
        return hop if hop and hop != "::" else None
    return None


def _parse_errqueue(
    anc: List[Tuple[int, int, bytes]], addr: Any, dest: str
) -> Tuple[Optional[str], Optional[str]]:
    recv_err = _linux_ip_recverr() or _LINUX_IP_RECVERR
    recv_err6 = _linux_ipv6_recverr() or _LINUX_IPV6_RECVERR
    for level, typ, data in anc:
        if typ not in {recv_err, recv_err6} and not (
            level in (getattr(socket, "SOL_IP", 0), socket.IPPROTO_IP, socket.IPPROTO_IPV6)
            and typ == recv_err
        ):
            continue
        if len(data) < 16:
            continue
        _ee_errno, origin, ee_type, ee_code, _pad, _info, _data = struct.unpack_from(
            "@IBBBBII", data, 0
        )
        hop = _offender_ip(data)
        if not hop and addr:
            hop = addr[0]
        if origin not in {0, SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6} and not hop:
            continue
        v6 = typ == recv_err6 or level == socket.IPPROTO_IPV6
        if v6:
            if ee_type == ICMP6_TIMXCEED:
                return hop, "ttl"
            if ee_type == ICMP6_UNREACH:
                if hop == dest or (addr and addr[0] == dest):
                    return hop or dest, "reply"
                return hop, "unreach"
            if ee_type == ICMP6_ECHOREPLY:
                return hop or dest, "reply"
            continue
        if ee_type == ICMP_TIMXCEED:
            return hop, "ttl"
        if ee_type == ICMP_UNREACH:
            if ee_code == ICMP_UNREACH_PORT or hop == dest or (addr and addr[0] == dest):
                return hop or dest, "reply"
            return hop, "unreach"
        if ee_type == ICMP_ECHOREPLY:
            return hop or dest, "reply"
    return None, None


def _new_ident() -> int:
    return random.randint(1, 65535)


def _payload() -> bytes:
    return struct.pack("!d", time.time()) + os.urandom(8)


def _echo(engine: Any) -> Any:
    return getattr(engine, "echo_or_udp", None) or engine.echo


def _normalize_via(method: Optional[str]) -> str:
    text = (method or "icmp").strip().lower()
    if text.startswith("python-"):
        text = text[7:]
    return {"icmp": "python-icmp", "udp": "python-udp", "tcp": "python-tcp"}.get(
        text, f"python-{text}" if text else "python-icmp"
    )


def _via_label(methods: List[Optional[str]]) -> str:
    names: List[str] = []
    for method in methods:
        for part in str(method or "icmp").split("+"):
            label = _normalize_via(part)
            if label not in names:
                names.append(label)
    return "+".join(names) if names else "python-icmp"


def _tool_via(proto: str) -> str:
    """Result-level method for traceroute/MTR: the tool, not hop race winners."""
    return _normalize_via(proto)


INTEL_KEYS = (
    "asn",
    "org_name",
    "prefix",
    "country",
    "country_name",
    "flag",
    "flag_url",
    "flag_html",
)


def _daemon_ready() -> bool:
    from pathlib import Path

    from ..intel_server.client import LOOKUP_SOCKET

    sock = Path(LOOKUP_SOCKET)
    try:
        return sock.exists() and (sock.parent / "lookup.ready").exists()
    except OSError:
        return False


_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ULA = ipaddress.ip_network("fc00::/7")
_CLOUD_GATEWAYS = {"169.254.169.254", "169.254.169.253", "fd00:ec2::254"}
_PLACE_RULES: Tuple[Tuple[re.Pattern[str], str, str, str], ...] = (
    (re.compile(r"(?:^|[.-])sydney(?:[.-]|$)"), "Sydney", "AU", "Australia"),
    (re.compile(r"(?:^|[.-])melbourne(?:[.-]|$)"), "Melbourne", "AU", "Australia"),
    (re.compile(r"(?:^|[.-])sydp?\d*(?:[.-]|$)"), "Sydney", "AU", "Australia"),
    (re.compile(r"(?:^|[.-])mel\d*(?:[.-]|$)"), "Melbourne", "AU", "Australia"),
    (re.compile(r"(?:^|[.-])per(?:th)?\d*(?:[.-]|$)"), "Perth", "AU", "Australia"),
    (re.compile(r"(?:^|[.-])akl\d*(?:[.-]|$)"), "Auckland", "NZ", "New Zealand"),
    (re.compile(r"(?:^|[.-])lax\d*(?:[.-]|$)"), "Los Angeles", "US", "United States"),
    (re.compile(r"(?:^|[.-])sfo\d*(?:[.-]|$)"), "San Francisco", "US", "United States"),
    (re.compile(r"(?:^|[.-])sjc\d*(?:[.-]|$)"), "San Jose", "US", "United States"),
    (re.compile(r"(?:^|[.-])sea\d*(?:[.-]|$)"), "Seattle", "US", "United States"),
    (re.compile(r"(?:^|[.-])dfw\d*(?:[.-]|$)"), "Dallas", "US", "United States"),
    (re.compile(r"(?:^|[.-])ord\d*(?:[.-]|$)"), "Chicago", "US", "United States"),
    (re.compile(r"(?:^|[.-])iad\d*(?:[.-]|$)"), "Ashburn", "US", "United States"),
    (re.compile(r"(?:^|[.-])ewr\d*(?:[.-]|$)"), "Newark", "US", "United States"),
    (re.compile(r"(?:^|[.-])jfk\d*(?:[.-]|$)"), "New York", "US", "United States"),
    (re.compile(r"(?:^|[.-])nyc\d*(?:[.-]|$)"), "New York", "US", "United States"),
    (re.compile(r"(?:^|[.-])atl\d*(?:[.-]|$)"), "Atlanta", "US", "United States"),
    (re.compile(r"(?:^|[.-])mia\d*(?:[.-]|$)"), "Miami", "US", "United States"),
    (re.compile(r"(?:^|[.-])den\d*(?:[.-]|$)"), "Denver", "US", "United States"),
    (re.compile(r"(?:^|[.-])ashburn(?:[.-]|$)"), "Ashburn", "US", "United States"),
    (re.compile(r"(?:^|[.-])hkg\d*(?:[.-]|$)"), "Hong Kong", "HK", "Hong Kong"),
    (re.compile(r"(?:^|[.-])sin\d*(?:[.-]|$)"), "Singapore", "SG", "Singapore"),
    (re.compile(r"(?:^|[.-])nrt\d*(?:[.-]|$)"), "Tokyo", "JP", "Japan"),
    (re.compile(r"(?:^|[.-])tyo\d*(?:[.-]|$)"), "Tokyo", "JP", "Japan"),
    (re.compile(r"(?:^|[.-])lhr\d*(?:[.-]|$)"), "London", "GB", "United Kingdom"),
    (re.compile(r"(?:^|[.-])lon\d*(?:[.-]|$)"), "London", "GB", "United Kingdom"),
    (re.compile(r"(?:^|[.-])ams\d*(?:[.-]|$)"), "Amsterdam", "NL", "Netherlands"),
    (re.compile(r"(?:^|[.-])fra\d*(?:[.-]|$)"), "Frankfurt", "DE", "Germany"),
    (re.compile(r"(?:^|[.-])par\d*(?:[.-]|$)"), "Paris", "FR", "France"),
    (re.compile(r"(?:^|[.-])jnb\d*(?:[.-]|$)"), "Johannesburg", "ZA", "South Africa"),
)


def local_networks() -> Tuple[ipaddress._BaseNetwork, ...]:
    """Prefixes on this host (plus LOOKING_GLASS_LOCAL_NETS). Used only to label LAN."""
    nets: List[ipaddress._BaseNetwork] = []
    extra = os.environ.get("LOOKING_GLASS_LOCAL_NETS") or ""
    for part in extra.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    nets.extend(_interface_v4_networks())
    return tuple(nets)


def _ioctl_v4_codes() -> Optional[Tuple[int, int]]:
    """(SIOCGIFADDR, SIOCGIFNETMASK) or None if this OS has no ifreq ioctl."""
    if sys.platform.startswith("linux"):
        return 0x8915, 0x891B
    if sys.platform in {"darwin", "freebsd", "netbsd", "openbsd"}:
        return 0xC0206921, 0xC0206925
    return None


def _interface_v4_networks() -> List[ipaddress.IPv4Network]:
    """IPv4 prefixes on this host. Used only to promote RFC1918/CGNAT to LAN."""
    if fcntl is None:
        return []
    codes = _ioctl_v4_codes()
    if codes is None:
        return []
    sio_addr, sio_mask = codes
    try:
        names = [name for _idx, name in socket.if_nameindex()]
    except OSError:
        try:
            names = os.listdir("/sys/class/net")
        except OSError:
            return []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    nets: List[ipaddress.IPv4Network] = []
    try:
        for name in names:
            if name == "lo" or name.startswith("lo"):
                continue
            packed = struct.pack("256s", name.encode("utf-8", "replace")[:15])
            try:
                addr = socket.inet_ntoa(fcntl.ioctl(sock, sio_addr, packed)[20:24])
                mask = socket.inet_ntoa(fcntl.ioctl(sock, sio_mask, packed)[20:24])
            except OSError:
                continue
            try:
                net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            except ValueError:
                continue
            if net.network_address.is_loopback or net.network_address.is_link_local:
                continue
            nets.append(net)
    finally:
        sock.close()
    return nets


def _in_local_subnet(addr: ipaddress._BaseAddress, nets: Tuple[ipaddress._BaseNetwork, ...]) -> bool:
    return any(addr in net for net in nets)


def classify_ip(
    value: Optional[str], *, local_nets: Optional[Tuple[ipaddress._BaseNetwork, ...]] = None
) -> Dict[str, Any]:
    """Scope for a hop. RFC1918 is private/internal, not LAN, unless it is on-box."""
    if not value:
        return {
            "scope": "none",
            "scope_label": "No reply",
            "scope_detail": "This hop did not return an address",
            "lan": False,
        }
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return {"scope": "unknown", "scope_label": "Unknown", "lan": False}
    if local_nets is None:
        local_nets = local_networks()
    text = str(addr)
    if text in _CLOUD_GATEWAYS:
        return {
            "scope": "cloud-gateway",
            "scope_label": "Cloud gateway",
            "scope_detail": "Link-local metadata hop (RFC 3927)",
            "lan": True,
        }
    if addr.is_loopback:
        return {
            "scope": "loopback",
            "scope_label": "Loopback",
            "scope_detail": "RFC 1122",
            "lan": True,
        }
    if addr.is_link_local:
        return {
            "scope": "link-local",
            "scope_label": "Link-local",
            "scope_detail": "RFC 3927",
            "lan": True,
        }
    if addr.version == 4 and addr in _CGNAT_V4:
        if _in_local_subnet(addr, local_nets):
            return {
                "scope": "lan",
                "scope_label": "LAN",
                "scope_detail": "Monitor's local subnet",
                "lan": True,
            }
        return {
            "scope": "cgnat",
            "scope_label": "CGNAT",
            "scope_detail": "RFC 6598 shared address space",
            "lan": False,
        }
    rfc1918 = addr.version == 4 and any(addr in net for net in _RFC1918)
    unique_local = addr.version == 6 and addr in _ULA
    if rfc1918 or unique_local:
        if _in_local_subnet(addr, local_nets):
            return {
                "scope": "lan",
                "scope_label": "LAN",
                "scope_detail": "Monitor's local subnet",
                "lan": True,
            }
        if rfc1918:
            return {
                "scope": "private",
                "scope_label": "RFC1918",
                "scope_detail": "Private/internal network address (RFC 1918)",
                "lan": False,
            }
        return {
            "scope": "private",
            "scope_label": "Private",
            "scope_detail": "Unique local address (RFC 4193)",
            "lan": False,
        }
    if addr.is_multicast:
        return {"scope": "multicast", "scope_label": "Multicast", "lan": False}
    if addr.is_reserved or addr.is_unspecified or getattr(addr, "is_documentation", False):
        return {
            "scope": "reserved",
            "scope_label": "Reserved",
            "scope_detail": "IANA special-use",
            "lan": False,
        }
    return {"scope": "public", "scope_label": "Public", "lan": False}


def infer_place(name: Optional[str]) -> Optional[Dict[str, str]]:
    """City from router PTR labels (lax04, sydp, sydney, …). Not GeoIP."""
    if not name:
        return None
    text = str(name).strip().lower()
    if not text or _is_ip(text):
        return None
    for pattern, city, cc, country in _PLACE_RULES:
        if pattern.search(text):
            return {
                "place": city,
                "place_country": cc,
                "place_country_name": country,
                "place_source": "hostname",
            }
    return None


def _stamp_scope(
    row: Dict[str, Any],
    ip: Optional[str],
    local_nets: Tuple[ipaddress._BaseNetwork, ...],
) -> None:
    for key, value in classify_ip(ip, local_nets=local_nets).items():
        row.setdefault(key, value)


def annotate_scopes(result: Dict[str, Any]) -> None:
    nets = local_networks()
    _stamp_scope(result, result.get("ip"), nets)
    for row in result.get("probes") or []:
        _stamp_scope(row, row.get("from"), nets)
    for hop in result.get("hops") or []:
        _stamp_scope(hop, hop.get("host"), nets)
        details: List[Dict[str, Any]] = []
        for ip in hop.get("hosts") or []:
            entry = {"ip": ip}
            _stamp_scope(entry, ip, nets)
            details.append(entry)
        if details:
            hop["hosts_detail"] = details


def annotate_places(result: Dict[str, Any]) -> None:
    def apply(row: Dict[str, Any], name: Optional[str]) -> None:
        info = infer_place(name)
        if info:
            for key, value in info.items():
                row.setdefault(key, value)

    apply(result, result.get("name"))
    for row in result.get("probes") or []:
        apply(row, row.get("name"))
    for hop in result.get("hops") or []:
        apply(hop, hop.get("name"))
        for entry in hop.get("hosts_detail") or []:
            apply(entry, entry.get("name"))


def interpret_path(result: Dict[str, Any]) -> Dict[str, Any]:
    """Short reading of a traceroute/MTR table: GeoIP path vs hostname cities."""
    hops = list(result.get("hops") or [])
    reached = bool(result.get("reached"))
    countries: List[str] = []
    places: List[str] = []
    asns: List[int] = []
    for hop in hops:
        rows = [hop]
        for alt in hop.get("hosts_detail") or []:
            if isinstance(alt, dict) and alt.get("ip") and alt.get("ip") != hop.get("host"):
                rows.append(alt)
        for row in rows:
            if row.get("scope") and row.get("scope") != "public":
                continue
            name = row.get("country_name") or row.get("country")
            if name and (not countries or countries[-1] != name):
                countries.append(str(name))
            place = row.get("place")
            if place and (not places or places[-1] != place):
                places.append(str(place))
            asn = row.get("asn")
            if isinstance(asn, int) and asn > 0 and (not asns or asns[-1] != asn):
                asns.append(asn)

    dest = hops[-1] if hops else None
    loss: Optional[float] = None
    latency: Optional[float] = None
    if dest:
        if dest.get("loss_percent") is not None:
            loss = float(dest["loss_percent"])
        elif reached or dest.get("status") == "reply":
            loss = 0.0
        for key in ("avg_ms", "last_ms", "rtt_ms"):
            if dest.get(key) is not None:
                latency = float(dest[key])
                break
    warnings: List[str] = []
    if dest and hops:
        dest_loss = dest.get("loss_percent")
        noisy = [
            hop
            for hop in hops[:-1]
            if (hop.get("loss_percent") or 0) >= 10
        ]
        if noisy and reached and (dest_loss in {None, 0, 0.0}):
            warnings.append(
                "Intermediate ICMP loss detected; downstream hosts respond normally"
            )
        silent = [hop for hop in hops[:-1] if not hop.get("host")]
        if silent and reached and not noisy:
            warnings.append(
                f"{len(silent)} hop{'s' if len(silent) != 1 else ''} did not reply; the path continued"
            )
    if hops and not reached:
        warnings.append("Destination did not respond within the hop limit")

    return {
        "route": countries,
        "route_text": " → ".join(countries) if countries else None,
        "inferred": places,
        "inferred_text": " → ".join(places) if places else None,
        "reached": reached,
        "loss_percent": loss,
        "latency_ms": round(latency, 3) if latency is not None else None,
        "as_path": asns,
        "as_text": " → ".join(f"AS{asn}" for asn in asns) if asns else None,
        "warnings": warnings,
    }


async def _finalize_result(result: Dict[str, Any], kind: str, enrich: bool) -> None:
    annotate_scopes(result)
    if enrich:
        await enrich_probe_result(result)
    annotate_places(result)
    if kind in {"traceroute", "mtr", "tcptraceroute"}:
        result["summary"] = interpret_path(result)


def _is_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def collect_probe_ips(result: Dict[str, Any]) -> List[str]:
    seen: List[str] = []

    def add(ip: Optional[str]) -> None:
        if ip and _is_ip(ip) and ip not in seen:
            seen.append(ip)

    add(result.get("ip"))
    for row in result.get("probes") or []:
        add(row.get("from"))
    for hop in result.get("hops") or []:
        add(hop.get("host"))
        for host in hop.get("hosts") or []:
            add(host)
    return seen


def _intel_from_daemon(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    payload = (data or {}).get("result") or {}
    intel: Dict[str, Any] = {}
    for key in INTEL_KEYS:
        value = payload.get(key)
        if value not in (None, False, ""):
            intel[key] = value
    country = intel.get("country")
    if country:
        from ..intel.flags import lookup_fields

        for key, value in lookup_fields(country).items():
            intel.setdefault(key, value)
    return intel


def stamp_intel(
    row: Dict[str, Any], ip: Optional[str], table: Dict[str, Dict[str, Any]]
) -> None:
    if not ip:
        return
    intel = table.get(ip)
    if not intel:
        return
    for key, value in intel.items():
        row.setdefault(key, value)


async def lookup_path_intel(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    if not ips or not _daemon_ready():
        return {}
    nets = local_networks()
    ips = [ip for ip in ips if classify_ip(ip, local_nets=nets).get("scope") == "public"]
    if not ips:
        return {}
    import aiohttp

    from ..intel_server.client import LOOKUP_SOCKET, lookup_json_async

    table: Dict[str, Dict[str, Any]] = {}

    async def one(ip: str, session: aiohttp.ClientSession) -> None:
        try:
            data = await lookup_json_async(ip, timeout=0.45, session=session)
        except Exception:
            return
        intel = _intel_from_daemon(data)
        if intel:
            table[ip] = intel

    connector = aiohttp.UnixConnector(path=LOOKUP_SOCKET)
    async with aiohttp.ClientSession(connector=connector) as session:
        await asyncio.gather(*(one(ip, session) for ip in ips), return_exceptions=True)
    return table


async def enrich_probe_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Attach ASN / country / flag fields from the intel server when it is up."""
    try:
        table = await lookup_path_intel(collect_probe_ips(result))
    except Exception:
        table = {}
    if table:
        stamp_intel(result, result.get("ip"), table)
        for row in result.get("probes") or []:
            stamp_intel(row, row.get("from"), table)
        for hop in result.get("hops") or []:
            stamp_intel(hop, hop.get("host"), table)
            for entry in hop.get("hosts_detail") or []:
                stamp_intel(entry, entry.get("ip"), table)
    await _attach_ptr_names(result)
    return result


async def _attach_ptr_names(result: Dict[str, Any]) -> None:
    ips = collect_probe_ips(result)
    if not ips:
        return
    names: Dict[str, str] = {}

    async def one(ip: str) -> None:
        try:
            loop = asyncio.get_running_loop()
            host, _service = await asyncio.wait_for(loop.getnameinfo((ip, 0), 0), 0.4)
        except Exception:
            return
        if host and host != ip:
            names[ip] = host

    await asyncio.gather(*(one(ip) for ip in ips), return_exceptions=True)
    if not names:
        return
    if result.get("ip") in names:
        result.setdefault("name", names[result["ip"]])
    for row in result.get("probes") or []:
        ip = row.get("from")
        if ip in names:
            row.setdefault("name", names[ip])
    for hop in result.get("hops") or []:
        ip = hop.get("host")
        if ip in names:
            hop.setdefault("name", names[ip])
        for entry in hop.get("hosts_detail") or []:
            alt = entry.get("ip")
            if alt in names:
                entry.setdefault("name", names[alt])


async def ping_async(
    target: str,
    *,
    count: int = PING_COUNT,
    timeout: float = PING_TIMEOUT,
    engine: Optional[ProbeEngine] = None,
) -> Dict[str, Any]:
    start = time.time()
    enrich = engine is None
    engine = engine or SocketEngine()
    try:
        ip, family, name = await engine.resolve(target)
    except Exception as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": _ms(start)}
    ident = _new_ident()
    probes: List[Dict[str, Any]] = []
    rtts: List[float] = []
    echo = _echo(engine)
    try:
        for seq in range(1, max(1, count) + 1):
            hit = await echo(
                ip,
                family,
                ttl=64,
                ident=ident,
                seq=seq,
                timeout=timeout,
                payload=_payload(),
            )
            row = {
                "seq": seq,
                "from": hit.addr,
                "rtt_ms": hit.rtt_ms,
                "ok": hit.kind == "reply",
                "error": None if hit.kind == "reply" else (hit.error or hit.kind),
                "via": hit.via,
            }
            probes.append(row)
            if hit.rtt_ms is not None and hit.kind == "reply":
                rtts.append(hit.rtt_ms)
            if seq < count:
                await asyncio.sleep(0.15)
    except PermissionError as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": _ms(start)}
    received = sum(1 for row in probes if row["ok"])
    loss = round(100.0 * (count - received) / count, 1) if count else 0.0
    result = {
        "target": name,
        "ip": ip,
        "family": "IPv4" if family == socket.AF_INET else "IPv6",
        "transmitted": count,
        "received": received,
        "loss_percent": loss,
        "min_ms": round(min(rtts), 3) if rtts else None,
        "avg_ms": round(sum(rtts) / len(rtts), 3) if rtts else None,
        "max_ms": round(max(rtts), 3) if rtts else None,
        "probes": probes,
        "via": _via_label([row.get("via") for row in probes]),
    }
    await _finalize_result(result, "ping", enrich)
    return {"ok": True, "result": result, "error": None, "total_ms": _ms(start)}


def _dest_hit(hit: ProbeHit, ip: str) -> bool:
    """True when this packet is dest-reached (echo reply / dest-unreach / port-unreach).

    Anycast dest-unreach often comes from a sibling address, not the queried IP.
    """
    if hit.kind == "reply":
        return True
    if hit.kind == "unreach":
        return True
    return hit.addr == ip and hit.kind == "ttl"


def _hop_display_host(hosts: List[str], target: str) -> Optional[str]:
    """Prefer the target IP when it answered this hop; otherwise first seen."""
    if target in hosts:
        return target
    return hosts[0] if hosts else None


async def traceroute_async(
    target: str,
    *,
    max_hops: int = TRACE_MAX_HOPS,
    timeout: float = TRACE_TIMEOUT,
    engine: Optional[ProbeEngine] = None,
    proto: str = "udp",
    port: int = 443,
) -> Dict[str, Any]:
    start = time.time()
    enrich = engine is None
    engine = engine or SocketEngine()
    try:
        ip, family, name = await engine.resolve(target)
    except Exception as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": _ms(start)}
    ident = _new_ident()
    hops: List[Dict[str, Any]] = []
    if proto == "tcp":
        tcp_port = int(port)

        async def echo(
            ip: str,
            family: int,
            *,
            ttl: int,
            ident: int,
            seq: int,
            timeout: float,
            payload: bytes,
        ) -> ProbeHit:
            if hasattr(engine, "echo_tcp"):
                return await engine.echo_tcp(
                    ip,
                    family,
                    ttl=ttl,
                    ident=ident,
                    seq=seq,
                    timeout=timeout,
                    payload=payload,
                    port=tcp_port,
                )
            return await engine.echo(
                ip, family, ttl=ttl, ident=ident, seq=seq, timeout=timeout, payload=payload
            )
    else:
        echo = _echo(engine)
    reached = False
    timeouts = 0
    saw_hop = False
    same = 0
    inflight_hops = max(1, TRACE_NQUERIES // TRACE_PROBES)
    pending: Dict[int, "asyncio.Task[Dict[str, Any]]"] = {}
    next_ttl = 1

    async def probe_ttl(ttl: int) -> Dict[str, Any]:
        seq0 = (ttl - 1) * TRACE_PROBES
        hits = await asyncio.gather(
            *[
                echo(
                    ip,
                    family,
                    ttl=ttl,
                    ident=ident,
                    seq=seq0 + probe_i,
                    timeout=timeout,
                    payload=_payload(),
                )
                for probe_i in range(TRACE_PROBES)
            ]
        )
        te_hosts: List[str] = []
        dest_hosts: List[str] = []
        unreach_hosts: List[str] = []
        te_rtts: List[float] = []
        dest_rtts: List[float] = []
        unreach_rtts: List[float] = []
        vias: List[Optional[str]] = []

        def _take(bucket: List[str], rtts: List[float], hit: ProbeHit) -> None:
            if hit.addr and hit.addr not in bucket:
                bucket.append(hit.addr)
            if hit.kind in {"reply", "ttl", "unreach"} and hit.rtt_ms is not None:
                rtts.append(hit.rtt_ms)

        for hit in hits:
            if hit.via:
                vias.append(hit.via)
            if _dest_hit(hit, ip):
                _take(dest_hosts, dest_rtts, hit)
            elif hit.kind == "ttl":
                _take(te_hosts, te_rtts, hit)
            elif hit.kind == "unreach":
                _take(unreach_hosts, unreach_rtts, hit)
        # Mixed TTL: Time Exceeded stays here; dest-style replies belong on the dest hop.
        if te_hosts:
            hosts, rtts, status = te_hosts, te_rtts, "ttl"
        elif dest_hosts:
            hosts, rtts, status = dest_hosts, dest_rtts, "reply"
        elif unreach_hosts:
            hosts, rtts, status = unreach_hosts, unreach_rtts, "unreach"
        else:
            hosts, rtts, status = [], [], "timeout"
        return {
            "hop": ttl,
            "host": _hop_display_host(hosts, ip),
            "hosts": hosts,
            "rtt_ms": rtts[0] if rtts else None,
            "rtts": rtts,
            "status": status,
            "via": _via_label(vias),
        }

    def fill() -> None:
        nonlocal next_ttl
        while len(pending) < inflight_hops and next_ttl <= max_hops:
            pending[next_ttl] = asyncio.create_task(probe_ttl(next_ttl))
            next_ttl += 1

    try:
        fill()
        ttl = 1
        while ttl <= max_hops:
            fill()
            task = pending.pop(ttl, None)
            if task is None:
                break
            row = await task
            hops.append(row)
            if row["status"] == "reply":
                reached = True
                break
            if (
                row["status"] != "timeout"
                and row.get("host")
                and len(hops) >= 2
                and hops[-2].get("host") == row["host"]
                and hops[-2].get("status") != "timeout"
            ):
                # Same router on back-to-back TTLs: either MPLS or a box that
                # answers every remaining hop. Do not keep cloning it to hop 30.
                same += 1
                if same >= 2:
                    reached = row["host"] == ip
                    break
            else:
                same = 0
            if row["status"] == "timeout":
                timeouts += 1
                # traceroute(8) walks to max hops. Only stop after a real hop
                # followed by consecutive * (blackhole). Leading * must not
                # abort the trace — that hid every hop when receive failed.
                if saw_hop and timeouts >= TRACE_STOP_TIMEOUTS:
                    break
            else:
                timeouts = 0
                saw_hop = True
            ttl += 1
            fill()
    except PermissionError as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": _ms(start)}
    finally:
        for task in pending.values():
            task.cancel()
        if pending:
            await asyncio.gather(*pending.values(), return_exceptions=True)
    result = {
        "target": name,
        "ip": ip,
        "family": "IPv4" if family == socket.AF_INET else "IPv6",
        "reached": reached,
        "hops": hops,
        "via": _tool_via(proto),
        "probe": proto,
    }
    if proto == "tcp":
        result["port"] = int(port)
    await _finalize_result(result, "traceroute", enrich)
    return {"ok": True, "result": result, "error": None, "total_ms": _ms(start)}


def parse_mtr_query_cycles(raw: Any) -> int:
    """Strict ?cycles=: integer in 1..max_cycles. Do not coerce."""
    try:
        from ..config import load

        cap = int((load().get("mtr") or {}).get("max_cycles") or 30)
    except Exception:
        cap = 30
    cap = max(1, min(cap, MTR_HARD_CEILING))
    if raw is None or isinstance(raw, bool):
        raise ValueError("cycles must be an integer")
    text = str(raw).strip()
    try:
        n = int(text)
    except (TypeError, ValueError) as exc:
        raise ValueError("cycles must be an integer") from exc
    if n < 1 or n > cap:
        raise ValueError(f"cycles must be 1–{cap}")
    return n


def clamp_mtr_cycles(raw: Any = None) -> int:
    """mtr -c: omit/garbage → config default, N<1 → 1, N>max → max. Ceiling 50."""
    try:
        from ..config import load

        mtr = load().get("mtr") or {}
        default = int(mtr.get("cycles") or MTR_CYCLES)
        cap = int(mtr.get("max_cycles") or 30)
    except Exception:
        default, cap = MTR_CYCLES, 30
    cap = max(1, min(cap, MTR_HARD_CEILING))
    default = max(1, min(default, cap))
    if raw is None:
        return default
    if isinstance(raw, str) and not raw.strip():
        return default
    if isinstance(raw, bool):
        return default
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return default
    if n < 1:
        return 1
    return min(n, cap)


async def mtr_async(
    target: str,
    *,
    cycles: Optional[int] = None,
    max_hops: int = TRACE_MAX_HOPS,
    timeout: float = MTR_TIMEOUT,
    engine: Optional[ProbeEngine] = None,
) -> Dict[str, Any]:
    start = time.time()
    enrich = engine is None
    engine = engine or SocketEngine()
    try:
        ip, family, name = await engine.resolve(target)
    except Exception as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": _ms(start)}
    cycles = clamp_mtr_cycles(cycles)
    ident = _new_ident()
    echo = _echo(engine)
    per_hop: Dict[int, Dict[str, Any]] = {}
    dest_ttl: Optional[int] = None
    exact_dest = False
    farthest = 0
    seq = 0
    try:
        for _cycle in range(max(1, cycles)):
            if dest_ttl is not None:
                limit = dest_ttl
            elif farthest:
                limit = min(max_hops, farthest + MTR_STOP_TIMEOUTS)
            else:
                limit = max(1, max_hops)
            seq0 = seq
            seq += limit

            async def probe_hop(ttl: int, probe_seq: int) -> Tuple[int, ProbeHit]:
                hit = await echo(
                    ip,
                    family,
                    ttl=ttl,
                    ident=ident,
                    seq=probe_seq,
                    timeout=timeout,
                    payload=_payload(),
                )
                return ttl, hit

            pairs = await asyncio.gather(
                *[probe_hop(ttl, seq0 + ttl) for ttl in range(1, limit + 1)]
            )
            sticky_at: Optional[int] = None
            last_host: Optional[str] = None
            same_host = 0
            for ttl, hit in sorted(pairs, key=lambda row: row[0]):
                if dest_ttl is not None and ttl > dest_ttl:
                    continue
                bucket = per_hop.setdefault(
                    ttl, {"hop": ttl, "hosts": [], "sent": 0, "rtts": [], "vias": []}
                )
                bucket["sent"] += 1
                if hit.addr and hit.addr not in bucket["hosts"]:
                    bucket["hosts"].append(hit.addr)
                if hit.via and hit.via not in bucket["vias"]:
                    bucket["vias"].append(hit.via)
                if hit.kind in {"reply", "ttl", "unreach"} and hit.rtt_ms is not None:
                    bucket["rtts"].append(hit.rtt_ms)
                if hit.addr == ip and hit.kind in {"reply", "unreach", "ttl"}:
                    dest_ttl = ttl if dest_ttl is None or not exact_dest else min(dest_ttl, ttl)
                    exact_dest = True
                    farthest = max(farthest, ttl)
                    last_host = None
                    same_host = 0
                    continue
                if _dest_hit(hit, ip):
                    if not exact_dest:
                        dest_ttl = ttl if dest_ttl is None else min(dest_ttl, ttl)
                    farthest = max(farthest, ttl)
                    last_host = None
                    same_host = 0
                    continue
                if hit.kind in {"ttl", "unreach"} and hit.addr:
                    farthest = max(farthest, ttl)
                    if hit.addr == last_host:
                        same_host += 1
                        if same_host >= 2 and sticky_at is None:
                            sticky_at = ttl
                    else:
                        same_host = 0
                    last_host = hit.addr
                else:
                    last_host = None
                    same_host = 0
            if dest_ttl is None and sticky_at is not None:
                dest_ttl = sticky_at
    except PermissionError as exc:
        return {"ok": False, "result": None, "error": str(exc), "total_ms": _ms(start)}
    hops = []
    if dest_ttl is not None:
        cap = dest_ttl
    elif farthest:
        cap = farthest + MTR_STOP_TIMEOUTS
    else:
        cap = max(per_hop) if per_hop else 0
    for ttl in sorted(per_hop):
        if ttl > cap:
            continue
        bucket = per_hop[ttl]
        rtts: List[float] = bucket["rtts"]
        sent = bucket["sent"]
        recv = len(rtts)
        loss = round(100.0 * (sent - recv) / sent, 1) if sent else 0.0
        hops.append(
            {
                "hop": ttl,
                "host": _hop_display_host(bucket["hosts"], ip),
                "hosts": bucket["hosts"],
                "sent": sent,
                "recv": recv,
                "loss_percent": loss,
                "last_ms": round(rtts[-1], 3) if rtts else None,
                "avg_ms": round(sum(rtts) / len(rtts), 3) if rtts else None,
                "best_ms": round(min(rtts), 3) if rtts else None,
                "worst_ms": round(max(rtts), 3) if rtts else None,
                "stdev_ms": _stdev(rtts),
                "via": _via_label(bucket["vias"]),
            }
        )
    reached_at = dest_ttl
    if reached_at is None:
        reached_at = next((row["hop"] for row in hops if row.get("host") == ip), None)
    if reached_at is not None:
        hops = [row for row in hops if row["hop"] <= reached_at]
        dest_ttl = reached_at
    result = {
        "target": name,
        "ip": ip,
        "family": "IPv4" if family == socket.AF_INET else "IPv6",
        "cycles": cycles,
        "reached": dest_ttl is not None,
        "hops": hops,
        "via": _tool_via("udp"),
        "probe": "udp",
    }
    await _finalize_result(result, "mtr", enrich)
    return {"ok": True, "result": result, "error": None, "total_ms": _ms(start)}


def _ms(start: float) -> float:
    return round((time.time() - start) * 1000.0, 3)


async def run_probe_async(
    kind: str,
    target: str,
    *,
    engine: Optional[ProbeEngine] = None,
    port: Optional[int] = None,
    cycles: Any = None,
) -> Dict[str, Any]:
    if kind == "ping":
        return await ping_async(target, engine=engine)
    if kind == "traceroute":
        return await traceroute_async(target, engine=engine)
    if kind == "tcptraceroute":
        return await traceroute_async(
            target, engine=engine, proto="tcp", port=int(port or 443)
        )
    if kind == "mtr":
        return await mtr_async(target, engine=engine, cycles=cycles)
    raise ValueError(f"unknown probe {kind!r}")


def run_probe(kind: str, target: str, **kwargs: Any) -> Dict[str, Any]:
    """Sync wrapper. Do not call from a running event loop."""
    return asyncio.run(run_probe_async(kind, target, **kwargs))
