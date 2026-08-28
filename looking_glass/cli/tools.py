"""Click commands that mirror the GUI tools."""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence, Tuple

import click

from ..intel_server.pipeline import classify_query
from ..dns.resolve import DNS_TYPE_EXAMPLES, parse_nameserver
from ..http.site import lookup_classified
from ..i18n import t
from .render import emit


def _cli_history_path(kind: str, value: str, kwargs: dict) -> str:
    port = kwargs.get("port")
    if kind == "tcp":
        return f"/tcp/{value}/{int(port or 443)}"
    if kind == "tls":
        if port not in (None, "", 443):
            return f"/tls/{value}/{int(port)}"
        return f"/tls/{value}"
    if kind == "tcptraceroute":
        return f"/tcptraceroute/{value}/{int(port or 443)}"
    if kind == "mtr":
        path = f"/mtr/{value}"
        cycles = kwargs.get("cycles")
        if cycles not in (None, ""):
            path += f"?cycles={int(cycles)}"
        return path
    if kind == "register":
        path = f"/register/{value}"
        tlds = kwargs.get("tlds")
        if tlds:
            path += "?tlds=" + ",".join(str(t) for t in tlds)
        return path
    if kind == "asn":
        return f"/AS{value}"
    if kind in {"ip", "country"}:
        return f"/{value}"
    return f"/{kind}/{value}"


def _run(kind: str, value: str, **kwargs: Any) -> None:
    payload = lookup_classified(kind, value, **kwargs)
    if isinstance(payload, dict):
        payload.setdefault("kind", kind)
        payload.setdefault("query", value)
        from ..observe import attach_observation

        attach_observation(payload)
        try:
            from ..auth import history as action_history

            action_history.append(
                "",
                path=_cli_history_path(kind, value, kwargs),
                kind=kind,
                query=value,
                payload=payload,
            )
        except OSError:
            pass
    emit(payload, kind="lookup")
    if not payload.get("ok"):
        raise SystemExit(1)


def parse_dig_args(tokens: Sequence[str]) -> Tuple[Optional[str], str, Optional[str]]:
    """Parse `[@server] name [type]` like dig."""
    server: Optional[str] = None
    positional: list[str] = []
    for token in tokens:
        if token.startswith("@"):
            if server is not None:
                raise click.UsageError(t("cli.dns.err.one_server"))
            server = token[1:].strip()
            if not server:
                raise click.UsageError(t("cli.dns.err.need_server"))
            continue
        positional.append(token)
    if not positional:
        raise click.UsageError(t("cli.dns.err.need_name"))
    name = positional[0]
    qtype = positional[1] if len(positional) > 1 else None
    if len(positional) > 2:
        raise click.UsageError(t("cli.dns.err.too_many"))
    return server, name, qtype


def register_tool_commands(cli: click.Group) -> None:
    cli.add_command(ip_cmd)
    cli.add_command(asn_cmd)
    cli.add_command(dns_cmd)
    cli.add_command(dnssec_cmd)
    cli.add_command(tls_cmd)
    cli.add_command(apex_cmd)
    cli.add_command(register_cmd)
    cli.add_command(ping_cmd)
    cli.add_command(traceroute_cmd)
    cli.add_command(mtr_cmd)
    cli.add_command(tcptraceroute_cmd)
    cli.add_command(rdap_cmd)
    cli.add_command(whois_cmd)
    cli.add_command(reputation_cmd)
    cli.add_command(bgp_cmd)
    cli.add_command(dnstrace_cmd)
    cli.add_command(http_cmd)
    cli.add_command(ptr_cmd)
    cli.add_command(mail_cmd)
    cli.add_command(tcp_cmd)
    cli.add_command(pmtu_cmd)


@click.command("ip")
@click.argument("addr")
def ip_cmd(addr: str) -> None:
    """Look up an IPv4 or IPv6 address (same as GET /<ip>). Also accepts ASN or country."""
    try:
        kind, value = classify_query(addr)
    except ValueError as e:
        emit({"ok": False, "error": str(e), "result": None}, kind="error")
        raise SystemExit(1)
    _run(kind, value)


@click.command("asn")
@click.argument("asn")
def asn_cmd(asn: str) -> None:
    """Look up an autonomous system (same as GET /AS<number>)."""
    raw = asn.strip()
    if raw.lower().startswith("as"):
        raw = raw[2:]
    _run("asn", raw)


@click.command("dns")
@click.argument("args", nargs=-1)
@click.option("-p", "--port", type=int, default=None, help="Nameserver port (default 53).")
@click.option(
    "-t",
    "--type",
    "rrtype",
    default=None,
    help="RR type (A, AAAA, MX, DS, …). Positional type wins if both are given.",
)
@click.option("--server", "server_opt", default=None, help="Nameserver IP (or IP:port).")
@click.option("--timeout", type=float, default=5.0, show_default=True)
def dns_cmd(
    args: Tuple[str, ...],
    port: Optional[int],
    rrtype: Optional[str],
    server_opt: Optional[str],
    timeout: float,
) -> None:
    """Query DNS like dig: `looking-glass dns [@server] name [type]`.

    Default nameserver comes from resolv.conf. Pass @server (or --server)
    only to override it.

    \b
      looking-glass dns example.com
      looking-glass dns example.com DS
      looking-glass dns @1.1.1.1 example.com A
      looking-glass dns @8.8.8.8:5353 example.com MX
      looking-glass dns example.com AAAA -p 53 --server 9.9.9.9

    DS, DNSKEY, and NSEC are published at the zone apex (example.com), not www.
    Known public examples: %s
    """ % ", ".join(f"{t} {n}" for t, n in DNS_TYPE_EXAMPLES.items())
    at_server, name, positional_type = parse_dig_args(args)
    qtype = positional_type or rrtype or "A"
    raw_server = at_server or server_opt
    kwargs: dict = {"qtype": qtype, "timeout": timeout}
    try:
        if raw_server:
            host, ns_port = parse_nameserver(raw_server, port)
            kwargs["server"] = host
            kwargs["ns_port"] = ns_port
        elif port is not None:
            kwargs["ns_port"] = port
        _run("dns", name, **kwargs)
    except ValueError as e:
        emit({"ok": False, "query": name, "result": None, "error": str(e)}, kind="error")
        raise SystemExit(1)


@click.command("dnssec")
@click.argument("domain")
def dnssec_cmd(domain: str) -> None:
    """Walk the DNSSEC chain of trust (same as GET /dnssec/<domain>)."""
    _run("dnssec", domain)


@click.command("tls")
@click.argument("host")
@click.option("-p", "--port", type=int, default=443, show_default=True)
@click.option("--sni", default=None, help="Override SNI hostname.")
def tls_cmd(host: str, port: int, sni: Optional[str]) -> None:
    """Inspect a TLS handshake and certificate (same as GET /tls/<host> with optional /<port>)."""
    _run("tls", host, port=port, sni=sni)


@click.command("apex")
@click.argument("domain")
def apex_cmd(domain: str) -> None:
    """Zone and mail health (same as GET /apex/<domain>)."""
    _run("apex", domain)


@click.command("register")
@click.argument("name")
@click.option("--tlds", "tlds_opt", default=None, help="Comma-separated TLD list (same as ?tlds=).")
def register_cmd(name: str, tlds_opt: Optional[str]) -> None:
    """Check a label against every IANA TLD (same as GET /register/<name>)."""
    kwargs: Dict[str, Any] = {}
    if tlds_opt:
        kwargs["tlds"] = [part.strip().lower().lstrip(".") for part in tlds_opt.split(",") if part.strip()]
    _run("register", name, **kwargs)


@click.command("ping")
@click.argument("target")
def ping_cmd(target: str) -> None:
    """ICMP ping (same as GET /ping/<host>)."""
    _run("ping", target)


@click.command("traceroute")
@click.argument("target")
def traceroute_cmd(target: str) -> None:
    """UDP traceroute (same as GET /traceroute/<host>)."""
    _run("traceroute", target)


@click.command("mtr")
@click.argument("target")
@click.option("-c", "--cycles", type=int, default=None)
def mtr_cmd(target: str, cycles: Optional[int]) -> None:
    """MTR-style path report (same as GET /mtr/<host>)."""
    _run("mtr", target, cycles=cycles)


@click.command("tcptraceroute")
@click.argument("target")
@click.option("-p", "--port", type=int, default=443, show_default=True)
def tcptraceroute_cmd(target: str, port: int) -> None:
    """TCP traceroute (same as GET /tcptraceroute/<host>/<port>)."""
    _run("tcptraceroute", target, port=port)


@click.command("rdap")
@click.argument("target")
def rdap_cmd(target: str) -> None:
    """RDAP lookup (same as GET /rdap/<token>)."""
    _run("rdap", target)


@click.command("reputation")
@click.argument("target")
def reputation_cmd(target: str) -> None:
    """Domain or IP blocklists (same as GET /reputation/<name>)."""
    _run("reputation", target)


@click.command("bgp")
@click.argument("target")
def bgp_cmd(target: str) -> None:
    """Prefix origin ASN and RPKI ROA status (same as GET /bgp/<ip>)."""
    _run("bgp", target)


@click.command("dnstrace")
@click.argument("name")
@click.option("-t", "--type", "qtype", default="A", show_default=True)
def dnstrace_cmd(name: str, qtype: str) -> None:
    """Iterative DNS walk from the root, like dig +trace."""
    _run("dnstrace", name, qtype=qtype)


@click.command("http")
@click.argument("target")
def http_cmd(target: str) -> None:
    """Inspect HTTP status chain, redirects, headers, and TTFB."""
    _run("http", target)


@click.command("ptr")
@click.argument("addr")
def ptr_cmd(addr: str) -> None:
    """PTR plus forward-confirmed reverse DNS."""
    _run("ptr", addr)


@click.command("mail")
@click.argument("domain")
def mail_cmd(domain: str) -> None:
    """MX, SPF, DMARC, DKIM selectors, SMTP banner and STARTTLS."""
    _run("mail", domain)


@click.command("tcp")
@click.argument("host")
@click.option("-p", "--port", type=int, default=443, show_default=True)
def tcp_cmd(host: str, port: int) -> None:
    """TCP connect check: RTT and an optional banner peek."""
    _run("tcp", host, port=port)


@click.command("pmtu")
@click.argument("host")
def pmtu_cmd(host: str) -> None:
    """Path MTU discovery with don't-fragment ping probes."""
    _run("pmtu", host)


@click.command("whois")
@click.argument("target")
@click.option("--legacy", is_flag=True, help="Use port-43 WHOIS instead of RDAP.")
def whois_cmd(target: str, legacy: bool) -> None:
    """Registration data. RDAP by default; --legacy for classic WHOIS."""
    _run("whois", target, legacy=legacy)
