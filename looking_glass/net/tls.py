"""TLS inspector: handshake, certificate, and path intel for a host:port.

Connects with the stdlib ssl module (no openssl(1)). Hostname is used as
SNI. The peer IP is enriched with ASN/org/country from the intel server
when it is running.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

from ..dns.resolve import normalize_qname
from .host import format_hostport, restore_collapsed_slashes, resolve_probe_host, split_host_port, unbracket_host, reject_probe_target, reject_url_as_host


def _tls_port(raw: Any) -> int:
    try:
        port = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("tls port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("tls port must be 1–65535")
    return port


def parse_tls_path(path: str) -> Tuple[str, int]:
    """Parse /tls/<host>, /tls/<host>:<port>, or /tls/<host>/<port>."""
    text = restore_collapsed_slashes(unquote(str(path or ""))).strip()
    if text.startswith("/"):
        text = text[1:]
    text = text.rstrip("/")
    if text != "tls" and not text.startswith("tls/"):
        raise ValueError("not a tls path")
    rest = "" if text == "tls" else text[len("tls/") :]
    if not rest:
        raise ValueError("tls path needs a host, e.g. /tls/example.com")
    if "://" in rest or rest.lower().startswith("//"):
        raise ValueError("host is not a URL")
    reject_url_as_host(rest.split("/")[0])
    parts = rest.split("/")
    try:
        host, colon_port = split_host_port(parts[0], 443)
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("port "):
            raise ValueError("tls " + msg) from exc
        raise
    if not host:
        raise ValueError("tls path needs a host, e.g. /tls/example.com")
    reject_probe_target(host)
    if len(parts) == 1:
        return host, colon_port
    if len(parts) == 2:
        return host, _tls_port(parts[1])
    raise ValueError("tls path is /tls/<host> or /tls/<host>/<port>")


def _flatten_name(seq: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for rdn in seq or []:
        for key, value in rdn:
            out[str(key)] = str(value)
    return out


def _parse_when(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    try:
        ts = ssl.cert_time_to_seconds(text)
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return str(text)


def _days_left(text: Optional[str]) -> Optional[int]:
    if not text:
        return None
    try:
        ts = ssl.cert_time_to_seconds(text)
        return int((ts - time.time()) / 86400)
    except Exception:
        return None


def _sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _leaf_from_der(der: bytes) -> Dict[str, Any]:
    """Fill subject/issuer/SANs when ssl.getpeercert() is empty (CERT_NONE)."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der)

    def _name_map(name: Any) -> Dict[str, str]:
        out: Dict[str, str] = {}
        oid_to_key = {
            NameOID.COMMON_NAME: "commonName",
            NameOID.ORGANIZATION_NAME: "organizationName",
            NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
            NameOID.COUNTRY_NAME: "countryName",
            NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
            NameOID.LOCALITY_NAME: "localityName",
        }
        for attr in name:
            key = oid_to_key.get(attr.oid, attr.oid.dotted_string)
            out[key] = attr.value if isinstance(attr.value, str) else str(attr.value)
        return out

    sans: List[Dict[str, str]] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in ext.value.get_values_for_type(x509.DNSName):
            sans.append({"type": "DNS", "value": name})
        for addr in ext.value.get_values_for_type(x509.IPAddress):
            sans.append({"type": "IP Address", "value": str(addr)})
    except Exception:
        pass
    ocsp: List[str] = []
    ca_issuers: List[str] = []
    crl: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_oid = x509.AuthorityInformationAccessOID.OCSP
        issuers_oid = x509.AuthorityInformationAccessOID.CA_ISSUERS
        for desc in ext.value:
            loc = getattr(desc.access_location, "value", desc.access_location)
            uri = str(loc)
            if desc.access_method == ocsp_oid:
                ocsp.append(uri)
            elif desc.access_method == issuers_oid:
                ca_issuers.append(uri)
    except Exception:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for point in ext.value:
            for name in point.full_name or []:
                loc = getattr(name, "value", name)
                crl.append(str(loc))
    except Exception:
        pass
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    if getattr(nb, "tzinfo", None) is None:
        nb = nb.replace(tzinfo=timezone.utc)
    if getattr(na, "tzinfo", None) is None:
        na = na.replace(tzinfo=timezone.utc)
    not_before = nb.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_after = na.strftime("%Y-%m-%dT%H:%M:%SZ")
    days = None
    try:
        days = int((na.timestamp() - time.time()) / 86400)
    except Exception:
        pass
    return {
        "subject": _name_map(cert.subject),
        "issuer": _name_map(cert.issuer),
        "serial": format(cert.serial_number, "X"),
        "version": int(cert.version.value) if cert.version is not None else None,
        "not_before": not_before,
        "not_after": not_after,
        "days_remaining": days,
        "expired": days is not None and days < 0,
        "sans": sans,
        "ocsp": ocsp,
        "ca_issuers": ca_issuers,
        "crl": crl,
        "sha256": _sha256(der),
        "pem": ssl.DER_cert_to_PEM_cert(der).strip(),
    }


def _leaf_from_cert(cert: Dict[str, Any], der: Optional[bytes]) -> Dict[str, Any]:
    if der and not (cert or {}).get("subject") and not (cert or {}).get("subjectAltName"):
        try:
            return _leaf_from_der(der)
        except Exception:
            pass
    sans = []
    for kind, value in cert.get("subjectAltName") or []:
        sans.append({"type": kind, "value": value})
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    days = _days_left(not_after)
    leaf = {
        "subject": _flatten_name(cert.get("subject")),
        "issuer": _flatten_name(cert.get("issuer")),
        "serial": cert.get("serialNumber"),
        "version": cert.get("version"),
        "not_before": _parse_when(not_before),
        "not_after": _parse_when(not_after),
        "days_remaining": days,
        "expired": days is not None and days < 0,
        "sans": sans,
        "ocsp": list(cert.get("OCSP") or []),
        "ca_issuers": list(cert.get("caIssuers") or []),
        "crl": list(cert.get("crlDistributionPoints") or []),
        "sha256": _sha256(der) if der else None,
        "pem": ssl.DER_cert_to_PEM_cert(der).strip() if der else None,
    }
    if der:
        try:
            extra = _leaf_from_der(der)
            for key in ("ocsp", "ca_issuers", "crl"):
                if extra.get(key):
                    leaf[key] = extra[key]
            if extra.get("version") is not None:
                leaf["version"] = extra["version"]
        except Exception:
            pass
    return leaf


def _resolve(host: str) -> Tuple[str, int, str]:
    host = unbracket_host(host)
    try:
        ip = str(ipaddress.ip_address(host))
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return ip, family, ip
    except ValueError:
        pass
    name = normalize_qname(host, qtype="A").rstrip(".")
    ip, family, _sockaddr = resolve_probe_host(name)
    return ip, family, name


def _handshake(
    ip: str,
    family: int,
    port: int,
    sni: Optional[str],
    *,
    verify: bool,
) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = bool(sni) and not _is_ip(sni)
        ctx.verify_mode = ssl.CERT_REQUIRED
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(8.0)
        dest = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
        sock.connect(dest)
        server_hostname = sni if (sni and not _is_ip(sni)) else None
        ssock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        try:
            der = ssock.getpeercert(binary_form=True)
            cert = ssock.getpeercert() or {}
            chain_der: List[bytes] = []
            getter = getattr(ssock, "get_unverified_chain", None)
            if callable(getter):
                chain_der = [bytes(item) for item in (getter() or [])]
            cipher = ssock.cipher()
            alpn = None
            try:
                alpn = ssock.selected_alpn_protocol()
            except Exception:
                pass
            chain = []
            for idx, item in enumerate(chain_der or ([der] if der else [])):
                chain.append(
                    {
                        "index": idx,
                        "sha256": _sha256(item),
                        "pem": ssl.DER_cert_to_PEM_cert(item).strip(),
                        "leaf": idx == 0,
                    }
                )
            return {
                "ok": True,
                "verified": bool(verify),
                "protocol": ssock.version(),
                "cipher": {
                    "name": cipher[0] if cipher else None,
                    "protocol": cipher[1] if cipher else None,
                    "bits": cipher[2] if cipher else None,
                },
                "alpn": alpn,
                "sni": server_hostname,
                "leaf": _leaf_from_cert(cert, der),
                "chain": chain,
                "error": None,
            }
        finally:
            try:
                ssock.close()
            except OSError:
                pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _is_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _name_ok(leaf: Dict[str, Any], hostname: str) -> Optional[bool]:
    if _is_ip(hostname):
        want = hostname.lower()
        for san in leaf.get("sans") or []:
            if str(san.get("type") or "").lower().startswith("ip") and str(san.get("value") or "").lower() == want:
                return True
        return False
    want = hostname.rstrip(".").lower()
    names = []
    cn = (leaf.get("subject") or {}).get("commonName")
    if cn:
        names.append(cn)
    for san in leaf.get("sans") or []:
        if str(san.get("type") or "").upper() in {"DNS", "DNSNAME"}:
            names.append(str(san.get("value") or ""))
    if not names:
        return False
    for name in names:
        n = name.rstrip(".").lower()
        if n == want:
            return True
        if n.startswith("*.") and want.count(".") == n.count("."):
            if want.split(".", 1)[-1] == n.split(".", 1)[-1]:
                return True
    return False


async def _intel(ip: str) -> Dict[str, Any]:
    try:
        from pathlib import Path

        from ..intel_server.client import LOOKUP_SOCKET, lookup_json_async

        sock = Path(LOOKUP_SOCKET)
        if not sock.exists() or not (sock.parent / "lookup.ready").exists():
            return {}
        data = await lookup_json_async(ip, timeout=0.6)
        payload = (data or {}).get("result") or {}
        out: Dict[str, Any] = {}
        for key in (
            "asn",
            "org_name",
            "prefix",
            "country",
            "country_name",
            "flag",
            "flag_url",
            "flag_html",
        ):
            if payload.get(key) not in (None, False, ""):
                out[key] = payload[key]
        return out
    except Exception:
        return {}


async def inspect_tls_async(
    host: str,
    *,
    port: int = 443,
    sni: Optional[str] = None,
) -> Dict[str, Any]:
    start = time.time()

    def fail(
        error: str,
        *,
        ip: Optional[str] = None,
        family: Optional[int] = None,
        name: Optional[str] = None,
        sni_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "host": name or host,
            "port": int(port),
            "verified": False,
            "error": error,
        }
        if sni_name:
            result["sni"] = sni_name
        if ip:
            result["ip"] = ip
            result["endpoint"] = format_hostport(ip, port)
            if family is not None:
                result["family"] = "IPv4" if family == socket.AF_INET else "IPv6"
        return {
            "ok": False,
            "result": result,
            "error": error,
            "total_ms": round((time.time() - start) * 1000.0, 3),
        }

    try:
        ip, family, name = await asyncio.to_thread(_resolve, host)
    except Exception as exc:
        return fail(str(exc))
    sni_name = (sni or (None if _is_ip(host) else name) or None)
    error = None
    handshake: Dict[str, Any]
    try:
        handshake = await asyncio.to_thread(
            _handshake, ip, family, port, sni_name, verify=True
        )
    except ssl.SSLCertVerificationError as exc:
        error = str(exc)
        try:
            handshake = await asyncio.to_thread(
                _handshake, ip, family, port, sni_name, verify=False
            )
            handshake["verified"] = False
            handshake["error"] = error
        except Exception as inner:
            return fail(str(inner), ip=ip, family=family, name=name, sni_name=sni_name)
    except Exception as exc:
        return fail(str(exc), ip=ip, family=family, name=name, sni_name=sni_name)

    leaf = handshake.get("leaf") or {}
    name_ok = _name_ok(leaf, sni_name or name)
    intel = await _intel(ip)
    result = {
        "host": name,
        "ip": ip,
        "endpoint": format_hostport(ip, port),
        "family": "IPv4" if family == socket.AF_INET else "IPv6",
        "port": int(port),
        "sni": sni_name,
        "hostname_matches": name_ok,
        **intel,
        **handshake,
    }
    return {
        "ok": True,
        "result": result,
        "error": None,
        "total_ms": round((time.time() - start) * 1000.0, 3),
    }


def inspect_tls(host: str, **kwargs: Any) -> Dict[str, Any]:
    """Sync wrapper. Do not call from a running event loop."""
    return asyncio.run(inspect_tls_async(host, **kwargs))
