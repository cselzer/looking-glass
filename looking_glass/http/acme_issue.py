"""Let's Encrypt HTTP-01: issue and renew certs under ~/.looking-glass/certs."""

from __future__ import annotations

import errno
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..utility import get_certs_dir

DIRECTORY_PROD = "https://acme-v02.api.letsencrypt.org/directory"
DIRECTORY_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
RENEW_DAYS = 30
BIND_HINT = (
    "Cannot bind port {port} for Let's Encrypt HTTP-01 ({err}). "
    "Set net.ipv4.ip_unprivileged_port_start=0 (or 80) once on the host; "
    "this app does not run as root."
)

IssuerFn = Callable[..., Tuple[str, str]]


def certs_root() -> Path:
    return Path(get_certs_dir())


def host_dir(hostname: str) -> Path:
    dest = certs_root() / str(hostname or "").strip().rstrip(".").lower()
    dest.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(dest, 0o700)
    except OSError:
        pass
    return dest


def cert_files(hostname: str) -> Tuple[Path, Path]:
    folder = host_dir(hostname)
    return folder / "fullchain.pem", folder / "privkey.pem"


def cert_file_paths(hostname: str) -> Tuple[Path, Path]:
    """fullchain/privkey paths without creating directories."""
    folder = certs_root() / str(hostname or "").strip().rstrip(".").lower()
    return folder / "fullchain.pem", folder / "privkey.pem"


def account_key_path() -> Path:
    return certs_root() / "account.pem"


def bind_error_message(exc: BaseException, port: int) -> str:
    err = getattr(exc, "errno", None)
    name = errno.errorcode.get(err, "") if isinstance(err, int) else ""
    label = name or type(exc).__name__
    return BIND_HINT.format(port=int(port), err=label or str(exc) or "error")


def _load_cert(fullchain: Path) -> Optional[x509.Certificate]:
    try:
        pem = fullchain.read_bytes()
    except OSError:
        return None
    try:
        return x509.load_pem_x509_certificate(pem)
    except Exception:
        return None


def _cert_expiry(cert: x509.Certificate) -> datetime:
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is not None:
        return expiry
    naive = cert.not_valid_after
    if naive.tzinfo is None:
        return naive.replace(tzinfo=timezone.utc)
    return naive


def _name_map(name: x509.Name) -> Dict[str, str]:
    oid_to_key = {
        NameOID.COMMON_NAME: "commonName",
        NameOID.ORGANIZATION_NAME: "organizationName",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
        NameOID.COUNTRY_NAME: "countryName",
        NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
        NameOID.LOCALITY_NAME: "localityName",
    }
    out: Dict[str, str] = {}
    for attr in name:
        key = oid_to_key.get(attr.oid, attr.oid.dotted_string)
        out[key] = attr.value if isinstance(attr.value, str) else str(attr.value)
    return out


def _san_dns(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except Exception:
        return []
    return [str(name) for name in ext.value.get_values_for_type(x509.DNSName)]


def cert_not_after(fullchain: Path) -> Optional[datetime]:
    cert = _load_cert(fullchain)
    if cert is None:
        return None
    return _cert_expiry(cert)


def cert_info(fullchain: Path) -> Optional[Dict[str, Any]]:
    """Subject, issuer, SAN, and expiry. Never includes PEM or the private key."""
    cert = _load_cert(fullchain)
    if cert is None:
        return None
    expiry = _cert_expiry(cert)
    delta = expiry - datetime.now(timezone.utc)
    return {
        "subject": _name_map(cert.subject),
        "issuer": _name_map(cert.issuer),
        "san": _san_dns(cert),
        "not_after": expiry.isoformat(),
        "days_left": int(delta.total_seconds() // 86400),
    }


def needs_issue(hostname: str, days: int = RENEW_DAYS) -> bool:
    fullchain, key = cert_file_paths(hostname)
    if not fullchain.is_file() or not key.is_file():
        return True
    expiry = cert_not_after(fullchain)
    if expiry is None:
        return True
    return expiry <= datetime.now(timezone.utc) + timedelta(days=int(days))


def _write_secret(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


@contextmanager
def serve_http01(port: int, token: str, body: str) -> Iterator[None]:
    """Serve one ACME HTTP-01 token on 0.0.0.0:port."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            want = "/.well-known/acme-challenge/" + token
            if self.path.split("?", 1)[0] != want:
                self.send_error(404)
                return
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    try:
        httpd = HTTPServer(("0.0.0.0", int(port)), Handler)
    except OSError as exc:
        raise OSError(bind_error_message(exc, port)) from exc
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2.0)


def _load_or_create_account_key():
    import josepy as jose

    path = account_key_path()
    if path.is_file():
        pem = path.read_bytes()
        pkey = serialization.load_pem_private_key(pem, password=None)
        return jose.JWKRSA(key=pkey)
    pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_secret(path, pem.decode("ascii"))
    return jose.JWKRSA(key=pkey)


def _load_or_create_domain_key(privkey: Path):
    if privkey.is_file():
        return serialization.load_pem_private_key(privkey.read_bytes(), password=None)
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _domain_csr_pem(pkey, hostname: str) -> bytes:
    from acme import crypto_util

    pem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return crypto_util.make_csr(pem, [hostname])


def run_http01_order(
    hostname: str,
    email: str,
    *,
    staging: bool,
    acme_port: int,
    directory_url: Optional[str] = None,
) -> Tuple[str, str]:
    """Talk to Let's Encrypt; return (fullchain_pem, privkey_pem)."""
    from acme import challenges, client, messages

    url = directory_url or (DIRECTORY_STAGING if staging else DIRECTORY_PROD)
    account_key = _load_or_create_account_key()
    net = client.ClientNetwork(account_key, user_agent="looking-glass")
    directory = messages.Directory.from_json(net.get(url).json())
    acme = client.ClientV2(directory, net)
    try:
        acme.new_account(
            messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
        )
    except messages.Error as exc:
        if "already been registered" not in str(exc).lower():
            raise
    fullchain_path, privkey_path = cert_files(hostname)
    pkey = _load_or_create_domain_key(privkey_path)
    order = acme.new_order(_domain_csr_pem(pkey, hostname))
    for authz in order.authorizations:
        for challb in authz.body.challenges:
            if not isinstance(challb.chall, challenges.HTTP01):
                continue
            response, validation = challb.response_and_validation(account_key)
            token = str(challb.chall.encode("token"))
            with serve_http01(acme_port, token, validation):
                acme.answer_challenge(challb, response)
                order = acme.poll_and_finalize(order)
            break
    if not order.fullchain_pem:
        raise RuntimeError("ACME order did not return a certificate")
    priv_pem = pkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return order.fullchain_pem, priv_pem


def ensure_certificate(
    hostname: str,
    email: str,
    *,
    staging: bool = False,
    acme_port: int = 80,
    days: int = RENEW_DAYS,
    force: bool = False,
    issuer: Optional[IssuerFn] = None,
) -> Dict[str, str]:
    """Return cert paths, issuing or renewing when needed."""
    host = str(hostname or "").strip().rstrip(".").lower()
    mail = str(email or "").strip()
    if not host:
        raise ValueError("http.hostname is required to issue a certificate")
    if not mail:
        raise ValueError("http.email is required to issue a certificate")
    fullchain, privkey = cert_files(host)
    if not force and not needs_issue(host, days=days):
        return {"fullchain": str(fullchain), "privkey": str(privkey), "issued": False}
    fn = issuer or run_http01_order
    chain_pem, key_pem = fn(host, mail, staging=staging, acme_port=int(acme_port))
    _write_secret(fullchain, chain_pem)
    _write_secret(privkey, key_pem)
    return {"fullchain": str(fullchain), "privkey": str(privkey), "issued": True}


def write_self_signed(hostname: str, days: int = 90) -> Dict[str, str]:
    """Test helper: a local cert so expiry checks have a real PEM."""
    host = str(hostname or "localhost").strip().rstrip(".").lower()
    pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .public_key(pkey.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=int(days)))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(pkey, hashes.SHA256())
    )
    fullchain, privkey = cert_files(host)
    _write_secret(
        fullchain,
        cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )
    _write_secret(
        privkey,
        pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii"),
    )
    return {"fullchain": str(fullchain), "privkey": str(privkey), "issued": True}
