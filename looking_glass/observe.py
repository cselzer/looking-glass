"""Node identity stamped on every lookup JSON (hostname + egress IP + UTC time)."""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def hostname() -> str:
    names: list[str] = []
    for getter in (socket.getfqdn, socket.gethostname):
        try:
            name = (getter() or "").strip().rstrip(".")
        except OSError:
            continue
        if name and name.lower() not in {"localhost", "localhost.localdomain"}:
            names.append(name)
    if not names:
        return (socket.gethostname() or "").strip()
    names.sort(key=lambda name: (name.count("."), len(name)), reverse=True)
    return names[0]


_DARWIN_CODENAMES = {
    "11": "Big Sur",
    "12": "Monterey",
    "13": "Ventura",
    "14": "Sonoma",
    "15": "Sequoia",
    "16": "Tahoe",
    "26": "Tahoe",
}


def _unquote_os(value: str) -> str:
    text = (value or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1].strip()
    return text


def _os_release() -> Dict[str, str]:
    path = Path("/etc/os-release")
    if not path.is_file():
        return {}
    out: Dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw = line.split("=", 1)
            out[key.strip()] = _unquote_os(raw)
    except OSError:
        return {}
    return out


def _darwin_os() -> Dict[str, Optional[str]]:
    name = "macOS"
    version = None
    try:
        name = subprocess.check_output(
            ["sw_vers", "-productName"], text=True, timeout=2
        ).strip() or "macOS"
        version = subprocess.check_output(
            ["sw_vers", "-productVersion"], text=True, timeout=2
        ).strip() or None
    except (OSError, subprocess.SubprocessError):
        version = platform.mac_ver()[0] or None
    major = (version or "").split(".", 1)[0]
    return {
        "os": name or "macOS",
        "os_version": version,
        "os_codename": _DARWIN_CODENAMES.get(major),
    }


def _kernel() -> Optional[str]:
    try:
        return platform.release() or None
    except Exception:
        return None


def host_os() -> Dict[str, Optional[str]]:
    """Operating system, version, codename, and kernel for GET /status. Never raises."""
    empty: Dict[str, Optional[str]] = {
        "os": None,
        "os_version": None,
        "os_codename": None,
        "kernel": None,
    }
    try:
        kernel = _kernel()
        system = platform.system()
        if system == "Linux":
            info = _os_release()
            return {
                "os": info.get("NAME") or "Linux",
                "os_version": info.get("VERSION_ID") or None,
                "os_codename": info.get("VERSION_CODENAME") or info.get("UBUNTU_CODENAME") or None,
                "kernel": kernel,
            }
        if system == "Darwin":
            out = _darwin_os()
            out["kernel"] = kernel
            return out
        return {
            "os": system or None,
            "os_version": platform.release() or None,
            "os_codename": None,
            "kernel": kernel,
        }
    except Exception:
        return empty


def _usable_ip(ip: str, *, allow_link_local: bool) -> bool:
    if not ip or ip in {"0.0.0.0", "::"}:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return False
    if not allow_link_local and addr.is_link_local:
        return False
    return True


def _pick_usable(candidates: list[str]) -> Optional[str]:
    for allow_link_local in (False, True):
        for ip in candidates:
            if _usable_ip(ip, allow_link_local=allow_link_local):
                return ip
    return None


def egress_addrs() -> Dict[str, Optional[str]]:
    found: Dict[int, list[str]] = {4: [], 6: []}
    for family, probe in (
        (socket.AF_INET, "1.1.1.1"),
        (socket.AF_INET6, "2606:4700:4700::1111"),
    ):
        try:
            sock = socket.socket(family, socket.SOCK_DGRAM)
        except OSError:
            continue
        try:
            sock.connect((probe, 80))
            ip = sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
        if not ip:
            continue
        try:
            version = ipaddress.ip_address(ip).version
        except ValueError:
            continue
        found[version].append(ip)
    return {"ipv4": _pick_usable(found[4]), "ipv6": _pick_usable(found[6])}


def egress_ip() -> Optional[str]:
    addrs = egress_addrs()
    return addrs["ipv4"] or addrs["ipv6"]


def observed_at(now: Optional[datetime] = None) -> str:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return current.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def attach_observation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Stamp probe host/ip and observed_at unless already set. Never raises."""
    if not isinstance(payload, dict):
        return payload
    try:
        if not payload.get("observed_at"):
            payload["observed_at"] = observed_at()
        probe = payload.get("probe")
        if not isinstance(probe, dict) or not (probe.get("host") or probe.get("ip")):
            payload["probe"] = {"host": hostname() or None, "ip": egress_ip()}
    except Exception:
        payload.setdefault("observed_at", observed_at())
        payload.setdefault("probe", {"host": None, "ip": None})
    return payload
