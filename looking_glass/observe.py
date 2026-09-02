"""Node identity stamped on every lookup JSON (hostname + egress IP + UTC time)."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


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


_KB = 1024
_DISK_NAME = re.compile(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|hd[a-z]+)$")
_VM_WANT = frozenset({"pgpgin", "pgpgout", "pswpin", "pswpout", "pgmajfault"})
_NET_SKIP_PREFIX = ("docker", "veth", "br-")
_RESOURCE_TTL_S = 1.0
_resource_cache: Optional[Tuple[float, Dict[str, Any]]] = None


def _proc_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _parse_meminfo(root: Path) -> Optional[Dict[str, int]]:
    raw: Dict[str, int] = {}
    for line in _proc_lines(root / "meminfo"):
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.split()
        if not parts:
            continue
        try:
            raw[key.strip()] = int(parts[0]) * _KB
        except ValueError:
            continue
    total = raw.get("MemTotal")
    available = raw.get("MemAvailable")
    if total is None or available is None:
        return None
    rss = 0
    for line in _proc_lines(root / "self" / "status"):
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    rss = int(parts[1]) * _KB
                except ValueError:
                    rss = 0
            break
    return {
        "total": total,
        "available": available,
        "used": total - available,
        "swap_total": raw.get("SwapTotal", 0),
        "swap_free": raw.get("SwapFree", 0),
        "rss": rss,
    }


def _parse_vmstat(root: Path) -> Optional[Dict[str, int]]:
    out: Dict[str, int] = {}
    for line in _proc_lines(root / "vmstat"):
        parts = line.split()
        if len(parts) != 2 or parts[0] not in _VM_WANT:
            continue
        try:
            out[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return out or None


def _parse_diskstats(root: Path) -> Optional[Dict[str, Dict[str, int]]]:
    out: Dict[str, Dict[str, int]] = {}
    for line in _proc_lines(root / "diskstats"):
        parts = line.split()
        if len(parts) < 14 or not _DISK_NAME.match(parts[2]):
            continue
        try:
            out[parts[2]] = {
                "reads": int(parts[3]),
                "writes": int(parts[7]),
                "rsec": int(parts[5]),
                "wsec": int(parts[9]),
                "in_progress": int(parts[11]),
            }
        except (IndexError, ValueError):
            continue
    return out or None


def _parse_netdev(root: Path) -> Optional[Dict[str, Dict[str, int]]]:
    out: Dict[str, Dict[str, int]] = {}
    for index, line in enumerate(_proc_lines(root / "net" / "dev")):
        if index < 2 or ":" not in line:
            continue
        name, rest = line.split(":", 1)
        iface = name.strip()
        if not iface or iface == "lo" or iface.startswith(_NET_SKIP_PREFIX):
            continue
        cols = rest.split()
        if len(cols) < 12:
            continue
        try:
            nums = [int(col) for col in cols[:12]]
        except ValueError:
            continue
        out[iface] = {
            "rx_bytes": nums[0],
            "rx_packets": nums[1],
            "rx_errs": nums[2],
            "rx_drop": nums[3],
            "tx_bytes": nums[8],
            "tx_packets": nums[9],
            "tx_errs": nums[10],
            "tx_drop": nums[11],
        }
    return out or None


def clear_host_resources_cache() -> None:
    global _resource_cache
    _resource_cache = None


def host_resources(*, proc_root: Optional[Path] = None, now: Optional[float] = None) -> Dict[str, Any]:
    """Linux /proc memory, vm, disk, and net counters. Never raises."""
    global _resource_cache
    live = proc_root is None
    stamp = time.monotonic() if now is None else float(now)
    if live and _resource_cache is not None:
        cached_at, cached = _resource_cache
        if stamp - cached_at < _RESOURCE_TTL_S:
            return dict(cached)
    root = Path(proc_root) if proc_root is not None else Path("/proc")
    out: Dict[str, Any] = {}
    try:
        mem = _parse_meminfo(root)
        if mem:
            out["memory"] = mem
        vm = _parse_vmstat(root)
        if vm:
            out["vm"] = vm
        io = _parse_diskstats(root)
        if io:
            out["io"] = io
        net = _parse_netdev(root)
        if net:
            out["net"] = net
    except Exception:
        out = {}
    if live:
        _resource_cache = (stamp, dict(out))
    return out


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
