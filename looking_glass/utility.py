import os
import json
import tempfile
from typing import Callable, Dict, Iterable, List, Optional
import requests
import csv
import io
import ipaddress
import re

LogFn = Callable[[str], None]
ProgressFn = Callable[[int, Optional[int]], None]


def build_info(prefix: str, log: Optional[LogFn] = None) -> LogFn:
    """Return an info() logger. CLI passes `log` to drive progress; otherwise print."""

    def info(msg: str) -> None:
        if log is not None:
            try:
                log(msg)
            except Exception:
                pass
            return
        try:
            print(f"[{prefix}] {msg}")
        except Exception:
            pass

    return info

def get_root() -> str:
    """
    Return the application root directory (~/.looking-glass), creating it if missing.
    This mirrors the _get_db_path behavior but returns the directory (no 'data' suffix).
    """
    home = os.path.expanduser("~")
    app_root = os.path.join(home, ".looking-glass")
    os.makedirs(app_root, exist_ok=True)
    return app_root

def get_data_dir() -> str:
    """Return ~/.looking-glass/data (ensure exists)."""
    root = get_root()
    data_dir = os.path.join(root, "data")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir

def get_certs_dir() -> str:
    """Return ~/.looking-glass/certs (mode 0700)."""
    dest = os.path.join(get_root(), "certs")
    os.makedirs(dest, exist_ok=True)
    try:
        os.chmod(dest, 0o700)
    except OSError:
        pass
    return dest


def get_cache_path(name: str) -> str:
    """Return a full path for a cache file under data_dir."""
    return os.path.join(get_data_dir(), name)

def atomic_write(path: str, data: str, mode: str = "w", encoding: str = "utf-8") -> None:
    """Atomically write text to path."""
    dirn = os.path.dirname(path)
    os.makedirs(dirn, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dirn)
    try:
        with os.fdopen(fd, mode, encoding=encoding) as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass

def load_json_cache(path: str) -> Optional[dict]:
    """Load JSON file and return dict or None on error."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None

def save_json_cache(path: str, payload: dict) -> bool:
    try:
        atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=None))
        return True
    except Exception:
        return False

# network helper
DEFAULT_TIMEOUT = 30

def fetch_text(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    progress: Optional[ProgressFn] = None,
    log: Optional[LogFn] = None,
) -> Optional[str]:
    """GET url and return text. Optional progress(n, total) reports download bytes.

    Failures return None. Pass `log` to record URL, status, size, and exceptions
    (used by the CLI build.raw.log).
    """

    def note(msg: str) -> None:
        if log is None:
            return
        try:
            log(msg)
        except Exception:
            pass

    note(f"GET {url} (timeout={timeout}s)")
    try:
        with requests.get(url, timeout=timeout, stream=True) as r:
            ctype = r.headers.get("Content-Type") or "-"
            clen = r.headers.get("Content-Length") or "-"
            if r.status_code != 200:
                snippet = ""
                try:
                    chunk = next(r.iter_content(chunk_size=256), b"")
                    snippet = chunk[:200].decode("utf-8", errors="replace")
                    snippet = " ".join(snippet.split())
                except Exception:
                    snippet = ""
                extra = f"  {snippet}" if snippet else ""
                note(f"HTTP {r.status_code} {url}  content-type={ctype}  content-length={clen}{extra}")
                return None
            note(f"HTTP {r.status_code} {url}  content-type={ctype}  content-length={clen}")
            total = None
            cl = r.headers.get("Content-Length")
            if cl and str(cl).isdigit():
                total = int(cl)
            if progress is not None:
                try:
                    progress(0, total)
                except Exception:
                    pass
            chunks: list[bytes] = []
            for chunk in r.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                chunks.append(chunk)
                if progress is not None:
                    try:
                        progress(len(chunk), total)
                    except Exception:
                        pass
            data = b"".join(chunks)
            if not data:
                note(f"empty body from {url}")
                return None
            # Do not use r.apparent_encoding here: after iter_content() requests
            # raises "content already consumed" and we would discard the download.
            encoding = r.encoding or "utf-8"
            try:
                text = data.decode(encoding)
            except LookupError:
                encoding = "utf-8"
                text = data.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                encoding = "utf-8"
                text = data.decode("utf-8", errors="replace")
            note(f"downloaded {len(data)} bytes from {url}  encoding={encoding}")
            return text
    except Exception as exc:
        note(f"GET failed {url}: {type(exc).__name__}: {exc}")
        return None
    return None

# CSV rows helper
def safe_csv_rows(text: str, delimiter: str = ",") -> Iterable[List[str]]:
    f = io.StringIO(text)
    reader = csv.reader(f, delimiter=delimiter)
    for row in reader:
        yield [c.strip() for c in row]

def ip_network_to_range(net: ipaddress._BaseNetwork) -> Dict[str, int]:
    """Return start,end,prefix,num_ips for a network object."""
    return {
        "start": int(net.network_address),
        "end": int(net.broadcast_address),
        "prefix_len": net.prefixlen if hasattr(net, "prefixlen") else None,
        "num_ips": net.num_addresses,
    }

def parse_rir_delegated(text: str, source: str) -> List[dict]:
    """
    Parse an RIR delegated file text and return list of normalized entries.
    Each entry contains start,end,country,registry,type and some metadata.
    """
    out: List[dict] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        registry = parts[0]
        country = parts[1].upper()
        ip_type = parts[2].lower()
        if country == "*" or country == "":
            continue
        if ip_type == "ipv4":
            try:
                start_ip = parts[3]
                count = int(parts[4])
                start_int = int(ipaddress.IPv4Address(start_ip))
                end_int = start_int + count - 1
                out.append({
                    "start": start_int,
                    "end": end_int,
                    "country": country,
                    "registry": registry,
                    "type": "ipv4",
                    "start_ip": start_ip,
                    "num_ips": count,
                    "date": parts[5],
                    "status": parts[6],
                    "source": source,
                })
            except Exception:
                continue
        elif ip_type == "ipv6":
            try:
                start_net = parts[3]
                prefix = int(parts[4])
                net = ipaddress.IPv6Network(f"{start_net}/{prefix}", strict=False)
                r = ip_network_to_range(net)
                out.append({
                    "start": r["start"],
                    "end": r["end"],
                    "country": country,
                    "registry": registry,
                    "type": "ipv6",
                    "start_ip": start_net,
                    "prefix_len": prefix,
                    "date": parts[5],
                    "status": parts[6],
                    "source": source,
                })
            except Exception:
                continue
    return out

_IANA_FOOTNOTE = re.compile(r"\s*\[\d+\]\s*$")


def _strip_iana_footnotes(text: str) -> str:
    bit = str(text or "").strip().strip('"')
    while True:
        nxt = _IANA_FOOTNOTE.sub("", bit).strip().strip('"')
        if nxt == bit:
            return nxt
        bit = nxt


def _iana_address_blocks(cell: str) -> List[str]:
    """Split an IANA Address Block cell into CIDRs (footnotes and quoted lists)."""
    text = _strip_iana_footnotes(cell)
    out: List[str] = []
    for raw in text.split(","):
        bit = _strip_iana_footnotes(raw)
        if bit:
            out.append(bit)
    return out


def parse_iana_csv_text(text: str, source: str) -> List[dict]:
    """
    Parse IANA CSV text (safe_csv_rows can be used upstream) into entries
    with cidr,start,end,prefix_len,num_ips,designation,description,source.
    """
    out: List[dict] = []
    for row in safe_csv_rows(text):
        if not row:
            continue
        first = row[0]
        if first.startswith("#") or first.lower().startswith("address") or first == "":
            continue
        cidrs: List[str] = []
        consumed = 0
        for cell in row:
            bits = _iana_address_blocks(cell)
            valid: List[str] = []
            for bit in bits:
                try:
                    valid.append(str(ipaddress.ip_network(bit, strict=False).with_prefixlen))
                except Exception:
                    valid = []
                    break
            if not valid:
                break
            cidrs.extend(valid)
            consumed += 1
        if not cidrs:
            continue
        rest = row[consumed:]
        designation = rest[0] if rest else ""
        description = rest[1] if len(rest) > 1 else ""
        references = rest[2] if len(rest) > 2 else ""
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr, strict=False)
            r = ip_network_to_range(net)
            entry = {
                "cidr": str(net.with_prefixlen),
                "start": r["start"],
                "end": r["end"],
                "prefix_len": r["prefix_len"],
                "num_ips": r["num_ips"],
                "designation": designation,
                "description": description,
                "references": references,
                "source": source,
            }
            out.append(entry)
    out.sort(key=lambda x: x["start"])
    return out

