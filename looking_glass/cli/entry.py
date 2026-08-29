import ipaddress
import json
import os
import random
import sys
import time
import traceback
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import click
from tqdm import tqdm

from ..intel import asn as asn_mod
from ..intel import asn_org, iana, rir
from ..datasets import DATASETS as _DATASETS, EMPTY_CACHE_BYTES as _EMPTY_CACHE_BYTES, file_row as _file_row, refresh_due_at as _refresh_due_at
from ..dns import resolve
from ..intel_server.pipeline import classify_query as _detect_query, lookup_country as _lookup_country, lookup_ip as _lookup_ip, warmup as _warmup
from ..dns.reputation import check_rbls
from ..utility import atomic_write, get_cache_path, get_data_dir
from ..wall import lists as wall_lists
from .render import emit, emit_path

_COMMAND_ORDER = (
    "build",
    "validate",
    "docs",
    "complete",
    "locale",
    "config",
    "auth",
    "lookup-server",
    "https",
    "status",
    "restart",
    "boot",
    "lookup",
    "ip",
    "asn",
    "dns",
    "dnssec",
    "tls",
    "apex",
    "register",
    "ping",
    "traceroute",
    "mtr",
    "tcptraceroute",
    "rdap",
    "whois",
    "reputation",
    "bgp",
    "dnstrace",
    "http",
    "ptr",
    "mail",
    "tcp",
    "pmtu",
    "cache",
    "wall",
    "logs",
)


class _Group(click.Group):
    """Keep help in a human order instead of alphabetical."""

    def list_commands(self, ctx: click.Context) -> List[str]:
        names = list(self.commands)
        ordered = [name for name in _COMMAND_ORDER if name in self.commands]
        ordered.extend(name for name in names if name not in ordered)
        return ordered

    def parse_args(self, ctx: click.Context, args: List[str]) -> List[str]:
        args = _strip_json_flag(ctx, list(args))
        return super().parse_args(ctx, args)

    def get_help(self, ctx: click.Context) -> str:
        from ..i18n import overlay_click

        root = ctx.find_root().command
        if isinstance(root, click.Group):
            overlay_click(root)
        return super().get_help(ctx)


class _LookupGroup(_Group):
    """`looking-glass lookup 1.1.1.1` still looks up; `lookup bench` is a subcommand."""

    def parse_args(self, ctx: click.Context, args: List[str]) -> List[str]:
        args = list(args)
        help_names = tuple(ctx.help_option_names or ("--help", "-h"))
        if args and args[0] in self.commands:
            return super().parse_args(ctx, args)
        if args and args[0] in help_names:
            return super().parse_args(ctx, args)
        args.insert(0, "query")
        return super().parse_args(ctx, args)


def _strip_json_flag(ctx: click.Context, args: List[str]) -> List[str]:
    ctx.ensure_object(dict)
    kept: List[str] = []
    for arg in args:
        if arg in ("--json", "-j"):
            ctx.obj["json"] = True
            continue
        if arg.startswith("--json="):
            val = arg.split("=", 1)[1].strip().lower()
            ctx.obj["json"] = val not in ("0", "false", "no", "off", "")
            continue
        kept.append(arg)
    return kept


def _print_json(payload: Any) -> None:
    emit(payload)


def _print_jsonl(payload: Any) -> None:
    emit(payload, jsonl=True)


def _format_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


def _format_span(seconds: float) -> str:
    total = max(0, int(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts: List[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and not days:
        parts.append(f"{minutes}m")
    if not parts:
        return "less than a minute"
    return " ".join(parts)


def _format_secs(elapsed: float) -> str:
    if elapsed < 1:
        return f"{elapsed * 1000:.0f}ms"
    return f"{elapsed:.1f}s"


def _format_clock(ts: float) -> str:
    ms = int((ts % 1) * 1000)
    return time.strftime("%H:%M:%S", time.localtime(ts)) + f".{ms:03d}"


def _format_elapsed(seconds: float) -> str:
    """Elapsed with units; sub-millisecond work shows as µs, not 0 ms."""
    seconds = max(0.0, seconds)
    if seconds < 1e-6:
        return "<1 µs"
    if seconds < 1e-3:
        return f"{seconds * 1e6:.0f} µs"
    if seconds < 1:
        ms = seconds * 1e3
        if ms < 10:
            return f"{ms:.2f} ms"
        if ms < 100:
            return f"{ms:.1f} ms"
        return f"{ms:.0f} ms"
    if seconds < 10:
        return f"{seconds:.2f} s"
    return f"{seconds:.1f} s"


# Below these sizes the file exists but cannot be a complete dataset.
_MIN_CACHE_BYTES = {
    "iana.json": 8_000,
    "dns_types.json": 2_000,
    "tlds.json": 2_000,
    "rdap-dns.json": 20_000,
    "rir.json": 1_000_000,
    "asn2org.json": 100_000,
    "asn_prefix.ipasn.dat": 1_000_000,
}


def _read_refresh_policy() -> Dict[str, Any]:
    """Per-dataset days between automatic rebuilds, from ~/.looking-glass/config.json."""
    from ..config import refresh_policy

    return refresh_policy()


_BUILD_RAW_LOG = "build.raw.log"
_BUILD_LOG_WARN_BYTES = 300 * 1024 * 1024


def _build_raw_log_path() -> str:
    return get_cache_path(_BUILD_RAW_LOG)


class _BuildRawLog:
    """Append-only build transcript. Sessions are separated; writes are thread-safe."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = Lock()
        self._fp: Any = None

    def size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def open(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._fp = open(self.path, "a", encoding="utf-8", buffering=1)

    def write(self, line: str = "") -> None:
        with self._lock:
            if self._fp is None:
                return
            try:
                from looking_glass.logrotate import rotate_if_needed

                self._fp.flush()
                if rotate_if_needed(self.path):
                    try:
                        self._fp.close()
                    except Exception:
                        pass
                    self._fp = open(self.path, "a", encoding="utf-8", buffering=1)
            except Exception:
                pass
            try:
                self._fp.write(line.rstrip("\n") + "\n")
            except Exception:
                pass

    def event(self, dataset: str, msg: str) -> None:
        text = " ".join(str(msg).split())
        self._emit("event", dataset=str(dataset or ""), message=text)

    def block(self, text: str) -> None:
        payload = str(text or "")
        if not payload.strip():
            return
        self._emit("block", message=payload)

    def banner(self, *, force: bool, data_dir: str, planned: List[str]) -> None:
        self._emit(
            "banner",
            data={
                "argv": list(sys.argv),
                "python": sys.version.split()[0],
                "data": data_dir,
                "force": bool(force),
                "datasets": list(planned),
            },
        )

    def close_banner(self, elapsed: float) -> None:
        self._emit("end", data={"elapsed": round(float(elapsed), 3)})

    def _emit(
        self,
        event: str,
        *,
        dataset: str = "",
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        row: Dict[str, Any] = {
            "ts": time.time(),
            "logger": "build",
            "event": event,
            "dataset": dataset,
            "message": message,
        }
        if data:
            row["data"] = data
        try:
            self.write(json.dumps(row, ensure_ascii=False))
        except Exception:
            pass

    def close(self) -> None:
        with self._lock:
            if self._fp is None:
                return
            try:
                self._fp.flush()
                self._fp.close()
            except Exception:
                pass
            self._fp = None


def _format_when(ts: float) -> str:
    return time.strftime("%a %d %b %Y, %H:%M", time.localtime(ts))


def _refresh_policy_payload(policy: Dict[str, Any], *, force: bool = False) -> Dict[str, Any]:
    return {
        "path": policy.get("path"),
        "source": policy.get("source"),
        "force": force,
        "days": {key: (policy.get("days") or {}).get(key) for key, _mod, _fn, _label in _DATASETS},
        "invalid_keys": policy.get("invalid_keys") or [],
        "error": policy.get("error"),
    }


def _refresh_status_text(
    mtime: Optional[float],
    days: Optional[int],
    now: Optional[float] = None,
) -> str:
    now = now or time.time()
    if days is None:
        return "indefinite until config.json is valid, or --force"
    if mtime is None:
        return "on next build"
    due = _refresh_due_at(mtime, days)
    assert due is not None
    if due <= now:
        return f"due now (stale since {_format_when(due)})"
    return f"{_format_when(due)}  ({_format_span(due - now)} left)"


def _short(msg: str, width: int = 42) -> str:
    msg = " ".join(str(msg).split())
    return msg if len(msg) <= width else msg[: width - 1] + "…"


_STATUS_W = 18
_HOST_STATUS = (
    ("apnic", "APNIC"),
    ("arin", "ARIN"),
    ("lacnic", "LACNIC"),
    ("afrinic", "AFRINIC"),
    ("ripe", "RIPE"),
    ("iana.org", "IANA"),
)


def _human_status(msg: str) -> str:
    """Turn builder logs into a short postfix. Never leave a URL on the bar."""
    text = " ".join(str(msg).split())
    lower = text.lower()
    if "http://" in lower or "https://" in lower:
        for token, name in _HOST_STATUS:
            if token in lower:
                return f"↓ {name}"
        return "downloading"
    if "mrt record" in lower:
        return "reading RIB"
    if "converting" in lower:
        return "converting"
    if lower.startswith("parsed") or "parsing" in lower:
        return "parsing"
    if "saved" in lower or "ready" in lower:
        return "saving"
    if "download" in lower:
        return "downloading"
    if "starting" in lower or "checking" in lower:
        return "starting"
    return _short(text, _STATUS_W)


def _set_bar_status(bar: Any, text: str) -> None:
    # Put status in the description so tqdm does not prefix it with a comma.
    desc = getattr(bar, "_bar_desc", bar.desc)
    status = _human_status(text).ljust(_STATUS_W)
    bar.set_description_str(f"{desc}  {status}", refresh=True)


def _validate_check(
    check_id: str,
    check: str,
    status: str,
    detail: str,
    *,
    started: float,
    finished: Optional[float] = None,
) -> Dict[str, Any]:
    done = time.time() if finished is None else finished
    elapsed_s = max(0.0, done - started)
    return {
        "id": check_id,
        "check": check,
        "status": status,
        "detail": detail,
        "started": _format_clock(started),
        "finished": _format_clock(done),
        "elapsed": _format_elapsed(elapsed_s),
        "elapsed_s": elapsed_s,
    }


def _iana_blob(result: Dict[str, Any]) -> str:
    entry = result.get("iana")
    if not isinstance(entry, dict):
        return ""
    return " ".join(
        str(entry.get(key) or "")
        for key in ("designation", "description", "cidr", "prefix")
    ).lower()


_VALIDATE_SAMPLES = 3


def _ip_between(start: int, end: int, version: int, rng: random.Random) -> str:
    lo, hi = (int(start), int(end)) if start <= end else (int(end), int(start))
    n = rng.randint(lo, hi)
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return str(cls(n))


def _sample_from_bounds(
    starts: Any,
    ends: Any,
    extra: Any,
    version: int,
    rng: random.Random,
) -> Optional[Dict[str, Any]]:
    if not starts:
        return None
    idx = rng.randrange(len(starts))
    ip = _ip_between(starts[idx], ends[idx], version, rng)
    item: Dict[str, Any] = {"ip": ip, "version": version}
    if extra is not None:
        item["expect"] = extra[idx]
    return item


def _sample_iana_rows(rng: random.Random, n: int) -> List[Dict[str, Any]]:
    pools: List[Tuple[int, Any, Any, Any]] = []
    if iana._starts_v4 and iana._meta_v4:
        pools.append((4, iana._starts_v4, iana._ends_v4, iana._meta_v4))
    if iana._starts_v6 and iana._meta_v6:
        pools.append((6, iana._starts_v6, iana._ends_v6, iana._meta_v6))
    return _sample_pools(pools, n, rng)


def _sample_rir_rows(rng: random.Random, n: int) -> List[Dict[str, Any]]:
    pools: List[Tuple[int, Any, Any, Any]] = []
    if rir._starts_v4 and rir._meta_v4:
        pools.append((4, rir._starts_v4, rir._ends_v4, rir._meta_v4))
    if rir._starts_v6 and rir._meta_v6:
        pools.append((6, rir._starts_v6, rir._ends_v6, rir._meta_v6))
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for _ in range(n * 40):
        if len(rows) >= n or not pools:
            break
        version, starts, ends, extra = rng.choice(pools)
        item = _sample_from_bounds(starts, ends, extra, version, rng)
        if item is None:
            continue
        ip = item["ip"]
        if ip in seen:
            continue
        country = str(item.get("expect") or "")
        if len(country) != 2 or country in ("ZZ", "??"):
            continue
        if iana.find_for_ip(ip):
            continue
        hit = rir.get_country(ip)
        if not hit or hit.get("country") != country:
            continue
        seen.add(ip)
        rows.append({"ip": ip, "version": version, "country": country})
    return rows


def _sample_pools(
    pools: List[Tuple[int, Any, Any, Any]],
    n: int,
    rng: random.Random,
) -> List[Dict[str, Any]]:
    if not pools:
        return []
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    versions = [p[0] for p in pools]
    want_v6 = 1 if (n >= 2 and 6 in versions and 4 in versions) else 0
    for _ in range(n * 20):
        if len(rows) >= n:
            break
        have_v6 = sum(1 for row in rows if row["version"] == 6)
        if want_v6 and have_v6 < want_v6 and len(rows) >= n - want_v6:
            pool = next(p for p in pools if p[0] == 6)
        elif want_v6 and have_v6 >= want_v6 and 4 in versions:
            pool = next(p for p in pools if p[0] == 4)
        else:
            pool = rng.choice(pools)
        version, starts, ends, extra = pool
        item = _sample_from_bounds(starts, ends, extra, version, rng)
        if item is None or item["ip"] in seen:
            continue
        seen.add(item["ip"])
        rows.append(item)
    return rows


def _sample_asn_rows(rng: random.Random, n: int) -> List[Dict[str, Any]]:
    path = get_cache_path("asn_prefix.ipasn.dat")
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    if size < 64:
        return []
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    want_v6 = 1 if n >= 2 else 0
    with open(path, "rb") as fh:
        for _ in range(n * 50):
            if len(rows) >= n:
                break
            fh.seek(rng.randrange(size))
            fh.readline()
            raw = fh.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", "replace").strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                net = ipaddress.ip_network(parts[0], strict=False)
                asn = int(parts[1])
            except Exception:
                continue
            if asn <= 0:
                continue
            have_v6 = sum(1 for row in rows if row["version"] == 6)
            if want_v6 and have_v6 >= want_v6 and net.version == 6:
                continue
            if want_v6 and have_v6 < want_v6 and net.version == 4 and len(rows) >= n - want_v6:
                continue
            ip = _ip_between(
                int(net.network_address), int(net.broadcast_address), net.version, rng
            )
            if ip in seen or iana.find_for_ip(ip):
                continue
            origin = asn_mod.find_origin(ip)
            if not origin or origin.get("asn") != asn:
                continue
            if not rir.get_country(ip):
                continue
            seen.add(ip)
            rows.append(
                {
                    "ip": ip,
                    "asn": asn,
                    "prefix": str(origin.get("prefix") or net),
                    "version": net.version,
                }
            )
    return rows


def _file_validate_row(filename: str) -> Dict[str, Any]:
    """Inspect a cache file without collapsing empty into missing."""
    path = get_cache_path(filename)
    if not os.path.exists(path):
        return {"path": path, "state": "missing", "size": None, "mtime": None}
    st = os.stat(path)
    empty_limit = _EMPTY_CACHE_BYTES.get(filename)
    if empty_limit is not None and st.st_size <= empty_limit:
        return {"path": path, "state": "empty", "size": st.st_size, "mtime": st.st_mtime}
    minimum = _MIN_CACHE_BYTES.get(filename)
    if minimum is not None and st.st_size < minimum:
        return {"path": path, "state": "small", "size": st.st_size, "mtime": st.st_mtime}
    return {"path": path, "state": "ok", "size": st.st_size, "mtime": st.st_mtime}


def _run_validate(
    *,
    now: Optional[float] = None,
    seed: Optional[int] = None,
    on_working: Optional[Any] = None,
    on_check: Optional[Any] = None,
    on_note: Optional[Any] = None,
) -> Dict[str, Any]:
    """Validate ~/.looking-glass/data using the same load/lookup path as `looking-glass lookup`."""
    now = now or time.time()
    data_dir = get_data_dir()
    policy = _read_refresh_policy()
    t_run = time.time()
    seed = random.randrange(2**32) if seed is None else int(seed)
    rng = random.Random(seed)
    checks: List[Dict[str, Any]] = []
    loaded: Dict[str, bool] = {}
    lookup_cache: Dict[str, Dict[str, Any]] = {}

    def note(msg: str) -> None:
        if on_note is not None:
            on_note(msg)

    def working(title: str, started: float) -> None:
        if on_working is not None:
            on_working(title, started)

    def add(item: Dict[str, Any]) -> None:
        checks.append(item)
        if on_check is not None:
            on_check(item)

    def stamp(
        check_id: str, title: str, status: str, detail: str, started: float
    ) -> None:
        add(_validate_check(check_id, title, status, detail, started=started))

    note("Files")
    for key, mod, filename, label in _DATASETS:
        started = time.time()
        info = _file_validate_row(filename)
        size = info["size"]
        size_text = _format_bytes(size) if size is not None else "—"
        if info["state"] == "missing":
            stamp(f"file.{key}", label, "failed", "missing", started)
            loaded[key] = False
            continue
        if info["state"] == "empty":
            stamp(f"file.{key}", label, "failed", f"empty ({size_text})", started)
            loaded[key] = False
            continue
        if info["state"] == "small":
            need = _format_bytes(_MIN_CACHE_BYTES[filename])
            stamp(
                f"file.{key}",
                label,
                "failed",
                f"too small ({size_text}, need ≥ {need})",
                started,
            )
            loaded[key] = False
            continue
        stamp(f"file.{key}", label, "ok", size_text, started)

        days = policy["days"].get(key)
        due = _refresh_due_at(info["mtime"], days)
        if due is not None and due <= now:
            fresh_started = time.time()
            stamp(
                f"fresh.{key}",
                f"{label} freshness",
                "warn",
                _refresh_status_text(info["mtime"], days, now=now),
                fresh_started,
            )

    loadable = [
        (key, mod, label)
        for key, mod, _filename, label in _DATASETS
        if any(row["id"] == f"file.{key}" and row["status"] == "ok" for row in checks)
    ]
    if loadable:
        note("Loading")
    for key, mod, label in loadable:
        started = time.time()
        working(f"Load {label}", started)
        try:
            ok = bool(mod.load(force=False))
        except Exception as exc:
            stamp(f"load.{key}", f"Load {label}", "failed", str(exc), started)
            loaded[key] = False
            continue
        if not ok:
            stamp(
                f"load.{key}",
                f"Load {label}",
                "failed",
                "load returned false",
                started,
            )
            loaded[key] = False
            continue
        stamp(f"load.{key}", f"Load {label}", "ok", "loaded", started)
        loaded[key] = True

    if loaded.get("rdap_dns"):
        started = time.time()
        from ..intel import rdap as rdap_mod

        jp_urls = rdap_mod.domain_rdap_urls("jprs.jp")
        de_urls = rdap_mod.domain_rdap_urls("xn--bcher-kva.de")
        org = [url for url in list(jp_urls) + list(de_urls) if "rdap.org" in url]
        de_ok = bool(de_urls) and "rdap.denic.de" in de_urls[0] and not org
        if jp_urls or not de_ok:
            detail = "jp invented or de not DENIC"
            if org:
                detail = "jp/de mapped to rdap.org"
            elif jp_urls:
                detail = f"jp has RDAP URL {jp_urls[0]}"
            elif not de_urls:
                detail = "de missing from bootstrap"
            stamp("rdap.bootstrap", "RDAP DNS bootstrap", "failed", detail, started)
        else:
            stamp(
                "rdap.bootstrap",
                "RDAP DNS bootstrap",
                "ok",
                f"jp=none de={de_urls[0]}",
                started,
            )

    def lookup(ip: str, started: float) -> Dict[str, Any]:
        cached = lookup_cache.get(ip)
        if cached is not None:
            return cached
        working(f"Look up {ip}", started)
        payload = _lookup_ip(ip, load=False)
        lookup_cache[ip] = payload
        return payload

    def skipped(check_id: str, title: str, need: Tuple[str, ...], started: float) -> bool:
        missing = [name for name in need if not loaded.get(name)]
        if not missing:
            return False
        stamp(
            check_id,
            title,
            "failed",
            "skipped (dataset failed: " + ", ".join(missing) + ")",
            started,
        )
        return True

    def probe_lookup(
        check_id: str,
        title: str,
        ip: str,
        need: Tuple[str, ...],
        fn: Any,
    ) -> None:
        started = time.time()
        if skipped(check_id, title, need, started):
            return
        try:
            payload = lookup(ip, started)
        except Exception as exc:
            stamp(check_id, title, "failed", str(exc), started)
            return
        result = payload.get("result") or {}
        ok, detail = fn(result)
        stamp(check_id, title, "ok" if ok else "failed", detail, started)

    def title_for(kind: str, ip: str) -> str:
        return f"{kind} {ip}"

    note("Lookups")
    if not loaded.get("iana"):
        stamp(
            "sample.iana",
            "IANA samples",
            "failed",
            "skipped (dataset failed: iana)",
            time.time(),
        )
    else:
        iana_rows = _sample_iana_rows(rng, _VALIDATE_SAMPLES)
        if not iana_rows:
            stamp(
                "sample.iana",
                "IANA samples",
                "failed",
                "no IANA ranges to sample",
                time.time(),
            )
        for i, row in enumerate(iana_rows):
            expect = row.get("expect") if isinstance(row.get("expect"), dict) else {}

            def iana_match(result: Dict[str, Any], meta: Dict[str, Any] = expect) -> Tuple[bool, str]:
                blob = _iana_blob(result)
                ok = result.get("source") == "iana" and bool(blob)
                cidr = str(meta.get("cidr") or meta.get("prefix") or "")
                detail = blob.strip() or cidr or "no IANA match"
                return ok, detail

            probe_lookup(
                f"sample.iana.{i}",
                title_for("IANA", row["ip"]),
                row["ip"],
                ("iana",),
                iana_match,
            )

    if not loaded.get("rir") or not loaded.get("iana"):
        missing = [name for name in ("iana", "rir") if not loaded.get(name)]
        stamp(
            "sample.rir",
            "RIR samples",
            "failed",
            "skipped (dataset failed: " + ", ".join(missing) + ")",
            time.time(),
        )
    else:
        rir_rows = _sample_rir_rows(rng, _VALIDATE_SAMPLES)
        if not rir_rows:
            stamp(
                "sample.rir",
                "RIR samples",
                "failed",
                "no RIR ranges to sample",
                time.time(),
            )
        for i, row in enumerate(rir_rows):
            want = row["country"]

            def country_match(result: Dict[str, Any], code: str = want) -> Tuple[bool, str]:
                got = str(result.get("country") or "")
                ok = result.get("source") == "rir" and got == code
                detail = got if ok else f"{got or 'none'} (expect {code})"
                return ok, detail or "no country"

            probe_lookup(
                f"sample.rir.{i}",
                title_for("RIR", row["ip"]),
                row["ip"],
                ("rir",),
                country_match,
            )

    if not loaded.get("asn") or not loaded.get("rir") or not loaded.get("iana"):
        missing = [name for name in ("iana", "rir", "asn") if not loaded.get(name)]
        stamp(
            "sample.asn",
            "ASN samples",
            "failed",
            "skipped (dataset failed: " + ", ".join(missing) + ")",
            time.time(),
        )
    else:
        asn_rows = _sample_asn_rows(rng, _VALIDATE_SAMPLES)
        if not asn_rows:
            stamp(
                "sample.asn",
                "ASN samples",
                "failed",
                "no ASN prefixes to sample",
                time.time(),
            )
        for i, row in enumerate(asn_rows):
            want_asn = row["asn"]
            want_prefix = row["prefix"]

            def asn_match(
                result: Dict[str, Any],
                number: int = want_asn,
                prefix: str = want_prefix,
            ) -> Tuple[bool, str]:
                got = result.get("asn")
                got_prefix = result.get("prefix") or ""
                ok = got == number
                detail = f"AS{got} {got_prefix}".strip() if got not in (None, False) else "no ASN"
                if not ok:
                    detail = f"{detail} (expect AS{number} {prefix})"
                return ok, detail

            probe_lookup(
                f"sample.asn.{i}",
                title_for("ASN", row["ip"]),
                row["ip"],
                ("rir", "asn"),
                asn_match,
            )
            if not loaded.get("asn_org"):
                continue
            org = asn_org.find_org(want_asn)
            if not org or not org.get("name"):
                continue
            want_org = str(org["name"])

            def org_match(result: Dict[str, Any], name: str = want_org) -> Tuple[bool, str]:
                got = str(result.get("org_name") or "")
                ok = got == name
                detail = got if ok else f"{got or 'none'} (expect {name})"
                return ok, detail or "no organization"

            probe_lookup(
                f"sample.org.{i}",
                title_for("Org", row["ip"]),
                row["ip"],
                ("rir", "asn", "asn_org"),
                org_match,
            )

    if loaded.get("asn") and not loaded.get("asn_org"):
        stamp(
            "sample.org",
            "Org samples",
            "failed",
            "skipped (dataset failed: asn_org)",
            time.time(),
        )

    failed = sum(1 for row in checks if row["status"] == "failed")
    warned = sum(1 for row in checks if row["status"] == "warn")
    t_done = time.time()
    elapsed_s = max(0.0, t_done - t_run)
    return {
        "ok": failed == 0,
        "data": data_dir,
        "failed": failed,
        "warned": warned,
        "seed": seed,
        "started": _format_clock(t_run),
        "finished": _format_clock(t_done),
        "elapsed": _format_elapsed(elapsed_s),
        "elapsed_s": elapsed_s,
        "checks": checks,
    }


def _classify_lookup(value: str) -> Tuple[str, str]:
    """IP, ASN, country, or a DNS name."""
    try:
        return _detect_query(value)
    except ValueError:
        pass
    from ..dns.resolve import is_dns_name

    if is_dns_name(value):
        return "dns", str(value).strip()
    raise click.BadParameter(f"{value!r} is not an IP address, ASN, country code, or DNS name")


def _daemon_running() -> bool:
    """True when the intel server pid is alive, ready, and its socket is present."""
    data = get_data_dir()
    sock = os.path.join(data, "lookup.sock")
    pidfile = os.path.join(data, "lookup.pid")
    if not os.path.exists(sock):
        return False
    if not os.path.exists(os.path.join(data, "lookup.ready")):
        return False
    try:
        with open(pidfile, encoding="utf-8") as fh:
            pid = int(fh.read().strip())
    except Exception:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False
    return True


def _lookup_prefer_daemon(kind: str, value: str) -> Tuple[Dict[str, Any], str]:
    """Use the Unix-socket intel server when it is up; otherwise look up in-process.

    Returns (payload, "intel" | "local"). "local" means the intel server was not
    running. If the intel server looked up but the request failed, the payload is
    still produced in-process and the via stays "intel" so the CLI stays quiet.
    """
    def _local() -> Dict[str, Any]:
        if kind == "country":
            return _lookup_country(value)
        return _lookup_ip(value)

    if not _daemon_running():
        return _local(), "local"
    try:
        from ..intel_server.client import lookup_json

        payload = lookup_json(
            value,
            socket_path=os.path.join(get_data_dir(), "lookup.sock"),
            timeout=5.0 if kind == "country" else 0.5,
        )
        if payload:
            return payload, "intel"
    except Exception:
        pass
    return _local(), "intel"


def _parse_rbl_map(rbls: Tuple[str, ...]) -> Optional[Dict[str, str]]:
    if not rbls:
        return None
    parsed: Dict[str, str] = {}
    for item in rbls:
        if "=" in item:
            name, domain = item.split("=", 1)
            parsed[name.strip()] = domain.strip()
        else:
            parsed[item] = item
    return parsed


def _read_query_lines(stream) -> List[str]:
    lines: List[str] = []
    for raw in stream:
        text = str(raw).strip()
        if not text or text.startswith("#"):
            continue
        lines.append(text)
    return lines


def _bulk_concurrency(requested: Optional[int], do_rbl: bool) -> int:
    if requested is not None and requested > 0:
        return requested
    return 16 if do_rbl else 128


def _run_bulk_lookup(
    queries: List[str],
    *,
    do_rbl: bool,
    rbl_map: Optional[Dict[str, str]],
    timeout: float,
    force: bool,
    concurrency: int,
    rrtype: Optional[str] = None,
    nameserver: Optional[str] = None,
    ns_port: Optional[int] = None,
) -> None:
    """Stream one compact JSON object per line. Progress goes to stderr."""

    async def _run() -> None:
        from ..dns.reputation import check_rbl_cached_async, dns_resolver

        daemon = _daemon_running()
        session = None
        sock = os.path.join(get_data_dir(), "lookup.sock")
        pool: Optional[ThreadPoolExecutor] = None
        if daemon:
            from ..intel_server.client import aiohttp, lookup_json_async

            conn = aiohttp.UnixConnector(path=sock, limit=max(concurrency, 4))
            session = aiohttp.ClientSession(connector=conn)
        else:
            _warmup()
            pool = ThreadPoolExecutor(max_workers=min(32, max(4, concurrency)))

        resolver = dns_resolver(timeout) if do_rbl else None
        loop = asyncio.get_running_loop()
        local_ready = not daemon
        progress = tqdm(
            total=len(queries),
            unit="ip",
            file=sys.stderr,
            mininterval=0.2,
            smoothing=0.1,
        )

        async def lookup_one(text: str) -> Dict[str, Any]:
            nonlocal local_ready, pool
            try:
                kind, value = _classify_lookup(text)
            except click.BadParameter:
                return {"ok": False, "query": text, "error": "not an IP address, ASN, country code, or DNS name"}
            if kind == "dns":
                if do_rbl:
                    return {"ok": False, "query": text, "error": "--rbl only applies to IP addresses"}
                from ..dns.resolve import lookup_dns_async

                try:
                    return await lookup_dns_async(
                        value,
                        rrtype or "A",
                        timeout=max(timeout, 2.0),
                        server=nameserver,
                        port=ns_port,
                    )
                except ValueError as e:
                    return {"ok": False, "name": value, "error": str(e)}
            if kind == "asn":
                try:
                    res = asn_org.find_org(value)
                    fetched_at = int(asn_org.get_fetched_at() or 0)
                except Exception as e:
                    return {
                        "ok": False,
                        "asn": value,
                        "result": None,
                        "fetched_at": None,
                        "error": str(e),
                    }
                return {
                    "ok": True,
                    "asn": value,
                    "result": res,
                    "fetched_at": fetched_at,
                    "error": None,
                }
            if kind == "country":
                payload = None
                via = "local"
                if session is not None:
                    from ..intel_server.client import lookup_json_async

                    payload = await lookup_json_async(
                        value,
                        socket_path=sock,
                        timeout=max(timeout, 5.0),
                        session=session,
                    )
                    if payload:
                        via = "intel"
                if payload is None:
                    if not local_ready:
                        _warmup()
                        local_ready = True
                        if pool is None:
                            pool = ThreadPoolExecutor(max_workers=min(32, max(4, concurrency)))
                    payload = await loop.run_in_executor(
                        pool, lambda cc=value: _lookup_country(cc, load=False)
                    )
                    via = "local"
                out = dict(payload)
                out["via"] = via
                out["intel"] = {"running": daemon}
                if not daemon:
                    out["intel"]["message"] = "Intel server is not running."
                return out

            via = "local"
            payload = None
            if session is not None:
                from ..intel_server.client import lookup_json_async

                payload = await lookup_json_async(
                    value, socket_path=sock, timeout=max(timeout, 0.5), session=session
                )
                if payload:
                    via = "intel"
            if payload is None:
                if not local_ready:
                    _warmup()
                    local_ready = True
                    if pool is None:
                        pool = ThreadPoolExecutor(max_workers=min(32, max(4, concurrency)))
                payload = await loop.run_in_executor(
                    pool, lambda ip=value: _lookup_ip(ip, load=False)
                )
                via = "local"
            out = dict(payload)
            out["via"] = via
            out["intel"] = {"running": daemon}
            if not daemon:
                out["intel"]["message"] = "Intel server is not running."
            if do_rbl:
                out["rbl"] = await check_rbl_cached_async(
                    value, rbl_map, timeout, force=force, resolver=resolver
                )
            return out

        try:
            for i in range(0, len(queries), concurrency):
                batch = queries[i : i + concurrency]
                recs = await asyncio.gather(
                    *[lookup_one(q) for q in batch], return_exceptions=True
                )
                for rec, query in zip(recs, batch):
                    if isinstance(rec, Exception):
                        rec = {"ok": False, "query": query, "error": str(rec)}
                    _print_jsonl(rec)
                    progress.update(1)
        finally:
            progress.close()
            if session is not None:
                await session.close()
            if pool is not None:
                pool.shutdown(wait=False)

    asyncio.run(_run())


def _apply_lang(ctx: click.Context, _param: click.Parameter, value: Optional[str]) -> Optional[str]:
    from ..i18n import overlay_click, resolve_locale, set_locale

    set_locale(resolve_locale(explicit=value))
    cmd = ctx.command if isinstance(ctx.command, click.Group) else None
    if cmd is not None:
        overlay_click(cmd)
    return value


def _apply_json(ctx: click.Context, _param: click.Parameter, value: bool) -> bool:
    ctx.ensure_object(dict)
    if value:
        ctx.obj["json"] = True
    return value


@click.group(
    cls=_Group,
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 88},
)
@click.option(
    "--lang",
    default=None,
    envvar="LOOKING_GLASS_LANG",
    is_eager=True,
    callback=_apply_lang,
    help="UI locale for help and HTML. JSON lookups stay English.",
)
@click.option(
    "--json",
    "-j",
    "as_json",
    is_flag=True,
    is_eager=True,
    envvar="LOOKING_GLASS_JSON",
    callback=_apply_json,
    help="Print JSON on stdout instead of a compact terminal view.",
)
@click.version_option(package_name="looking-glass", prog_name="looking-glass")
@click.pass_context
def cli(ctx: click.Context, lang: Optional[str], as_json: bool) -> None:
    """Local IP intelligence: country, ASN, and organization.

    Commands print a compact terminal view. Pass `--json` (or set LOOKING_GLASS_JSON=1)
    for the machine JSON dump. A single lookup is one object; `--file` or `-`
    writes one JSON object per line (JSONL) when `--json` is set.

    \b
    Get started:
      looking-glass build
      looking-glass validate
      looking-glass lookup 1.1.1.1
      looking-glass dns example.com DS
      looking-glass lookup --file ips.txt
      looking-glass lookup bench 1.1.1.1
      looking-glass docs
      looking-glass lookup-server start
      looking-glass wall block ip 203.0.113.0/24
      looking-glass wall list ip
      looking-glass --json wall list

    Datasets live in ~/.looking-glass/data. Build once, then look up as many IPs as you want.
    The intel server (lookup-server) uses a Unix socket in that same directory.
    """
    ctx.ensure_object(dict)
    if as_json:
        ctx.obj["json"] = True
    from ..i18n import overlay_click, resolve_locale, set_locale

    set_locale(resolve_locale(explicit=lang))
    overlay_click(ctx.command)


@cli.command("docs")
@click.argument("path", required=False, type=click.Path())
def docs_cmd(path: Optional[str]) -> None:
    """Write HTML docs for the HTTP API, Click CLI, and web GUI.

    Default path is ~/.looking-glass/data/docs.html (what GET /docs serves). Pass a
    path to write a copy anywhere.
    """
    from ..docs.generate import write_docs

    dest = write_docs(path)
    emit_path(dest)


@cli.command("complete")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"], case_sensitive=False))
def complete_cmd(shell: str) -> None:
    """Print a bash, zsh, or fish completion script.

    \b
      eval "$(looking-glass complete bash)"
      eval "$(looking-glass complete zsh)"
      looking-glass complete fish | source
    """
    from click.shell_completion import get_completion_class

    cls = get_completion_class(str(shell).lower())
    if cls is None:
        raise click.UsageError(f"unsupported shell {shell!r}")
    click.echo(cls(cli, {}, "looking-glass", "_LOOKING_GLASS_COMPLETE").source())


@cli.command("build")
@click.option("--force", is_flag=True, help="Re-download even if caches already exist.")
@click.option("--all", "all_flag", is_flag=True, help="Build every dataset (this is the default).")
@click.option("--iana", "do_iana", is_flag=True, help="IANA special-use ranges only.")
@click.option("--dns-types", "do_dns_types", is_flag=True, help="IANA DNS RR types only.")
@click.option("--tlds", "do_tlds", is_flag=True, help="IANA TLD list only.")
@click.option("--rdap-dns", "do_rdap_dns", is_flag=True, help="IANA RDAP DNS bootstrap only.")
@click.option("--rir", "do_rir", is_flag=True, help="RIR country allocations only.")
@click.option("--asn", "do_asn", is_flag=True, help="ASN origin prefixes only (slow; RouteViews RIB).")
@click.option("--asn-org", "do_asn_org", is_flag=True, help="ASN organization names only (RIPE).")
@click.option("-v", "--verbose", is_flag=True, help="Show each download/parse step.")
def build_cmd(
    force: bool,
    all_flag: bool,
    do_iana: bool,
    do_dns_types: bool,
    do_tlds: bool,
    do_rdap_dns: bool,
    do_rir: bool,
    do_asn: bool,
    do_asn_org: bool,
    verbose: bool,
) -> None:
    """Download lookup datasets into ~/.looking-glass/data.

    Each dataset refreshes on its own schedule from ~/.looking-glass/config.json
    (created with defaults if missing). Pass --force to fetch everything now.
    The ASN origin step can take several minutes. Progress bars go to stderr;
    the result is a compact terminal view (or JSON with `--json`).
    """
    selected = {
        "iana": do_iana,
        "dns_types": do_dns_types,
        "tlds": do_tlds,
        "rdap_dns": do_rdap_dns,
        "rir": do_rir,
        "asn": do_asn,
        "asn_org": do_asn_org,
    }
    if not any(selected.values()) or all_flag:
        selected = {key: True for key in selected}

    planned = [row for row in _DATASETS if selected[row[0]]]
    data_dir = get_data_dir()
    now = time.time()
    session_t0 = now
    policy = None if force else _read_refresh_policy()
    raw_path = _build_raw_log_path()
    raw = _BuildRawLog(raw_path)
    size_before = raw.size()
    log_error: Optional[str] = None

    try:
        raw.open()
        raw.banner(force=force, data_dir=data_dir, planned=[row[3] for row in planned])
    except Exception as exc:
        log_error = str(exc)

    jobs: List[Tuple[Any, ...]] = []
    datasets: List[Dict[str, Any]] = []

    for key, mod, filename, label in planned:
        info = _file_row(filename)
        days = None if policy is None else policy["days"].get(key)
        rebuild = force or not info["exists"]
        if not rebuild and days is not None:
            due = _refresh_due_at(info["mtime"], days)
            rebuild = due is not None and due <= now
        if rebuild:
            jobs.append((key, mod, filename, label, bool(info["exists"]), days))
        else:
            datasets.append(
                {
                    "key": key,
                    "label": label,
                    "result": "up_to_date",
                    "elapsed_s": None,
                    "size": info["size"],
                    "next_refresh": _refresh_status_text(info["mtime"], days, now=now),
                    "error": None,
                }
            )
            raw.event(
                "-",
                f"skip {label}  size={_format_bytes(info['size'])}  refresh={datasets[-1]['next_refresh']}",
            )

    failed_any = False
    cancelled = False
    job_results: Dict[str, Tuple[bool, float, Optional[str]]] = {}

    try:
        if jobs:
            tqdm.set_lock(Lock())
            bars: Dict[str, Any] = {}
            hooks: Dict[str, Tuple[Any, Any, Dict[str, str]]] = {}
            label_width = max(len(job[3]) for job in jobs)

            def make_hooks(key: str, label: str, bar: Any) -> Tuple[Any, Any, Dict[str, str]]:
                state: Dict[str, str] = {"msg": ""}

                def log(msg: str) -> None:
                    state["msg"] = msg
                    raw.event(key, msg)
                    _set_bar_status(bar, msg)
                    if verbose and "mrt record" not in str(msg).lower():
                        tqdm.write(f"    {label}: {msg}", file=sys.stderr)

                def progress(n: int, _total: Optional[int] = None) -> None:
                    if n:
                        bar.update(n)

                return log, progress, state

            def run_job(job: Tuple[Any, ...]) -> Tuple[str, bool, float, Optional[str]]:
                key, mod, _filename, label, existed, _days = job
                log, progress, state = hooks[key]
                t0 = time.time()
                raw.event(key, f"job start  force={force or existed}")
                try:
                    ok = bool(mod.build(force=force or existed, log=log, progress=progress))
                    elapsed = time.time() - t0
                    if not ok:
                        err = state["msg"] or "build failed"
                        raw.event(key, f"job failed  {elapsed:.1f}s  {err}")
                        return key, False, elapsed, err
                    raw.event(key, f"job ok  {elapsed:.1f}s")
                    return key, True, elapsed, None
                except Exception as exc:
                    elapsed = time.time() - t0
                    tb = traceback.format_exc()
                    raw.event(key, f"job exception  {elapsed:.1f}s  {exc}")
                    raw.block(tb)
                    if verbose:
                        tqdm.write(tb, file=sys.stderr)
                    return key, False, elapsed, str(exc)

            try:
                for i, job in enumerate(jobs):
                    key, _mod, _filename, label, _existed, _days = job
                    bar = tqdm(
                        desc=label.ljust(label_width),
                        position=i,
                        unit="B",
                        unit_scale=True,
                        unit_divisor=1024,
                        mininterval=0.2,
                        smoothing=0.15,
                        ncols=88,
                        leave=True,
                        file=sys.stderr,
                        bar_format="{desc}  {n_fmt:>7}  {rate_fmt:>10}  {elapsed}",
                    )
                    bar._bar_desc = label.ljust(label_width)
                    _set_bar_status(bar, "starting")
                    bars[key] = bar
                    hooks[key] = make_hooks(key, label, bar)
                    raw.event(key, "queued")

                with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
                    futs = {pool.submit(run_job, job): job[0] for job in jobs}
                    for fut in as_completed(futs):
                        key, ok, elapsed, error = fut.result()
                        job_results[key] = (ok, elapsed, error)
                        _set_bar_status(bars[key], "done" if ok else "failed")
                for bar in bars.values():
                    bar.close()
            except KeyboardInterrupt:
                cancelled = True
                raw.event("-", "cancelled (KeyboardInterrupt)")
                for bar in bars.values():
                    bar.close()
            finally:
                for bar in bars.values():
                    try:
                        bar.close()
                    except Exception:
                        pass

            if not cancelled:
                if policy is None:
                    policy = _read_refresh_policy()
                for key, _mod, filename, label, _existed, days in jobs:
                    ok, elapsed, error = job_results.get(key, (False, 0.0, "no result"))
                    info = _file_row(filename)
                    if days is None and policy is not None:
                        days = policy["days"].get(key)
                    nxt = _refresh_status_text(info["mtime"], days)
                    result = "ok" if ok else "failed"
                    if not ok:
                        failed_any = True
                    datasets.append(
                        {
                            "key": key,
                            "label": label,
                            "result": result,
                            "elapsed_s": round(elapsed, 3),
                            "size": info["size"] if info["exists"] else 0,
                            "next_refresh": nxt,
                            "error": None if ok else (error or "build failed"),
                        }
                    )
                    raw.event(
                        key,
                        f"result {result}  time={_format_secs(elapsed)}  size={_format_bytes(info['size']) if info['exists'] else '—'}",
                    )
    finally:
        raw.close_banner(time.time() - session_t0)
        raw.close()

    elapsed_s = max(0.0, time.time() - session_t0)
    if policy is None:
        policy = _read_refresh_policy()
    payload = {
        "ok": not failed_any and not cancelled,
        "cancelled": cancelled,
        "force": force,
        "data": data_dir,
        "log": raw_path,
        "log_error": log_error,
        "log_bytes": raw.size(),
        "elapsed_s": round(elapsed_s, 3),
        "refresh": _refresh_policy_payload(policy, force=force),
        "datasets": datasets,
    }
    _print_json(payload)
    if cancelled:
        raise SystemExit(130)
    if failed_any:
        raise SystemExit(2)


@cli.group("lookup-server")
def lookup_server_cmd() -> None:
    """Start, stop, or inspect the local intel server.

    The process listens on a Unix socket in ~/.looking-glass/data (lookup caches are in data/cache).
    `looking-glass wall wsgi` / `wall asgi` and the socket client use that socket.
    """


@lookup_server_cmd.command("start")
@click.option("-w", "--workers", type=int, default=None, help="uvicorn workers (default 1).")
@click.option("--timeout", type=int, default=None, help="Seconds to wait until ready (default 5, or 1800 when a dataset build is due).")
@click.option("--foreground", is_flag=True, help="Run in this terminal instead of detaching.")
def lookup_server_start_cmd(workers: Optional[int], timeout: Optional[int], foreground: bool) -> None:
    """Start the intel server if it is not already running."""
    from ..intel_server import app as lookup_mod

    report = lookup_mod.start(
        timeout=timeout, workers=workers, foreground=foreground, wait_ready=True
    )
    _print_json(report)
    if not report.get("ok"):
        raise SystemExit(1)


@lookup_server_cmd.command("stop")
@click.option("--timeout", type=int, default=5, help="Seconds to wait for shutdown.")
def lookup_server_stop_cmd(timeout: int) -> None:
    """Stop the intel server."""
    from ..intel_server import app as lookup_mod

    report = lookup_mod.stop(timeout=timeout)
    _print_json(report)


@lookup_server_cmd.command("status")
def lookup_server_status_cmd() -> None:
    """Show whether the intel server is running."""
    from ..intel_server import app as lookup_mod

    report = lookup_mod.status()
    report.setdefault("ok", True)
    if report.get("ready"):
        report.setdefault("state", "running")
    elif report.get("running"):
        report.setdefault("state", "starting")
    else:
        report.setdefault("state", "not_running")
    _print_json(report)


@cli.group("https")
def https_cmd() -> None:
    """Start, stop, inspect, or renew the looking-glass HTTPS supervisor.

    TLS listens on http.port (default 5555) for IPv4 and IPv6 (http.bind default *).
    Pin one family with `looking-glass config set http.bind 0.0.0.0` or `::`.
    Let's Encrypt HTTP-01 uses http.acme_port (default 80). Enable with
    `looking-glass config set http.enabled true` after setting hostname
    (email is optional).
    The intel server is a separate Unix socket.
    """


@https_cmd.command("start")
@click.option("--timeout", type=int, default=8, help="Seconds to wait for the TLS port.")
@click.option("--foreground", is_flag=True, help="Run in this terminal instead of detaching.")
def https_start_cmd(timeout: int, foreground: bool) -> None:
    """Issue or renew a certificate and serve the GUI over TLS."""
    from ..http import https_serve

    report = https_serve.start(timeout=timeout, foreground=foreground)
    _print_json(report)
    if not report.get("ok"):
        raise SystemExit(1)


@https_cmd.command("stop")
@click.option("--timeout", type=int, default=5, help="Seconds to wait for shutdown.")
def https_stop_cmd(timeout: int) -> None:
    """Stop the HTTPS supervisor."""
    from ..http import https_serve

    report = https_serve.stop(timeout=timeout)
    _print_json(report)


@https_cmd.command("status")
def https_status_cmd() -> None:
    """Show supervisor state, certificate paths, and Let's Encrypt expiry."""
    from ..http import https_serve

    report = https_serve.status()
    report.setdefault("ok", True)
    if report.get("running"):
        report.setdefault("state", "running")
    elif report.get("enabled"):
        report.setdefault("state", "not_running")
    else:
        report.setdefault("state", "disabled")
    _print_json(report)


@https_cmd.command("logs")
@click.option("--lines", type=int, default=50, help="Last N lines of each log.")
def https_logs_cmd(lines: int) -> None:
    """Show the HTTPS supervisor stdout and stderr tails."""
    from ..http import https_serve

    _print_json(https_serve.logs(lines=lines))


@https_cmd.command("renew")
@click.option("--force", is_flag=True, help="Issue even if the certificate is still valid.")
def https_renew_cmd(force: bool) -> None:
    """Issue or renew a Let's Encrypt certificate without starting the supervisor."""
    from ..http import https_serve

    report = https_serve.renew(force=force)
    _print_json(report)
    if not report.get("ok"):
        raise SystemExit(1)


@cli.command("status")
def daemons_status_cmd() -> None:
    """Show intel and HTTPS daemon health.

    Uses systemd --user when looking-glass-intel and looking-glass-https
    are enabled; otherwise pidfiles.
    """
    from .boot import HTTPS_UNIT, INTEL_UNIT, _echo_verbose, merge_daemon_status
    from ..http import https_serve
    from ..intel_server import app as lookup_mod

    intel = lookup_mod.status()
    https = https_serve.status()
    payload = merge_daemon_status(intel, https)
    if payload.get("via") == "systemd":
        _echo_verbose(
            ["systemctl", "--user", "status", "--no-pager", INTEL_UNIT, HTTPS_UNIT],
            payload.get("systemd_status") or "",
        )
    emit(payload, kind="daemons")
    if not payload.get("ok"):
        raise SystemExit(1)


@cli.command("restart")
def daemons_restart_cmd() -> None:
    """Stop then start the intel server and the HTTPS supervisor.

    When the systemd --user units are enabled, restarts those units.
    Otherwise stop is a no-op when a daemon is already down, so this
    also starts both from a cold state.
    """
    from .boot import HTTPS_UNIT, INTEL_UNIT, _echo_verbose, merge_daemon_status, restart_units, units_enabled
    from ..http import https_serve
    from ..intel_server import app as lookup_mod

    if units_enabled():
        bounced = restart_units()
        _echo_verbose(bounced["argv"], bounced.get("stdout") or "", bounced.get("stderr") or "")
        if not bounced.get("ok"):
            emit(
                {
                    "ok": False,
                    "error": bounced.get("stderr") or bounced.get("stdout") or "systemctl --user restart failed",
                    "argv": bounced.get("argv"),
                    "code": bounced.get("code"),
                },
                kind="daemons",
            )
            raise SystemExit(1)
        intel = lookup_mod.status()
        https = https_serve.status()
        payload = merge_daemon_status(intel, https)
        if payload.get("via") == "systemd":
            _echo_verbose(
                ["systemctl", "--user", "status", "--no-pager", INTEL_UNIT, HTTPS_UNIT],
                payload.get("systemd_status") or "",
            )
        emit(payload, kind="daemons")
        if not payload.get("ok"):
            raise SystemExit(1)
        return

    https_serve.stop()
    lookup_mod.stop()
    intel = lookup_mod.start(wait_ready=True)
    https = https_serve.start()
    payload = merge_daemon_status(intel, https)
    payload["ok"] = bool(intel.get("ok") and https.get("ok"))
    emit(payload, kind="daemons")
    if not payload["ok"]:
        raise SystemExit(1)


@cli.command("validate")
@click.option(
    "--strict",
    is_flag=True,
    help="Treat stale-dataset warnings as failures.",
)
@click.option(
    "--seed",
    type=int,
    default=None,
    help="Replay the same random samples.",
)
def validate_cmd(strict: bool, seed: Optional[int]) -> None:
    """Check that local datasets load and look up known IPs correctly.

    Uses ~/.looking-glass/data (the same files as `looking-glass lookup`). Does not re-download.
    Lookups are random samples from those datasets, not a fixed IP list.
    Stale caches warn; pass --strict to fail them. Exit 2 if a required check fails.
    """
    report = _run_validate(seed=seed)
    if strict and report["warned"] and report["ok"]:
        report = dict(report)
        report["ok"] = False
    _print_json(report)
    if not report["ok"] or (strict and report["warned"]):
        raise SystemExit(2)


@cli.group("lookup", cls=_LookupGroup)
def lookup_cmd() -> None:
    """Look up an IP, ASN, country, or DNS name, or bench the intel server.

    \b
      looking-glass lookup 1.1.1.1
      looking-glass lookup 2001:db8::1
      looking-glass lookup example.com
      looking-glass lookup example.com --type AAAA
      looking-glass lookup --file ips.txt
      looking-glass lookup bench 1.1.1.1
    """


@lookup_cmd.command("query")
@click.argument("query", required=False)
@click.option(
    "-f",
    "--file",
    "ip_file",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help="File of IPs, ASNs, country codes, or DNS names, one per line. With --json, writes one JSON object per line.",
)
@click.option(
    "-c",
    "--concurrency",
    type=int,
    default=None,
    help="In-flight lookups (default 128, or 16 with --rbl).",
)
@click.option(
    "--rbl",
    "do_rbl",
    is_flag=True,
    help="Check DNSBLs (Spamhaus ZEN, Barracuda, SpamCop, DroneBL). Uses TXT+A.",
)
@click.option(
    "--rbl-list",
    "rbls",
    multiple=True,
    help="RBL as name=domain or domain. Repeatable. Implies --rbl.",
)
@click.option("--timeout", type=float, default=2.0, show_default=True, help="DNS timeout per RBL or DNS lookup.")
@click.option(
    "--type",
    "rrtype",
    default=None,
    help="DNS RR type for a name lookup (A, AAAA, MX, TXT, …). Default A.",
)
@click.option(
    "--server",
    "nameserver",
    default=None,
    help="Nameserver IP (or IP:port) for DNS lookups. Default: system resolver (resolv.conf).",
)
@click.option(
    "-p",
    "--port",
    "ns_port",
    type=int,
    default=None,
    help="Nameserver port for DNS lookups (default 53). Overrides a port in --server.",
)
@click.option("--force", is_flag=True, help="Bypass the 24-hour RBL cache.")
def lookup_query_cmd(
    query: Optional[str],
    ip_file: Optional[str],
    concurrency: Optional[int],
    do_rbl: bool,
    rbls: Tuple[str, ...],
    timeout: float,
    rrtype: Optional[str],
    nameserver: Optional[str],
    ns_port: Optional[int],
    force: bool,
) -> None:
    """Look up an IP, ASN, country code, or DNS name.

    One query prints a compact terminal view (JSON with `--json`). `--file` or
    `-` (stdin) prints one short line per query, or JSONL with `--json`.
    The kind is detected from the token. IPs and country codes use the
    intel server when it is running; a country dump includes every RIR CIDR.
    Names that are not an IP, ASN, or country are DNS lookups (`--type`, default A).
    RBL results cache 24 hours.
    """
    from ..i18n import t

    bulk = ip_file is not None or query == "-"
    if ip_file is not None and query:
        raise click.UsageError(t("cli.lookup.err.both"))
    if not bulk and not query:
        raise click.UsageError(t("cli.lookup.err.need_query"))

    if bulk:
        if ip_file is not None:
            with open(ip_file, encoding="utf-8") as fh:
                queries = _read_query_lines(fh)
        else:
            queries = _read_query_lines(sys.stdin)
        if not queries:
            _print_json({"ok": False, "error": "no queries", "count": 0})
            raise SystemExit(2)
        _run_bulk_lookup(
            queries,
            do_rbl=bool(do_rbl or rbls),
            rbl_map=_parse_rbl_map(rbls),
            timeout=timeout,
            force=force,
            concurrency=_bulk_concurrency(concurrency, bool(do_rbl or rbls)),
            rrtype=rrtype,
            nameserver=nameserver,
            ns_port=ns_port,
        )
        return

    try:
        kind, value = _classify_lookup(query)
    except click.BadParameter as e:
        raise click.UsageError(str(e)) from e

    if rrtype and kind != "dns":
        raise click.UsageError(t("cli.lookup.err.type_dns"))
    if nameserver and kind != "dns":
        raise click.UsageError(t("cli.lookup.err.server_dns"))
    if ns_port is not None and kind != "dns":
        raise click.UsageError(t("cli.lookup.err.port_dns"))

    if kind == "dns":
        if do_rbl or rbls:
            raise click.UsageError(t("cli.lookup.err.rbl_ip"))
        from ..dns.resolve import lookup_dns

        try:
            payload = lookup_dns(
                value,
                rrtype or "A",
                timeout=max(timeout, 2.0),
                server=nameserver,
                port=ns_port,
            )
        except ValueError as e:
            _print_json({"ok": False, "name": value, "result": None, "error": str(e)})
            raise SystemExit(1)
        _print_json(payload)
        if not payload.get("ok"):
            raise SystemExit(1)
        return

    if kind == "asn":
        if do_rbl or rbls:
            raise click.UsageError(t("cli.lookup.err.rbl_ip"))
        try:
            res = asn_org.find_org(value)
            fetched_at = int(asn_org.get_fetched_at() or 0)
        except Exception as e:
            _print_json(
                {"ok": False, "asn": value, "result": None, "fetched_at": None, "error": str(e)}
            )
            raise SystemExit(1)
        _print_json(
            {"ok": True, "asn": value, "result": res, "fetched_at": fetched_at, "error": None}
        )
        return

    if kind == "country":
        if do_rbl or rbls:
            raise click.UsageError(t("cli.lookup.err.rbl_ip"))

    try:
        payload, via = _lookup_prefer_daemon(kind, value)
    except Exception as e:
        _print_json({"ok": False, kind: value, "result": None, "via": None, "error": str(e)})
        raise SystemExit(1)

    out = dict(payload)
    out["via"] = via
    if via == "local":
        out["intel"] = {"running": False, "message": "Intel server is not running."}
    else:
        out["intel"] = {"running": True}

    if do_rbl or rbls:
        try:
            out["rbl"] = check_rbls(
                value, _parse_rbl_map(rbls), timeout=timeout, force=force
            )
        except Exception as e:
            out["rbl"] = {"ok": False, "ip": value, "status": "unknown", "error": str(e)}

    _print_json(out)
    if out.get("rbl") is not None and not out["rbl"].get("ok"):
        raise SystemExit(1)


@lookup_cmd.command("bench")
@click.argument("ip")
@click.option(
    "-c",
    "--concurrency",
    type=int,
    default=None,
    help="Concurrent workers per thread (default 200).",
)
@click.option(
    "-d",
    "--duration",
    type=float,
    default=None,
    help="Seconds to run (default 30).",
)
@click.option(
    "-t",
    "--threads",
    type=int,
    default=1,
    show_default=True,
    help="Event loops (each with its own UDS session).",
)
@click.option(
    "--timeout",
    type=float,
    default=None,
    help="Per-request timeout seconds (default 0.5).",
)
@click.option(
    "--connections",
    type=int,
    default=None,
    help="UDS connection pool size (default: min(concurrency, process fd limit)).",
)
@click.option(
    "--socket",
    type=click.Path(dir_okay=False),
    default=None,
    help="Override ~/.looking-glass/data/lookup.sock.",
)
def lookup_bench_cmd(
    ip: str,
    concurrency: Optional[int],
    duration: Optional[float],
    threads: int,
    timeout: Optional[float],
    connections: Optional[int],
    socket: Optional[str],
) -> None:
    """Hammer the intel Unix socket with IPv4 and IPv6 lookups.

    Requires `looking-glass lookup-server start`. Does not load RIR in this process.
    Progress is on stderr; the report is a compact terminal view (or JSON with `--json`).
    """
    from ..intel_server.bench import (
        DEFAULT_CONCURRENCY,
        DEFAULT_DURATION,
        DEFAULT_TIMEOUT,
        bench,
    )

    payload = bench(
        ip,
        concurrency=DEFAULT_CONCURRENCY if concurrency is None else concurrency,
        duration=DEFAULT_DURATION if duration is None else duration,
        threads=threads,
        timeout=DEFAULT_TIMEOUT if timeout is None else timeout,
        connections=connections,
        socket_path=socket,
    )
    _print_json(payload)
    if not payload.get("ok"):
        raise SystemExit(2)


_WALL_KINDS = click.Choice(["ip", "asn", "country"], case_sensitive=False)


def _cli_note(note: Optional[str], default: str) -> str:
    text = str(note or "").strip()
    return text if text else default


def _stdin_is_tty() -> bool:
    try:
        return bool(sys.stdin.isatty())
    except Exception:
        return False


def _wall_json(fn):
    try:
        payload = fn()
    except ValueError as e:
        emit({"ok": False, "error": str(e)}, kind="error")
        raise SystemExit(2)
    emit(payload)


def _stats_with_iso(payload: Dict[str, Any]) -> Dict[str, Any]:
    from datetime import datetime, timezone

    def iso(stamp: Any) -> str:
        try:
            n = float(stamp)
        except (TypeError, ValueError):
            return ""
        return (
            datetime.fromtimestamp(n, timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    def series(pages: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if not isinstance(pages, dict):
            return out
        for page, rows in pages.items():
            copied = []
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                item = dict(row)
                if "t" in item:
                    item["iso"] = iso(item["t"])
                copied.append(item)
            out[str(page)] = copied
        return out

    out = dict(payload)
    out["day"] = series(payload.get("day"))
    out["week"] = series(payload.get("week"))
    return out


_CACHE_NS = click.Choice(("rdap", "bgp"), case_sensitive=False)


@cli.group("cache")
def cache_cmd() -> None:
    """Inspect and clear the on-disk lookup cache.

    RDAP and BGP responses live under ~/.looking-glass/data/cache. TTL and the web GUI
    switch are ~/.looking-glass/config.json (`looking-glass config`).

    \b
    looking-glass cache stats
    looking-glass cache stats rdap
    looking-glass cache clear
    looking-glass cache clear bgp
    looking-glass cache clear rdap ip_1.1.1.1.json
    """


@cache_cmd.command("stats")
@click.argument("namespace", required=False, type=_CACHE_NS)
def cache_stats_cmd(namespace: Optional[str]) -> None:
    """Show cached files. NAMESPACE is rdap or bgp."""
    from .. import cache as query_cache

    payload = query_cache.stats(namespace.lower() if namespace else None)
    payload["ok"] = True
    _print_json(payload)


@cache_cmd.command("clear")
@click.argument("namespace", required=False, type=_CACHE_NS)
@click.argument("name", required=False)
def cache_clear_cmd(namespace: Optional[str], name: Optional[str]) -> None:
    """Delete cached files. No args clears every namespace."""
    from .. import cache as query_cache

    payload = query_cache.clear(namespace.lower() if namespace else None, name)
    _print_json(payload)
    if not payload.get("ok"):
        raise SystemExit(1)


@cli.group("wall")
def wall_cmd() -> None:
    """Allow and block lists used by the request wall.

    Lists live in ~/.looking-glass/data/wall.json. IPv4 and IPv6 CIDRs are fine.
    Unknown visitors are allowed. Challenge serves a first-party puzzle;
    a pass cookie lasts wall.challenge_ttl_days (default 5).

    \b
    looking-glass wall block ip 203.0.113.0/24
    looking-glass wall block asn 13335
    looking-glass wall block country CN
    looking-glass wall allow ip 2001:db8::1
    looking-glass wall challenge ip 198.51.100.0/24
    looking-glass wall list ip
    looking-glass wall log
    looking-glass wall reset --force
    looking-glass wall remove ip 203.0.113.0/24
    looking-glass wall wsgi
    looking-glass wall asgi
    """


@wall_cmd.command("block")
@click.argument("kind", type=_WALL_KINDS)
@click.argument("value")
@click.option("--note", default="", help="Stored with the list entry and wall.log line.")
def wall_block_cmd(kind: str, value: str, note: str) -> None:
    """Block an IP/CIDR, ASN, or country code."""
    _wall_json(
        lambda: wall_lists.add(
            "block",
            kind.lower(),
            value,
            source="cli",
            note=_cli_note(note, "blocked via cli"),
        )
    )


@wall_cmd.command("allow")
@click.argument("kind", type=click.Choice(["ip"], case_sensitive=False))
@click.argument("value")
@click.option("--note", default="", help="Stored with the list entry and wall.log line.")
def wall_allow_cmd(kind: str, value: str, note: str) -> None:
    """Allow an IP or CIDR. That visitor skips challenge."""
    _wall_json(
        lambda: wall_lists.add(
            "allow",
            kind.lower(),
            value,
            source="cli",
            note=_cli_note(note, "allowed via cli"),
        )
    )


@wall_cmd.command("challenge")
@click.argument("kind", type=click.Choice(["ip", "asn"], case_sensitive=False))
@click.argument("value")
@click.option("--note", default="", help="Stored with the list entry and wall.log line.")
def wall_challenge_cmd(kind: str, value: str, note: str) -> None:
    """Challenge an IP/CIDR or ASN. The visitor solves a puzzle for a timed pass."""
    _wall_json(
        lambda: wall_lists.add(
            "challenge",
            kind.lower(),
            value,
            source="cli",
            note=_cli_note(note, "challenged via cli"),
        )
    )


@wall_cmd.command("list")
@click.argument("kind", required=False, type=_WALL_KINDS)
def wall_list_cmd(kind: Optional[str]) -> None:
    """Show block (and allow) lists. KIND is ip, asn, or country."""
    _wall_json(lambda: wall_lists.snapshot(kind.lower() if kind else None))


@wall_cmd.command("log")
@click.option(
    "--limit",
    default=100,
    type=int,
    show_default=True,
    help="Newest events to return. 0 means all.",
)
def wall_log_cmd(limit: int) -> None:
    """Show the wall actions log (bans, challenges, allows, removals)."""
    path = wall_lists.default_lists_path()
    cap = None if limit == 0 else max(limit, 0)
    actions = wall_lists.read_actions(path, limit=cap)
    _print_json(
        {
            "ok": True,
            "path": wall_lists.actions_path(path),
            "count": len(actions),
            "actions": actions,
        },
    )


@wall_cmd.command("reset")
@click.option("--force", is_flag=True, help="Do not ask for confirmation.")
@click.option("--note", default="", help="Stored on the wall.log reset line.")
def wall_reset_cmd(force: bool, note: str) -> None:
    """Clear every allow, block, and challenge list.

    Writes an empty wall.json and appends one reset line to wall.log.
    Existing challenge pass cookies expire on their own TTL.
    """
    if not force:
        if not _stdin_is_tty():
            raise click.UsageError("refusing to reset without --force (not a TTY)")
        if not click.confirm(
            "Clear all allow, block, and challenge lists?", default=False
        ):
            raise SystemExit(1)
    _wall_json(
        lambda: wall_lists.reset(
            source="cli",
            note=_cli_note(note, "reset via cli"),
        )
    )


@wall_cmd.command("remove")
@click.argument("kind", type=_WALL_KINDS)
@click.argument("value")
@click.option("--note", default="", help="Stored on the wall.log remove line.")
def wall_remove_cmd(kind: str, value: str, note: str) -> None:
    """Remove an IP/CIDR, ASN, or country code from the lists."""
    _wall_json(
        lambda: wall_lists.remove(
            kind.lower(),
            value,
            source="cli",
            note=_cli_note(note, "removed via cli"),
        )
    )


def _wall_http_banner(protocol: str, host: str, port: int) -> None:
    url = f"http://{host}:{port}/"
    _print_json(
        {
            "ok": True,
            "protocol": protocol,
            "url": url,
            "curl": [
                f"curl -s {url}",
                f"curl -s {url}1.1.1.1",
                f"curl -s {url}AS13335",
                f"curl -s {url}AU",
                f"curl -s {url}dns/example.com",
                f"curl -s {url}reputation/example.com",
            ],
            "intel": "looking-glass lookup-server start",
        }
    )


@wall_cmd.command("wsgi")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--port", default=8000, type=int, show_default=True, help="Bind port.")
def wall_wsgi_cmd(host: str, port: int) -> None:
    """HTTP test app (WSGI) that looks up the client IP through the wall."""
    from ..http import wsgi as wsgi_mod

    _wall_http_banner("wsgi", host, port)
    wsgi_mod.serve(host, port)


@wall_cmd.command("asgi")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--port", default=8001, type=int, show_default=True, help="Bind port.")
def wall_asgi_cmd(host: str, port: int) -> None:
    """HTTP test app (ASGI) that looks up the client IP through the wall."""
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        _print_json(
            {
                "ok": False,
                "protocol": "asgi",
                "error": "uvicorn is required to serve the ASGI demo",
            }
        )
        raise SystemExit(1)
    from ..http import asgi as asgi_mod

    _wall_http_banner("asgi", host, port)
    asgi_mod.serve(host, port)


@cli.group("logs")
def logs_cmd() -> None:
    """Read-only dumps of the GUI log stats store.

    Same payload the logs window refresh loads from GET /logs/stats
    (~/.looking-glass/data/logs/stats.json). Does not rebuild from access JSONL.

    \b
    looking-glass logs stats
    """


@logs_cmd.command("stats")
def logs_stats_cmd() -> None:
    """Print day/week hit and error series (unix t plus ISO)."""
    from ..http.weblog import stats_payload

    _print_json(_stats_with_iso(stats_payload()))


from .tools import register_tool_commands
from .locale_cmd import locale_group
from .config_cmd import config_group
from .auth_cmd import auth_group
from .boot import boot_group

register_tool_commands(cli)
cli.add_command(locale_group)
cli.add_command(config_group)
cli.add_command(auth_group)
cli.add_command(boot_group)


def _peek_lang(argv: list) -> Optional[str]:
    for i, arg in enumerate(argv):
        if arg == "--lang" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--lang="):
            return arg.split("=", 1)[1]
    return None


def main() -> None:
    """Console entrypoint used by the packaged CLI script."""
    from ..i18n import overlay_click, resolve_locale, set_locale

    set_locale(resolve_locale(explicit=_peek_lang(sys.argv[1:])))
    overlay_click(cli)
    cli()


if __name__ == "__main__":
    main()
