"""Benchmark GET /{ip} against the intel server.

Hits one IPv4 or IPv6 address over the Unix socket. Datasets stay in the
intel server; this process never loads RIR. Progress goes to stderr; the report
is a dict for JSON on stdout.
"""

from __future__ import annotations

import argparse
import asyncio
import errno as errno_mod
import ipaddress
import json
import math
import sys
import threading
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from tqdm import tqdm

from . import client as lookup_client
from . import app as lookup_mod

DEFAULT_CONCURRENCY = 200
DEFAULT_DURATION = 30
DEFAULT_TIMEOUT = 0.5


def _fd_cap() -> int:
    """Stay under RLIMIT_NOFILE so -c 300 does not hit EMFILE on macOS."""
    try:
        import resource

        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:
        return 128
    if soft <= 0:
        return 128
    return max(8, int(soft) - 32)


def pool_size(concurrency: int, connections: Optional[int] = None) -> int:
    """How many UDS connections to open. Tasks above this share the pool."""
    n = max(1, int(concurrency))
    cap = _fd_cap() if connections is None else max(1, int(connections))
    return max(1, min(n, cap))


def _percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    n = len(sorted_vals)
    rank = math.ceil((p / 100.0) * n)
    idx = max(0, min(n - 1, rank - 1))
    return sorted_vals[idx]


def _socket_path(socket_path: Optional[str]) -> str:
    return socket_path or lookup_client.LOOKUP_SOCKET


def _error_label(exc: BaseException) -> str:
    aiohttp = lookup_client.aiohttp
    if isinstance(exc, (asyncio.TimeoutError, aiohttp.ServerTimeoutError)):
        return "timeout"
    if isinstance(exc, aiohttp.ClientConnectorError):
        oserr = getattr(exc, "os_error", None) or exc.__cause__
        if isinstance(oserr, OSError) and oserr.errno:
            name = errno_mod.errorcode.get(oserr.errno, str(oserr.errno))
            return f"connect:{name}"
        return f"connect:{exc.__class__.__name__}"
    if isinstance(exc, aiohttp.ClientError):
        return exc.__class__.__name__
    return exc.__class__.__name__


def _request_timeout(timeout: float) -> Any:
    """Time out connect/read, not waiting for a free pooled connection."""
    aiohttp = lookup_client.aiohttp
    return aiohttp.ClientTimeout(total=None, sock_connect=timeout, sock_read=timeout)


async def _one(
    session: Any, ip: str, timeout: float
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One GET /{ip}. Returns (payload, error_label)."""
    try:
        async with session.get(
            lookup_client.lookup_url(ip),
            timeout=_request_timeout(timeout),
        ) as resp:
            if resp.status != 200:
                return None, f"http_{resp.status}"
            try:
                data = await resp.json(content_type=None)
            except Exception:
                return None, "invalid_json"
        if not isinstance(data, dict) or not data.get("ok"):
            if isinstance(data, dict):
                detail = data.get("error") or data.get("detail")
                if detail:
                    return None, str(detail)
            return None, "not_ok"
        return data, None
    except Exception as exc:
        return None, _error_label(exc)


async def _worker(
    stop_time: float,
    stats: Dict[str, Any],
    ip: str,
    progress: tqdm,
    latencies: List[float],
    timeout: float,
) -> None:
    session = stats.get("_session")
    reasons: Counter[str] = stats["error_reasons"]
    while time.time() < stop_time:
        t0 = time.perf_counter()
        res, err = await _one(session, ip, timeout)
        delta_ms = (time.perf_counter() - t0) * 1000.0
        if err is None:
            stats["count"] += 1
            latencies.append(delta_ms)
        else:
            stats["errors"] += 1
            reasons[err] += 1
        progress.update(1)


async def run_loop(
    ip: str,
    *,
    socket_path: str,
    concurrency: int,
    duration: float,
    timeout: float,
    connections: Optional[int] = None,
    position: int = 0,
    show_progress: bool = True,
) -> Dict[str, Any]:
    """One event loop, one shared UDS session, GET /{ip} for IPv4 and IPv6."""
    stats: Dict[str, Any] = {"count": 0, "errors": 0, "error_reasons": Counter()}
    latencies: List[float] = []
    started = time.time()
    stop_time = started + duration
    session = None
    n = max(1, int(concurrency))
    pool = pool_size(n, connections)
    try:
        conn = lookup_client.aiohttp.UnixConnector(
            path=socket_path,
            limit=pool,
            limit_per_host=0,
            keepalive_timeout=30,
        )
        session = lookup_client.aiohttp.ClientSession(connector=conn)
        stats["_session"] = session
        disable = (not show_progress) or (not sys.stderr.isatty())
        with tqdm(
            unit="req",
            desc=f"{ip}",
            leave=True,
            position=position,
            file=sys.stderr,
            disable=disable,
        ) as progress:
            tasks = [
                asyncio.create_task(
                    _worker(stop_time, stats, ip, progress, latencies, timeout)
                )
                for _ in range(n)
            ]
            await asyncio.gather(*tasks)
    finally:
        if session is not None:
            try:
                await session.close()
            except Exception:
                pass
    reasons = stats["error_reasons"]
    return {
        "count": int(stats["count"]),
        "errors": int(stats["errors"]),
        "duration_s": max(0.0, time.time() - started),
        "latencies": latencies,
        "error_summary": dict(reasons.most_common()),
        "connections": pool,
    }


def _merge_results(
    results: List[Dict[str, Any]]
) -> Tuple[int, int, float, List[float], Dict[str, int]]:
    total_count = sum(int(r.get("count", 0)) for r in results)
    total_errors = sum(int(r.get("errors", 0)) for r in results)
    durations = [float(r.get("duration_s", 0.0)) for r in results]
    duration_s = max(durations) if durations else 0.0
    all_latencies: List[float] = []
    reasons: Counter[str] = Counter()
    for r in results:
        all_latencies.extend(r.get("latencies") or [])
        reasons.update(r.get("error_summary") or {})
        err = r.get("error")
        if err:
            reasons[str(err)] += 1
    return total_count, total_errors, duration_s, all_latencies, dict(reasons.most_common())


def bench(
    ip: str,
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    duration: float = DEFAULT_DURATION,
    threads: int = 1,
    timeout: float = DEFAULT_TIMEOUT,
    connections: Optional[int] = None,
    socket_path: Optional[str] = None,
    show_progress: bool = True,
) -> Dict[str, Any]:
    """Run the intel server bench. Never loads datasets in this process."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {"ok": False, "ip": ip, "error": "invalid ip", "via": None}

    sock = _socket_path(socket_path)
    intel = lookup_mod.status()
    if not intel.get("ready"):
        return {
            "ok": False,
            "ip": str(addr),
            "error": "intel server is not running",
            "via": None,
            "socket": sock,
            "intel": intel,
        }

    n_threads = max(1, int(threads))
    results: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def thread_target(idx: int) -> None:
        try:
            res = asyncio.run(
                run_loop(
                    str(addr),
                    socket_path=sock,
                    concurrency=concurrency,
                    duration=duration,
                    timeout=timeout,
                    connections=connections,
                    position=idx,
                    show_progress=show_progress,
                )
            )
        except Exception as exc:
            res = {
                "count": 0,
                "errors": 1,
                "duration_s": 0.0,
                "latencies": [],
                "error_summary": {str(exc): 1},
            }
        with lock:
            results.append(res)

    workers = [
        threading.Thread(target=thread_target, args=(i,), daemon=False)
        for i in range(n_threads)
    ]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    total, errs, duration_s, latencies, error_summary = _merge_results(results)
    sorted_lat = sorted(latencies)
    rps = total / duration_s if duration_s > 0 else 0.0
    out = {
        "ok": True,
        "ip": str(addr),
        "via": "intel",
        "url": lookup_client.lookup_url(str(addr)),
        "socket": sock,
        "concurrency": int(concurrency),
        "connections": pool_size(int(concurrency), connections),
        "threads": n_threads,
        "timeout_s": float(timeout),
        "duration_s": round(duration_s, 3),
        "requests": total,
        "errors": errs,
        "rps": round(rps, 2),
        "latency_ms": {
            "p50": round(_percentile(sorted_lat, 50.0), 3),
            "p95": round(_percentile(sorted_lat, 95.0), 3),
            "p99": round(_percentile(sorted_lat, 99.0), 3),
        },
    }
    if error_summary:
        out["error_summary"] = error_summary
    return out


def main(argv: Optional[List[str]] = None) -> None:
    p = argparse.ArgumentParser(prog="looking-glass lookup bench")
    p.add_argument("ip", help="IPv4 or IPv6 address")
    p.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="concurrent workers per thread",
    )
    p.add_argument(
        "-d", "--duration", type=float, default=DEFAULT_DURATION, help="seconds"
    )
    p.add_argument("-t", "--threads", type=int, default=1, help="event loops")
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="per-request timeout seconds",
    )
    p.add_argument(
        "--connections",
        type=int,
        default=None,
        help="UDS connection pool size (default: min(concurrency, fd limit))",
    )
    p.add_argument("--socket", type=str, default=None, help="override lookup.sock")
    args = p.parse_args(argv)
    payload = bench(
        args.ip,
        concurrency=args.concurrency,
        duration=args.duration,
        threads=args.threads,
        timeout=args.timeout,
        connections=args.connections,
        socket_path=args.socket,
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    raise SystemExit(0 if payload.get("ok") else 2)


if __name__ == "__main__":
    main()
