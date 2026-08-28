"""Intel server (FastAPI + uvicorn) on a Unix socket.

Datasets are warmed at process start. Lookups use the same pipeline as
`looking-glass lookup`. Control the process with
`looking-glass lookup-server start|stop|status`.
Pid, socket, and logs live in ~/.looking-glass/data. Lookup caches are in data/cache.
"""

from __future__ import annotations

import asyncio
import gc
import json
import logging
import os
import signal
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request

from ..intel import asn as asn_mod
from ..intel import asn_org, iana, rir
from .pipeline import classify_query, lookup_country, lookup_ip
from ..utility import atomic_write, get_data_dir

PID_NAME = "lookup.pid"
SOCK_NAME = "lookup.sock"
STARTED_NAME = "lookup.started"
READY_NAME = "lookup.ready"
OUT_LOG = "lookup.out.log"
ERR_LOG = "lookup.err.log"
UVICORN_MODULE = "looking_glass.intel_server.app:app"
UVICORN_WORKERS = 1
REBUILD_EVERY = 15 * 60
BUILD_WAIT_S = 1800
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


class JsonLogFormatter(logging.Formatter):
    """One JSON object per log record (lookup.err.log)."""

    def format(self, record: logging.LogRecord) -> str:
        row: Dict[str, Any] = {
            "ts": float(record.created),
            "logger": record.name,
            "level": str(record.levelname or "").lower(),
            "message": record.getMessage(),
        }
        if record.exc_info:
            row["error"] = self.formatException(record.exc_info)
        return json.dumps(row, ensure_ascii=False)


UVICORN_LOG_CONFIG: Dict[str, Any] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {"()": "looking_glass.intel_server.app.JsonLogFormatter"},
    },
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stderr",
        },
    },
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.access": {"handlers": ["default"], "level": "WARNING", "propagate": False},
    },
    "root": {"handlers": ["default"], "level": "INFO"},
}


@lru_cache(maxsize=1)
def _data_dir_path() -> Path:
    d = Path(get_data_dir())
    d.mkdir(parents=True, exist_ok=True)
    return d


def _paths() -> tuple[Path, Path, Path, Path, Path]:
    d = _data_dir_path()
    return d / PID_NAME, d / SOCK_NAME, d / OUT_LOG, d / ERR_LOG, d / STARTED_NAME


def _ready_path() -> Path:
    return _data_dir_path() / READY_NAME


def _write_started(path: Path, when: Optional[float] = None) -> None:
    atomic_write(str(path), str(float(time.time() if when is None else when)))


def _read_started(path: Path) -> Optional[float]:
    try:
        return float(path.read_text().strip())
    except (OSError, ValueError):
        return None


def _mark_ready() -> None:
    dest = _ready_path()
    atomic_write(str(dest), str(float(time.time())) + "\n")
    _write_started(_paths()[4])


def _load_datasets() -> None:
    for mod in (iana, rir, asn_mod, asn_org):
        try:
            if hasattr(mod, "load"):
                mod.load(force=False)
            if hasattr(mod, "shrink"):
                try:
                    mod.shrink()
                except Exception:
                    pass
        except Exception:
            pass
    try:
        gc.collect()
    except Exception:
        pass


def _rebuild_then_load() -> None:
    log = logging.getLogger("looking_glass.intel_server")
    try:
        from ..datasets import rebuild_due

        rebuild_due(log=log)
    except Exception:
        log.exception("rebuild due failed")
    _load_datasets()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _rebuild_then_load)
    _mark_ready()
    task = asyncio.create_task(_refresh_loop(loop))
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _refresh_loop(loop: asyncio.AbstractEventLoop) -> None:
    try:
        while True:
            await asyncio.sleep(REBUILD_EVERY)
            await loop.run_in_executor(None, _rebuild_then_load)
    except asyncio.CancelledError:
        raise


app = FastAPI(title="looking-glass-intel", lifespan=_lifespan)


def _intel_from_payload(payload: Any) -> Dict[str, Any]:
    blob = payload
    if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
        blob = payload["result"]
    if not isinstance(blob, dict):
        return {}
    out: Dict[str, Any] = {}
    for key in INTEL_KEYS:
        val = blob.get(key)
        if val not in (None, "", False):
            out[key] = val
    return out


def _write_lookup_access(
    *,
    status: int,
    ms: float,
    kind: Optional[str],
    query: Optional[str],
    intel: Optional[Dict[str, Any]],
) -> None:
    _outlog = _paths()[2]
    row = {
        "ts": time.time(),
        "logger": "lookup",
        "status": int(status),
        "ms": round(float(ms), 1),
        "kind": kind,
        "query": query,
        "intel": intel or None,
    }
    try:
        with open(_outlog, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError:
        pass


def _dispatch(token: str) -> Dict[str, Any]:
    text = str(token).strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        text = text[1:-1]
    try:
        kind, value = classify_query(text)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid query")
    if kind == "ip":
        return lookup_ip(value, load=False)
    if kind == "country":
        return lookup_country(value, load=False)
    raise HTTPException(status_code=400, detail="invalid query")


def _logged_lookup(token: str) -> Dict[str, Any]:
    started = time.perf_counter()
    status = 200
    kind: Optional[str] = None
    query: Optional[str] = None
    intel: Dict[str, Any] = {}
    text = str(token or "").strip()
    if text.startswith("[") and text.endswith("]") and len(text) > 2:
        text = text[1:-1]
    try:
        try:
            kind, query = classify_query(text)
        except ValueError:
            kind, query = None, text or None
        payload = _dispatch(token)
        intel = _intel_from_payload(payload)
        return payload
    except HTTPException as exc:
        status = int(exc.status_code)
        raise
    except Exception:
        status = 500
        raise
    finally:
        _write_lookup_access(
            status=status,
            ms=(time.perf_counter() - started) * 1000,
            kind=kind,
            query=query,
            intel=intel,
        )


@app.get("/lookup")
def lookup_query(ip: str = Query(..., description="IP or country code")) -> Dict[str, Any]:
    """Optional query-string alias. Prefer GET /{token}."""
    return _logged_lookup(ip)


def lookup(ip: str) -> Dict[str, Any]:
    """Lookup an IPv4 or IPv6 address (same as GET /{ip})."""
    return _dispatch(ip)


@app.get("/{ip}")
def lookup_by_path(request: Request, ip: str) -> Dict[str, Any]:
    """Lookup by path. IPv4, IPv6, or a country code (e.g. /AU)."""
    if ip == "lookup":
        q = request.query_params.get("ip")
        if q:
            return _logged_lookup(q)
        raise HTTPException(status_code=400, detail="invalid query")
    return _logged_lookup(ip)


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_pidfile(pidfile: Path) -> Optional[int]:
    try:
        return int(pidfile.read_text().strip())
    except Exception:
        return None


def _write_pidfile(pidfile: Path, pid: int) -> None:
    atomic_write(str(pidfile), str(pid))


def _remove_if_exists(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass


def _base_info() -> Dict[str, Any]:
    pidfile, sockpath, outlog, errlog, _started = _paths()
    return {
        "pidfile": str(pidfile),
        "socket": str(sockpath),
        "data": str(_data_dir_path()),
        "out_log": str(outlog),
        "err_log": str(errlog),
    }


def status() -> Dict[str, Any]:
    """Pidfile / process / socket / ready state for the intel server."""
    pidfile, sockpath, _outlog, _errlog, started_path = _paths()
    pid = _read_pidfile(pidfile)
    running = bool(pid and _is_running(pid))
    ready = running and _ready_path().is_file()
    info = _base_info()
    info.update(
        {
            "running": running,
            "ready": ready,
            "pid": pid if running else None,
            "socket_exists": sockpath.exists(),
            "stale": bool(pidfile.exists() and pid and not running),
        }
    )
    if running:
        started_at = _read_started(started_path)
        if started_at is not None:
            info["started_at"] = started_at
            info["uptime"] = max(0.0, time.time() - started_at)
    return info


def _due_keys() -> List[str]:
    try:
        from ..datasets import due_keys

        return list(due_keys())
    except Exception:
        return []


def _note(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _tail_rebuild(errlog: Path, offset: int) -> int:
    try:
        with open(errlog, encoding="utf-8") as fh:
            fh.seek(offset)
            data = fh.read()
            nxt = fh.tell()
    except OSError:
        return offset
    for line in data.splitlines():
        msg = line
        try:
            row = json.loads(line)
            if isinstance(row, dict):
                msg = str(row.get("message") or "")
        except json.JSONDecodeError:
            pass
        if msg.startswith("rebuild start") or msg.startswith("rebuild end"):
            _note(f"intel server: {msg}")
    return nxt


def _wait_ready(proc: Any, errlog: Path, wait_s: float) -> Optional[Dict[str, Any]]:
    ready = _ready_path()
    deadline = time.time() + max(0.1, float(wait_s))
    offset = 0
    try:
        offset = errlog.stat().st_size
    except OSError:
        offset = 0
    while time.time() < deadline:
        offset = _tail_rebuild(errlog, offset)
        if ready.is_file():
            return None
        if proc is not None and proc.poll() is not None:
            return {
                "ok": False,
                "state": "error",
                "error": f"intel server exited early; see {_paths()[2]} and {errlog}",
                "pid": getattr(proc, "pid", None),
                **_base_info(),
            }
        time.sleep(0.2)
    offset = _tail_rebuild(errlog, offset)
    if ready.is_file():
        return None
    return {
        "ok": False,
        "state": "error",
        "error": "intel server did not become ready",
        **_base_info(),
        **status(),
    }


def start(
    timeout: Optional[int] = None,
    workers: Optional[int] = None,
    foreground: bool = False,
    wait_ready: bool = True,
) -> Dict[str, Any]:
    """Start uvicorn on ~/.looking-glass/data/lookup.sock. Idempotent if already up."""
    pidfile, sockpath, outlog, errlog, started_path = _paths()
    ready_path = _ready_path()
    _data_dir_path()
    due = _due_keys()
    if timeout is None:
        wait_s = float(BUILD_WAIT_S if due else 5)
    else:
        wait_s = float(timeout)

    existing = _read_pidfile(pidfile)
    if existing and _is_running(existing):
        if wait_ready and not ready_path.is_file():
            if due:
                extra = " (asn can take several minutes)" if "asn" in due else ""
                _note(f"intel server: building {', '.join(due)}{extra}")
            failed = _wait_ready(None, errlog, wait_s)
            if failed:
                return failed
        info = status()
        info.update(
            {
                "ok": True,
                "state": "already_running" if info.get("ready") else "starting",
                "building": due,
            }
        )
        return info
    _remove_if_exists(pidfile)
    _remove_if_exists(sockpath)
    _remove_if_exists(started_path)
    _remove_if_exists(ready_path)

    workers_to_use = UVICORN_WORKERS if workers is None else int(workers)

    if foreground:
        try:
            import uvicorn  # noqa: F401
        except Exception:
            return {
                "ok": False,
                "state": "error",
                "error": "uvicorn is required for foreground mode",
                **_base_info(),
            }
        _write_pidfile(pidfile, os.getpid())
        try:
            serve_uvicorn(uds=str(sockpath), workers=workers_to_use)
        finally:
            _remove_if_exists(pidfile)
            _remove_if_exists(sockpath)
            _remove_if_exists(started_path)
            _remove_if_exists(ready_path)
        return {"ok": True, "state": "stopped", **_base_info()}

    if due:
        extra = " (asn can take several minutes)" if "asn" in due else ""
        _note(f"intel server: building {', '.join(due)}{extra}")

    cmd = [
        sys.executable,
        "-m",
        "looking_glass.intel_server",
        "--uds",
        str(sockpath),
        "--workers",
        str(workers_to_use),
    ]
    out_f = open(outlog, "a")
    err_f = open(errlog, "a")
    try:
        proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f, close_fds=True)
    finally:
        out_f.close()
        err_f.close()

    _write_pidfile(pidfile, proc.pid)

    if not wait_ready:
        info = status()
        info.update(
            {
                "ok": True,
                "state": "starting" if not info.get("ready") else "started",
                "building": due,
                "pid": proc.pid,
            }
        )
        return info

    failed = _wait_ready(proc, errlog, wait_s)
    if failed:
        if proc.poll() is not None:
            _remove_if_exists(started_path)
            _remove_if_exists(ready_path)
        return failed
    info = status()
    info.update({"ok": True, "state": "started", "building": due})
    return info


def stop(timeout: int = 5) -> Dict[str, Any]:
    """Stop the intel server and remove pidfile + socket."""
    pidfile, sockpath, _outlog, _errlog, started_path = _paths()
    ready_path = _ready_path()
    pid = _read_pidfile(pidfile)
    if not pid or not _is_running(pid):
        _remove_if_exists(pidfile)
        _remove_if_exists(sockpath)
        _remove_if_exists(started_path)
        _remove_if_exists(ready_path)
        info = _base_info()
        info.update({"ok": True, "state": "not_running", "running": False, "ready": False, "pid": None})
        return info

    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _is_running(pid):
            break
        time.sleep(0.1)

    if _is_running(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    _remove_if_exists(pidfile)
    _remove_if_exists(sockpath)
    _remove_if_exists(started_path)
    _remove_if_exists(ready_path)
    info = _base_info()
    info.update({"ok": True, "state": "stopped", "running": False, "ready": False, "pid": None})
    return info


def serve_uvicorn(uds: Optional[str] = None, workers: Optional[int] = None) -> None:
    """Run uvicorn with JSON error logs and no Combined-format access log."""
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(prog="looking-glass-intel")
    parser.add_argument("--uds")
    parser.add_argument("--workers", type=int)
    args, _rest = parser.parse_known_args()
    sock = args.uds or uds or str(_paths()[1])
    nworkers = args.workers if args.workers is not None else (
        workers if workers is not None else UVICORN_WORKERS
    )
    uvicorn.run(
        app,
        uds=sock,
        workers=int(nworkers),
        log_level="info",
        access_log=False,
        log_config=UVICORN_LOG_CONFIG,
    )


if __name__ == "__main__":
    serve_uvicorn()