"""User-space HTTPS supervisor: TLS on http.port (default 5555), ACME on :80."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import load as load_config
from ..config import path as config_path
from ..utility import atomic_write, get_data_dir
from . import acme_issue

PID_NAME = "https.pid"
STARTED_NAME = "https.started"
OUT_LOG = "https.out.log"
ERR_LOG = "https.err.log"
ACME_LOG = acme_issue.ACME_LOG_NAME
POLL_SECONDS = 2.0
RENEW_SECONDS = 24 * 60 * 60
UVICORN_APP = "looking_glass.http.asgi:app"
DEFAULT_BIND = "*"


def _data_dir() -> Path:
    dest = Path(get_data_dir())
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def _paths() -> Tuple[Path, Path, Path, Path]:
    d = _data_dir()
    return d / PID_NAME, d / STARTED_NAME, d / OUT_LOG, d / ERR_LOG


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_pid(pidfile: Path) -> Optional[int]:
    try:
        return int(pidfile.read_text().strip())
    except Exception:
        return None


def _write_pid(pidfile: Path, pid: int) -> None:
    atomic_write(str(pidfile), str(pid))


def _remove(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def _write_started(path: Path) -> None:
    atomic_write(str(path), str(float(time.time())))


def _http_cfg(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = cfg if cfg is not None else load_config()
    http = data.get("http") if isinstance(data, dict) else None
    return dict(http) if isinstance(http, dict) else {}


def _fingerprint(http: Dict[str, Any], fullchain: Path, privkey: Path) -> Tuple[Any, ...]:
    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    return (
        http.get("hostname"),
        http.get("email"),
        int(http.get("port") or 5555),
        int(http.get("workers") or 1),
        str(http.get("bind") or DEFAULT_BIND),
        bool(http.get("staging")),
        int(http.get("acme_port") or 80),
        _mtime(fullchain),
        _mtime(privkey),
        _mtime(Path(config_path())),
    )


def _base_info() -> Dict[str, Any]:
    pidfile, started, outlog, errlog = _paths()
    return {
        "pidfile": str(pidfile),
        "out_log": str(outlog),
        "err_log": str(errlog),
        "acme_log": str(_data_dir() / ACME_LOG),
        "started_file": str(started),
    }


def status() -> Dict[str, Any]:
    pidfile, started, _out, _err = _paths()
    pid = _read_pid(pidfile)
    running = bool(pid and _is_running(pid))
    http = _http_cfg()
    info = _base_info()
    host = str(http.get("hostname") or "").strip().rstrip(".").lower()
    account = acme_issue.account_key_path()
    info.update(
        {
            "enabled": bool(http.get("enabled")),
            "running": running,
            "pid": pid if running else None,
            "hostname": host,
            "port": int(http.get("port") or 5555),
            "bind": _bind(http),
            "listen": _listen_hosts(_bind(http)),
            "workers": int(http.get("workers") or 1),
            "staging": bool(http.get("staging")),
            "acme_port": int(http.get("acme_port") or 80),
            "account_key": str(account),
            "account_key_exists": account.is_file(),
        }
    )
    fullchain, privkey = acme_issue.cert_file_paths(host)
    info["fullchain"] = str(fullchain)
    info["privkey"] = str(privkey)
    info["fullchain_exists"] = fullchain.is_file()
    info["privkey_exists"] = privkey.is_file()
    info["needs_issue"] = True if not host else acme_issue.needs_issue(host)
    parsed = acme_issue.cert_info(fullchain) if fullchain.is_file() else None
    if parsed:
        info["not_after"] = parsed["not_after"]
        info["days_left"] = parsed["days_left"]
        info["subject"] = parsed["subject"]
        info["issuer"] = parsed["issuer"]
        info["san"] = parsed["san"]
    if running and started.is_file():
        try:
            started_at = float(started.read_text().strip())
            info["started_at"] = started_at
            info["uptime"] = max(0.0, time.time() - started_at)
        except (OSError, ValueError):
            pass
    return info


def _bind(http: Dict[str, Any]) -> str:
    raw = str(http.get("bind") or DEFAULT_BIND).strip()
    return raw or DEFAULT_BIND


def _listen_hosts(bind: str) -> List[str]:
    raw = str(bind or DEFAULT_BIND).strip() or DEFAULT_BIND
    if raw in {"*", "dual"}:
        return ["0.0.0.0", "::"]
    return [raw]


def _require_acme(http: Dict[str, Any]) -> Optional[str]:
    if not str(http.get("hostname") or "").strip():
        return "http.hostname is required (looking-glass config hostname)"
    return None


def _require_https(http: Dict[str, Any]) -> Optional[str]:
    if not http.get("enabled"):
        return None
    return _require_acme(http)


def _uvicorn_cmd(
    http: Dict[str, Any],
    fullchain: Path,
    privkey: Path,
    host: Optional[str] = None,
) -> list[str]:
    listen = str(host) if host is not None else _listen_hosts(_bind(http))[0]
    port = int(http.get("port") or 5555)
    workers = int(http.get("workers") or 1)
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        UVICORN_APP,
        "--host",
        listen,
        "--port",
        str(port),
    ]
    if workers > 1:
        cmd.extend(["--workers", str(workers)])
    cmd.extend(
        [
            "--ssl-certfile",
            str(fullchain),
            "--ssl-keyfile",
            str(privkey),
            "--access-log",
        ]
    )
    return cmd


def _probe_target(host: str, port: int) -> Tuple[str, int]:
    if host == "::":
        return "::1", port
    if host in {"0.0.0.0", "*", "dual"}:
        return "127.0.0.1", port
    return host, port


def _connect_ok(host: str, port: int, timeout: float = 0.2) -> bool:
    target = _probe_target(host, port)
    try:
        with socket.create_connection(target, timeout=timeout):
            return True
    except OSError:
        return False


def _wait_host(host: str, port: int, timeout: float) -> bool:
    deadline = time.time() + max(0.0, float(timeout))
    while time.time() < deadline:
        if _connect_ok(host, port):
            return True
        time.sleep(0.1)
    return False


def _required_hosts(bind: str) -> List[str]:
    hosts = _listen_hosts(bind)
    if str(bind or DEFAULT_BIND).strip() in {"*", "dual", ""}:
        return ["0.0.0.0"]
    return hosts


def _wait_port(bind: str, port: int, timeout: float) -> bool:
    return all(_wait_host(host, port, timeout) for host in _required_hosts(bind))


def _busy_hosts(bind: str, port: int) -> List[str]:
    return [host for host in _listen_hosts(bind) if _connect_ok(host, port)]


def _port_bound(bind: str, port: int) -> bool:
    return bool(_busy_hosts(bind, port))


def _ps_table() -> str:
    for opts in (["-ax", "-o", "pid=,args="], ["-ax", "-o", "pid=,command="]):
        try:
            return subprocess.check_output(["ps", *opts], text=True, errors="replace")
        except (OSError, subprocess.CalledProcessError):
            continue
    return ""


def _asgi_pids(port: int) -> list[int]:
    """Uvicorn processes serving looking_glass.http.asgi:app on http.port."""
    text = _ps_table()
    port = int(port)
    found: list[int] = []
    me = os.getpid()
    for raw in text.splitlines():
        line = raw.strip()
        if UVICORN_APP not in line:
            continue
        if f"--port {port}" not in line and f"--port={port}" not in line:
            continue
        try:
            pid = int(line.split(None, 1)[0])
        except ValueError:
            continue
        if pid != me and _is_running(pid):
            found.append(pid)
    return found


def _kill_pids(pids: list[int], timeout: float = 5.0) -> None:
    seen = []
    for pid in pids:
        if pid in seen:
            continue
        seen.append(pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            continue
    deadline = time.time() + max(0.1, float(timeout))
    while time.time() < deadline:
        if not any(_is_running(pid) for pid in seen):
            break
        time.sleep(0.1)
    for pid in seen:
        if not _is_running(pid):
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def _stop_orphans(port: int, timeout: float = 5.0) -> None:
    _kill_pids(_asgi_pids(port), timeout=timeout)


def _spawn_uvicorn(
    http: Dict[str, Any],
    fullchain: Path,
    privkey: Path,
    outlog: Path,
    errlog: Path,
    host: str = "0.0.0.0",
):
    cmd = _uvicorn_cmd(http, fullchain, privkey, host=host)
    out_f = open(outlog, "a")
    err_f = open(errlog, "a")
    try:
        return subprocess.Popen(cmd, stdout=out_f, stderr=err_f, close_fds=True)
    finally:
        out_f.close()
        err_f.close()


def _stop_proc(proc: Optional[subprocess.Popen], timeout: float = 5.0) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def _stop_children(
    children: List[Tuple[str, Any]],
    stop_child=_stop_proc,
) -> None:
    for _host, proc in children:
        stop_child(proc)
    children.clear()


def _optional_hosts(bind: str) -> set[str]:
    if str(bind or DEFAULT_BIND).strip() in {"*", "dual", ""}:
        return {"::"}
    return set()


def ensure_ready(
    http: Optional[Dict[str, Any]] = None,
    issuer=None,
    *,
    force: bool = False,
) -> Dict[str, Any]:
    """Validate hostname/email and ensure a certificate exists. Does not bind 5555."""
    cfg = http if http is not None else _http_cfg()
    err = _require_acme(cfg)
    if err:
        raise ValueError(err)
    return acme_issue.ensure_certificate(
        str(cfg.get("hostname") or ""),
        str(cfg.get("email") or ""),
        staging=bool(cfg.get("staging")),
        acme_port=int(cfg.get("acme_port") or 80),
        force=force,
        issuer=issuer,
    )


def supervisor_loop(
    *,
    poll: float = POLL_SECONDS,
    renew_every: float = RENEW_SECONDS,
    issuer=None,
    spawn=_spawn_uvicorn,
    stop_child=_stop_proc,
    sleep=time.sleep,
    should_stop=None,
) -> None:
    """Issue/renew certs, run uvicorn, restart on config/cert/worker changes."""
    children: List[Tuple[str, Any]] = []
    last_fp: Optional[Tuple[Any, ...]] = None
    last_renew = 0.0
    skip_optional: set[str] = set()
    pidfile, started, outlog, errlog = _paths()
    try:
        while True:
            if should_stop and should_stop():
                break
            http = _http_cfg()
            if not http.get("enabled"):
                _stop_children(children, stop_child)
                last_fp = None
                skip_optional.clear()
                sleep(poll)
                continue
            now = time.time()
            try:
                if now - last_renew >= renew_every or last_fp is None:
                    paths = ensure_ready(http, issuer=issuer)
                    last_renew = now
                else:
                    host = str(http.get("hostname") or "")
                    fullchain, privkey = acme_issue.cert_files(host)
                    paths = {"fullchain": str(fullchain), "privkey": str(privkey)}
            except Exception as exc:
                err = acme_issue.format_acme_error(exc)
                acme_issue.append_acme_log(f"fail {err}")
                print(f"HTTPS ACME: {err}", file=sys.stderr, flush=True)
                sleep(poll)
                continue
            fullchain = Path(paths["fullchain"])
            privkey = Path(paths["privkey"])
            fp = _fingerprint(http, fullchain, privkey)
            bind = _bind(http)
            optional = _optional_hosts(bind)
            if fp != last_fp:
                skip_optional.clear()
            fatal = False
            kept: List[Tuple[str, Any]] = []
            for listen, proc in children:
                alive = proc is not None and proc.poll() is None
                if alive:
                    kept.append((listen, proc))
                    continue
                if listen in optional:
                    print(
                        f"HTTPS: {listen} listener exited; continuing without it",
                        file=sys.stderr,
                        flush=True,
                    )
                    skip_optional.add(listen)
                    continue
                fatal = True
            children[:] = kept
            want = [h for h in _listen_hosts(bind) if h not in skip_optional]
            have = {listen for listen, _proc in children}
            missing = [h for h in want if h not in have]
            if fatal or fp != last_fp or missing:
                if fatal or fp != last_fp:
                    _stop_children(children, stop_child)
                    want = [h for h in _listen_hosts(bind) if h not in skip_optional]
                for listen in want:
                    if any(h == listen for h, _p in children):
                        continue
                    children.append(
                        (
                            listen,
                            spawn(http, fullchain, privkey, outlog, errlog, host=listen),
                        )
                    )
                last_fp = fp
            sleep(poll)
    finally:
        _stop_children(children, stop_child)


def start(timeout: int = 8, foreground: bool = False) -> Dict[str, Any]:
    """Start the HTTPS supervisor if http.enabled. Idempotent when already up."""
    http = _http_cfg()
    info = status()
    if not http.get("enabled"):
        info.update({"ok": True, "state": "disabled", "enabled": False})
        return info
    err = _require_https(http)
    if err:
        info.update({"ok": False, "state": "error", "error": err})
        return info
    pidfile, started, outlog, errlog = _paths()
    existing = _read_pid(pidfile)
    if existing and _is_running(existing):
        info.update({"ok": True, "state": "already_running"})
        return info
    _remove(pidfile)
    _remove(started)
    bind = _bind(http)
    port = int(http.get("port") or 5555)
    busy = _busy_hosts(bind, port)
    if busy:
        used = busy[0]
        info.update(
            {
                "ok": False,
                "state": "error",
                "error": (
                    f"address already in use on {used}:{port}; "
                    "stop the leftover listener with looking-glass https stop"
                ),
                "bind": bind,
                "listen": _listen_hosts(bind),
                "port": port,
            }
        )
        return info
    try:
        ensure_ready(http)
    except Exception as exc:
        err = acme_issue.format_acme_error(exc)
        acme_issue.append_acme_log(f"fail {err}")
        info.update({"ok": False, "state": "error", "error": err})
        return info
    if foreground:
        _write_pid(pidfile, os.getpid())
        _write_started(started)
        try:
            supervisor_loop()
        finally:
            _remove(pidfile)
            _remove(started)
        info = status()
        info.update({"ok": True, "state": "stopped"})
        return info
    cmd = [sys.executable, "-m", "looking_glass.http.https_serve"]
    out_f = open(outlog, "a")
    err_f = open(errlog, "a")
    try:
        proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f, close_fds=True)
    finally:
        out_f.close()
        err_f.close()
    _write_pid(pidfile, proc.pid)
    _write_started(started)
    bind = _bind(http)
    port = int(http.get("port") or 5555)
    ready = _wait_port(bind, port, timeout)
    if proc.poll() is not None:
        _remove(pidfile)
        _remove(started)
        info = _base_info()
        info.update(
            {
                "ok": False,
                "state": "error",
                "error": f"HTTPS supervisor exited early; see {errlog}",
                "enabled": True,
            }
        )
        return info
    info = status()
    info.update({"ok": True, "state": "started", "port_ready": ready})
    return info


def stop(timeout: int = 5) -> Dict[str, Any]:
    pidfile, started, _out, _err = _paths()
    http = _http_cfg()
    port = int(http.get("port") or 5555)
    pid = _read_pid(pidfile)
    if pid and _is_running(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not _is_running(pid):
                break
            time.sleep(0.1)
        if _is_running(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    _remove(pidfile)
    _remove(started)
    _stop_orphans(port, timeout=timeout)
    info = _base_info()
    info.update({"ok": True, "state": "stopped", "running": False, "pid": None})
    return info


def _tail(path: Path, lines: int) -> str:
    if lines <= 0 or not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    bits = text.splitlines()
    return "\n".join(bits[-int(lines) :])


def logs(lines: int = 50) -> Dict[str, Any]:
    """Last N lines of the HTTPS supervisor stdout and stderr logs."""
    _pidfile, _started, outlog, errlog = _paths()
    n = max(0, int(lines))
    return {
        "ok": True,
        "out_log": str(outlog),
        "err_log": str(errlog),
        "lines": n,
        "out": _tail(outlog, n),
        "err": _tail(errlog, n),
    }


def renew(*, force: bool = False) -> Dict[str, Any]:
    """Issue or renew the certificate. Does not start the supervisor."""
    http = _http_cfg()
    info = status()
    err = _require_acme(http)
    if err:
        info.update({"ok": False, "state": "error", "error": err})
        return info
    try:
        result = ensure_ready(http, force=force)
    except Exception as exc:
        err = acme_issue.format_acme_error(exc)
        acme_issue.append_acme_log(f"fail {err}")
        info.update({"ok": False, "state": "error", "error": err})
        return info
    info = status()
    issued = bool(result.get("issued"))
    info.update(
        {
            "ok": True,
            "state": "issued" if issued else "unchanged",
            "issued": issued,
            "staging": bool(http.get("staging")),
        }
    )
    return info


def main() -> None:
    supervisor_loop()


if __name__ == "__main__":
    main()
