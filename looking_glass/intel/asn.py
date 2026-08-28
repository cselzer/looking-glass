"""
ASN origin lookup using pyasn.

This replaces the old CAIDA pfx2as JSON/range loader with a pyasn-backed
database built from a RouteViews RIB.

Public API kept compatible with previous usage:

    load(force: bool = False) -> bool
    build(force: bool = False) -> bool
    find_origin(as_ip: str) -> Optional[Dict[str, Any]]
    get_fetched_at() -> int
    shrink() -> None   (now a no-op)
"""

from __future__ import annotations

import os
import glob
import shutil
import ipaddress
import subprocess
import threading
from typing import Callable, Optional, Dict, Any

import pyasn  # type: ignore

from ..utility import LogFn, ProgressFn, build_info, get_cache_path

# Where we store the pyasn DB
_DB_NAME = "asn_prefix.ipasn.dat"

_asndb: Optional[pyasn.pyasn] = None
_asndb_path: Optional[str] = None
_fetched_at: int = 0
_meta_built: bool = False


def _db_path() -> str:
    """
    Full path to the pyasn DB file in the project's cache directory.
    """
    return get_cache_path(_DB_NAME)


def _load_db() -> bool:
    """
    Load an existing pyasn DB from disk into memory.
    """
    global _asndb, _asndb_path, _fetched_at, _meta_built

    path = _db_path()
    if not os.path.exists(path):
        return False

    try:
        _asndb = pyasn.pyasn(path)
        _asndb_path = path
        _fetched_at = int(os.path.getmtime(path))
        _meta_built = True
        return True
    except Exception:
        _asndb = None
        _meta_built = False
        return False


def load(force: bool = False) -> bool:
    """
    Load ASN DB from disk.

    - If force is False and DB exists, just load it.
    - Does NOT download/convert anything; build() is responsible for that.
    """
    if not force and _meta_built and _asndb is not None:
        return True
    return _load_db()


def get_fetched_at() -> int:
    """
    Return unix timestamp when the DB file was last written (mtime).
    """
    return int(_fetched_at or 0)


def shrink() -> None:
    """
    Backwards-compat stub.

    Old implementation dropped large in-memory range lists; pyasn already
    uses a compact structure, so there’s nothing meaningful to shrink here.
    We leave this as a no-op so callers don’t break.
    """
    # If you really wanted to free memory, you could uncomment this:
    # global _asndb, _meta_built
    # _asndb = None
    # _meta_built = False
    return


_PYASN_DOWNLOAD = "pyasn_util_download.py"
_PYASN_CONVERT = "pyasn_util_convert.py"


def _find_tool(name: str) -> Optional[str]:
    return shutil.which(name) or shutil.which(name.removesuffix(".py"))


def _require_pyasn_tools() -> tuple[str, str]:
    download = _find_tool(_PYASN_DOWNLOAD)
    convert = _find_tool(_PYASN_CONVERT)
    if not download or not convert:
        raise RuntimeError(
            "ASN build needs pyasn CLI tools on PATH "
            f"({_PYASN_DOWNLOAD}, {_PYASN_CONVERT}). Install with: pip install pyasn"
        )
    return download, convert


def _run(cmd: list[str], cwd: Optional[str] = None, log: Optional[LogFn] = None) -> None:
    """Run a command, streaming output to log (or stdout) and raising on failure."""
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    lines: list[str] = []
    assert proc.stdout is not None
    for raw in proc.stdout:
        text = raw.rstrip()
        if not text:
            continue
        lines.append(text)
        if log is not None:
            log(text)
        else:
            print(text)
    rc = proc.wait()
    if rc != 0:
        tail = "\n".join(lines[-20:])
        raise RuntimeError(f"Command failed ({rc}): {' '.join(cmd)}\n{tail}")


def _watch_growing_file(
    get_path: Callable[[], Optional[str]],
    progress: ProgressFn,
    stop: threading.Event,
) -> None:
    last = 0
    while not stop.wait(0.2):
        path = get_path()
        if not path or not os.path.exists(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        if size > last:
            try:
                progress(size - last, None)
            except Exception:
                pass
            last = size


def _run_watched(
    cmd: list[str],
    cwd: Optional[str],
    log: Optional[LogFn],
    progress: Optional[ProgressFn],
    get_path: Callable[[], Optional[str]],
) -> None:
    if progress is None:
        _run(cmd, cwd=cwd, log=log)
        return
    stop = threading.Event()
    t = threading.Thread(
        target=_watch_growing_file,
        args=(get_path, progress, stop),
        daemon=True,
    )
    t.start()
    try:
        _run(cmd, cwd=cwd, log=log)
    finally:
        stop.set()
        t.join(timeout=1.0)


def _cleanup_rib_files(dirpath: str) -> None:
    for path in glob.glob(os.path.join(dirpath, "rib.20*.bz2")):
        try:
            os.remove(path)
        except OSError:
            pass


def _find_latest_rib(dirpath: str) -> Optional[str]:
    """
    Find the most recent RouteViews rib.*.bz2 file in dirpath.
    pyasn_util_download.py drops them in the CWD.
    """
    pattern = os.path.join(dirpath, "rib.20*.bz2")
    candidates = glob.glob(pattern)
    if not candidates:
        return None
    # newest by mtime
    candidates.sort(key=os.path.getmtime, reverse=True)
    return candidates[0]


def build(
    force: bool = False,
    log: Optional[LogFn] = None,
    progress: Optional[ProgressFn] = None,
) -> bool:
    """
    Build or refresh the pyasn DB using pyasn’s CLI utilities.

    Workflow:
      1) If not force and a DB is already present, just load it.
      2) Run: pyasn_util_download.py --latestv46
      3) Pick the newest rib.20*.bz2 in the cache dir
      4) Run: pyasn_util_convert.py --single <rib> <ipasn.dat>
      5) Load the resulting DB into memory

    Requires that pyasn is installed with its CLI tools on PATH:
      - pyasn_util_download.py
      - pyasn_util_convert.py
    """
    info = build_info("asn build", log)

    info("starting ASN build via pyasn")

    if not force:
        info("checking for existing DB")
        if _load_db():
            info("using existing DB")
            return True
        info("no existing DB, downloading RouteViews RIB")

    download, convert = _require_pyasn_tools()
    cache_dir = os.path.dirname(_db_path())
    os.makedirs(cache_dir, exist_ok=True)

    try:
        info("downloading latest IPv4+IPv6 RIB (this can take a few minutes)")
        _run_watched(
            [download, "--latestv46"],
            cwd=cache_dir,
            log=info,
            progress=progress,
            get_path=lambda: _find_latest_rib(cache_dir),
        )
    except Exception as e:
        info(f"download failed: {e}")
        return False

    rib_file = _find_latest_rib(cache_dir)
    if not rib_file:
        info("no rib.20*.bz2 files found after download")
        return False

    info(f"converting {os.path.basename(rib_file)}")
    db_path = _db_path()
    try:
        _run_watched(
            [convert, "--single", rib_file, db_path],
            cwd=cache_dir,
            log=info,
            progress=progress,
            get_path=lambda: db_path if os.path.exists(db_path) else None,
        )
    except Exception as e:
        info(f"convert failed: {e}")
        return False

    _cleanup_rib_files(cache_dir)

    if not _load_db():
        info("failed to load DB after conversion")
        return False

    info("ASN DB ready")
    return True


def find_origin(as_ip: str) -> Optional[Dict[str, Any]]:
    """
    Return {"asn": int, "prefix": str} for as_ip, or None if unknown.

    Keeps the old signature/behavior, but delegates to pyasn’s lookup.

    Example:
        >>> find_origin("1.1.1.1")
        {"asn": 13335, "prefix": "1.1.1.0/24"}   # if present in DB
    """
    global _meta_built

    # Normalize and validate IP up front (avoid pyasn exceptions on garbage)
    try:
        ip_obj = ipaddress.ip_address(as_ip)
    except Exception:
        return None

    if not _meta_built or _asndb is None:
        # Try lazy load; if this fails, caller should run build()
        if not _load_db():
            return None

    try:
        asn, prefix = _asndb.lookup(str(ip_obj))  # type: ignore[operator]
    except Exception:
        return None

    if asn is None or prefix is None:
        return None

    try:
        asn_int = int(asn)
    except Exception:
        return None

    return {"asn": asn_int, "prefix": str(prefix)}