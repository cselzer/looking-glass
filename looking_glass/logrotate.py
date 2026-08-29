"""Size-based log rotation owned by looking-glass (no logrotate.d)."""

from __future__ import annotations

import fcntl
import os
from typing import List, Tuple

DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_KEEP = -1
MIN_MAX_BYTES = 1024


def settings() -> Tuple[int, int]:
    """Return (max_bytes, keep). keep=-1 means never delete rotated files."""
    max_bytes = DEFAULT_MAX_BYTES
    keep = DEFAULT_KEEP
    try:
        from .config import load as load_config

        cfg = load_config()
        blob = cfg.get("logs") if isinstance(cfg, dict) else None
    except Exception:
        blob = None
    if isinstance(blob, dict):
        try:
            max_bytes = int(blob.get("max_bytes") or DEFAULT_MAX_BYTES)
        except (TypeError, ValueError):
            max_bytes = DEFAULT_MAX_BYTES
        try:
            raw_keep = blob.get("keep")
            keep = DEFAULT_KEEP if raw_keep is None else int(raw_keep)
        except (TypeError, ValueError):
            keep = DEFAULT_KEEP
    if max_bytes < MIN_MAX_BYTES:
        max_bytes = MIN_MAX_BYTES
    if keep < -1:
        keep = DEFAULT_KEEP
    return max_bytes, keep


def _indices(path: str) -> List[int]:
    base = os.path.basename(path)
    folder = os.path.dirname(path) or "."
    prefix = base + "."
    out: List[int] = []
    try:
        names = os.listdir(folder)
    except OSError:
        return out
    for name in names:
        if not name.startswith(prefix):
            continue
        rest = name[len(prefix) :]
        if rest.isdigit():
            out.append(int(rest))
    return out


def _lock_fd(path: str) -> int:
    dest = path + ".rotate.lock"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(dest, os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _unlock_fd(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    os.close(fd)


def _shift_rotated(path: str, keep: int) -> None:
    indices = sorted(_indices(path), reverse=True)
    if keep == 0:
        for n in indices:
            try:
                os.unlink(f"{path}.{n}")
            except OSError:
                pass
        return
    if keep > 0:
        for n in indices:
            if n >= keep:
                try:
                    os.unlink(f"{path}.{n}")
                except OSError:
                    pass
        indices = [n for n in indices if n < keep]
        for n in sorted(indices, reverse=True):
            dest = n + 1
            if dest > keep:
                try:
                    os.unlink(f"{path}.{n}")
                except OSError:
                    pass
                continue
            try:
                os.replace(f"{path}.{n}", f"{path}.{dest}")
            except OSError:
                pass
        return
    for n in indices:
        try:
            os.replace(f"{path}.{n}", f"{path}.{n + 1}")
        except OSError:
            pass


def rotate_if_needed(path: str) -> bool:
    """Rename-rotate when size >= max_bytes. Returns True if rotated."""
    max_bytes, keep = settings()
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    if size < max_bytes:
        return False
    fd = _lock_fd(path)
    try:
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        if size < max_bytes:
            return False
        _shift_rotated(path, keep)
        if keep == 0:
            try:
                with open(path, "wb"):
                    pass
            except OSError:
                return False
            return True
        try:
            os.replace(path, f"{path}.1")
        except OSError:
            return False
        return True
    finally:
        _unlock_fd(fd)


def copytruncate_if_needed(path: str) -> bool:
    """Copy then truncate in place so open fds keep writing the same inode."""
    max_bytes, keep = settings()
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    if size < max_bytes:
        return False
    fd = _lock_fd(path)
    try:
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        if size < max_bytes:
            return False
        if keep == 0:
            log_fd = os.open(path, os.O_RDWR)
            try:
                os.ftruncate(log_fd, 0)
            finally:
                os.close(log_fd)
            return True
        tmp = f"{path}.rotate.tmp"
        try:
            with open(path, "rb") as src, open(tmp, "wb") as dest:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dest.write(chunk)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False
        _shift_rotated(path, keep)
        try:
            os.replace(tmp, f"{path}.1")
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False
        log_fd = os.open(path, os.O_RDWR)
        try:
            os.ftruncate(log_fd, 0)
        finally:
            os.close(log_fd)
        return True
    finally:
        _unlock_fd(fd)


def append_line(path: str, text: str) -> None:
    """Rotate if needed, then append a line."""
    rotate_if_needed(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = text if text.endswith("\n") else text + "\n"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(payload)
