from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as _pkg_version

from .wall import Decision, wall

__all__ = ["Decision", "package_version", "wall"]


def package_version() -> str:
    """Installed looking-glass version (PEP 440 from git tags via setuptools-scm)."""
    try:
        return _pkg_version("looking-glass")
    except PackageNotFoundError:
        try:
            from ._version import version as scm_version
        except ImportError:
            return "0.0.0"
        return str(scm_version)
