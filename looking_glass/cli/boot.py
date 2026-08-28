"""systemd --user units for intel + HTTPS. Manual boot check/enable only."""

from __future__ import annotations

import getpass
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import click

from .render import emit

INTEL_UNIT = "looking-glass-intel.service"
HTTPS_UNIT = "looking-glass-https.service"
TARGET_UNIT = "looking-glass.target"
OWNED = (INTEL_UNIT, HTTPS_UNIT, TARGET_UNIT)

_LINGER_HINT = "loginctl enable-linger {user}"


def cli_path() -> str:
    return os.path.join(os.path.dirname(sys.executable), "looking-glass")


def user_unit_dir() -> Path:
    xdg = (os.environ.get("XDG_CONFIG_HOME") or "").strip()
    if xdg:
        return Path(xdg) / "systemd" / "user"
    return Path.home() / ".config" / "systemd" / "user"


def current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return str(os.environ.get("USER") or os.environ.get("LOGNAME") or "")


def canonical_units(exe: Optional[str] = None) -> Dict[str, str]:
    path = exe or cli_path()
    intel = "\n".join(
        [
            "[Unit]",
            "Description=looking-glass intel server",
            "",
            "[Service]",
            "Type=simple",
            "WorkingDirectory=%h",
            "Environment=HOME=%h",
            f"ExecStart={path} lookup-server start --foreground",
            "Restart=on-failure",
            "RestartSec=5",
            "KillMode=mixed",
            "",
            "[Install]",
            "WantedBy=looking-glass.target",
            "",
        ]
    )
    https = "\n".join(
        [
            "[Unit]",
            "Description=looking-glass HTTPS",
            "After=network-online.target looking-glass-intel.service",
            "Wants=network-online.target looking-glass-intel.service",
            "",
            "[Service]",
            "Type=simple",
            "WorkingDirectory=%h",
            "Environment=HOME=%h",
            f"ExecStart={path} https start --foreground",
            "Restart=on-failure",
            "RestartSec=5",
            "KillMode=mixed",
            "",
            "[Install]",
            "WantedBy=looking-glass.target",
            "",
        ]
    )
    target = "\n".join(
        [
            "[Unit]",
            "Description=looking-glass",
            "Wants=looking-glass-intel.service looking-glass-https.service",
            "After=looking-glass-intel.service",
            "",
            "[Install]",
            "WantedBy=default.target",
            "",
        ]
    )
    return {INTEL_UNIT: intel, HTTPS_UNIT: https, TARGET_UNIT: target}


def _run(argv: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return 127, "", f"{argv[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()


def linger_status(user: Optional[str] = None) -> Dict[str, Any]:
    name = (user or current_user()).strip()
    hint = _LINGER_HINT.format(user=name or "$USER")
    if not name:
        return {"ok": False, "enabled": False, "user": "", "hint": hint, "error": "no user"}
    code, out, err = _run(["loginctl", "show-user", name, "-p", "Linger"])
    if code != 0:
        return {
            "ok": False,
            "enabled": False,
            "user": name,
            "hint": hint,
            "error": err or out or f"loginctl exited {code}",
        }
    value = out.split("=", 1)[-1].strip().lower() if "=" in out else out.strip().lower()
    enabled = value in {"yes", "1", "true"}
    return {"ok": True, "enabled": enabled, "user": name, "hint": hint, "raw": out}


def _unit_state(name: str) -> Dict[str, Any]:
    enabled_code, enabled_out, _ = _run(["systemctl", "--user", "is-enabled", name])
    active_code, active_out, _ = _run(["systemctl", "--user", "is-active", name])
    return {
        "unit": name,
        "enabled": enabled_out == "enabled" and enabled_code == 0,
        "enabled_state": enabled_out or "unknown",
        "active": active_out == "active" and active_code == 0,
        "active_state": active_out or "unknown",
    }


def units_enabled() -> bool:
    intel = _unit_state(INTEL_UNIT)
    https = _unit_state(HTTPS_UNIT)
    return bool(intel["enabled"] and https["enabled"])


def restart_units() -> Dict[str, Any]:
    argv = ["systemctl", "--user", "restart", INTEL_UNIT, HTTPS_UNIT]
    code, out, err = _run(argv, timeout=120)
    return {
        "ok": code == 0,
        "argv": argv,
        "code": code,
        "stdout": out,
        "stderr": err,
    }


def unit_status_blob(name: str) -> Dict[str, Any]:
    st = _unit_state(name)
    return {
        "enabled": st["enabled"],
        "active": st["active"],
        "active_state": st["active_state"],
    }


def unit_status_dump() -> str:
    _code, out, err = _run(
        ["systemctl", "--user", "status", "--no-pager", INTEL_UNIT, HTTPS_UNIT],
        timeout=30,
    )
    return "\n".join(part for part in (out, err) if part).strip()


def merge_daemon_status(intel: Dict[str, Any], https: Dict[str, Any]) -> Dict[str, Any]:
    intel = dict(intel)
    https = dict(https)
    intel.setdefault("ok", True)
    https.setdefault("ok", True)
    payload: Dict[str, Any] = {"ok": True, "intel": intel, "https": https, "via": "pidfile"}
    if not units_enabled():
        return payload
    intel["systemd"] = unit_status_blob(INTEL_UNIT)
    https["systemd"] = unit_status_blob(HTTPS_UNIT)
    dump = unit_status_dump()
    if dump:
        payload["systemd_status"] = dump
    payload["via"] = "systemd"
    payload["ok"] = bool(intel["systemd"]["active"] and https["systemd"]["active"])
    payload["intel"] = intel
    payload["https"] = https
    return payload


def _echo_verbose(argv: List[str], out: str = "", err: str = "") -> None:
    from .render import want_json

    if want_json():
        return
    click.echo("$ " + " ".join(argv))
    if out:
        click.echo(out)
    if err:
        click.echo(err, err=True)


def _file_row(dest: Path, wanted: str) -> Dict[str, Any]:
    exists = dest.is_file()
    text = dest.read_text(encoding="utf-8") if exists else ""
    return {
        "path": str(dest),
        "present": exists,
        "matches": exists and text == wanted,
    }


def inspect_units(unit_dir: Optional[Path] = None, exe: Optional[str] = None) -> Dict[str, Any]:
    dest_dir = unit_dir or user_unit_dir()
    wanted = canonical_units(exe)
    return {
        "intel": {**_file_row(dest_dir / INTEL_UNIT, wanted[INTEL_UNIT]), **_unit_state(INTEL_UNIT)},
        "https": {**_file_row(dest_dir / HTTPS_UNIT, wanted[HTTPS_UNIT]), **_unit_state(HTTPS_UNIT)},
        "target": {**_file_row(dest_dir / TARGET_UNIT, wanted[TARGET_UNIT]), **_unit_state(TARGET_UNIT)},
    }


def check(*, unit_dir: Optional[Path] = None, exe: Optional[str] = None) -> Dict[str, Any]:
    linger = linger_status()
    units = inspect_units(unit_dir=unit_dir, exe=exe)
    files_ok = all(units[key]["present"] and units[key]["matches"] for key in ("intel", "https", "target"))
    enabled_ok = all(units[key]["enabled"] for key in ("intel", "https", "target"))
    ok = bool(linger.get("enabled")) and files_ok and enabled_ok
    error = None
    if not linger.get("enabled"):
        error = f"linger is off; as root run `{linger.get('hint')}`"
    elif not files_ok:
        error = "unit files missing or edited; run looking-glass boot enable"
    elif not enabled_ok:
        error = "units not enabled; run looking-glass boot enable"
    payload = {
        "ok": ok,
        "linger": linger,
        "intel": units["intel"],
        "https": units["https"],
        "target": units["target"],
    }
    if error:
        payload["error"] = error
    return payload


def enable(*, unit_dir: Optional[Path] = None, exe: Optional[str] = None) -> Dict[str, Any]:
    linger = linger_status()
    dest_dir = unit_dir or user_unit_dir()
    wanted = canonical_units(exe)
    if not linger.get("enabled"):
        return {
            "ok": False,
            "linger": linger,
            "error": f"linger is off; as root run `{linger.get('hint')}`",
            "hint": linger.get("hint"),
        }
    existed = any((dest_dir / name).is_file() for name in OWNED)
    differed = False
    dest_dir.mkdir(parents=True, exist_ok=True)
    for name, text in wanted.items():
        dest = dest_dir / name
        current = dest.read_text(encoding="utf-8") if dest.is_file() else None
        if current != text:
            differed = True
            dest.write_text(text, encoding="utf-8")
    if existed and differed:
        action = "replaced"
    elif not existed:
        action = "added"
    else:
        action = "unchanged"
    units = inspect_units(unit_dir=dest_dir, exe=exe)
    already = action == "unchanged" and all(
        units[key]["enabled"] and units[key]["active"] for key in ("intel", "https", "target")
    )
    if not already:
        reload_code, _, reload_err = _run(["systemctl", "--user", "daemon-reload"])
        if reload_code != 0:
            return {
                "ok": False,
                "linger": linger,
                "action": action,
                "error": reload_err or "systemctl --user daemon-reload failed",
                "intel": units["intel"],
                "https": units["https"],
                "target": units["target"],
            }
        enable_code, _, enable_err = _run(
            [
                "systemctl",
                "--user",
                "enable",
                "--now",
                INTEL_UNIT,
                HTTPS_UNIT,
                TARGET_UNIT,
            ]
        )
        if enable_code != 0:
            units = inspect_units(unit_dir=dest_dir, exe=exe)
            return {
                "ok": False,
                "linger": linger,
                "action": action,
                "error": enable_err or "systemctl --user enable --now failed",
                "intel": units["intel"],
                "https": units["https"],
                "target": units["target"],
            }
        units = inspect_units(unit_dir=dest_dir, exe=exe)
        if action == "unchanged":
            action = "enabled"
    return {
        "ok": True,
        "linger": linger,
        "action": action,
        "intel": units["intel"],
        "https": units["https"],
        "target": units["target"],
        "note": "day-to-day bounce is looking-glass restart",
    }


@click.group("boot")
def boot_group() -> None:
    """Install systemd --user units so intel and HTTPS start at reboot.

    Requires linger (one root command): loginctl enable-linger $USER.
    Then `looking-glass boot enable`. Units run in the foreground with
    Restart=on-failure. After enable, `looking-glass restart` and
    `looking-glass status` talk to systemd --user.

    \b
    looking-glass boot check
    looking-glass boot enable
    """


@boot_group.command("check")
def boot_check_cmd() -> None:
    """Show linger and whether the looking-glass user units are installed."""
    payload = check()
    emit(payload, kind="boot")
    if not payload.get("ok"):
        raise SystemExit(1)


@boot_group.command("enable")
def boot_enable_cmd() -> None:
    """Write intel/HTTPS user units and enable looking-glass.target."""
    payload = enable()
    emit(payload, kind="boot")
    if not payload.get("ok"):
        raise SystemExit(1)
