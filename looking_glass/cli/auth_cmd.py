"""Click commands for admin password, API keys, and sessions."""

from __future__ import annotations

import getpass
import sys

import click

from ..auth import keys, password, session
from .render import emit


@click.group("auth")
def auth_group() -> None:
    """Manage the GUI password, API keys, and file sessions.

    An unset password disables login (it does not open admin). API keys
    work independently and grant the same admin rights as a password session.

    \b
    looking-glass auth password set
    looking-glass auth keys create tokyo
    looking-glass auth sessions clear
    """


@auth_group.group("password", invoke_without_command=True)
@click.pass_context
def password_group(ctx: click.Context) -> None:
    """Show whether the admin password is set, or set/clear it."""
    if ctx.invoked_subcommand is None:
        emit({"ok": True, "set": password.is_set()}, kind="auth")


def _secret(label: str) -> str:
    if sys.stdin.isatty():
        return getpass.getpass(f"{label}: ")
    return (sys.stdin.readline() or "").rstrip("\n")


@password_group.command("set")
def password_set() -> None:
    """Set the GUI admin password (prompted, not on the command line)."""
    first = _secret("Password")
    second = _secret("Confirm")
    if first != second:
        raise click.UsageError("passwords do not match")
    try:
        password.set_password(first)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    emit({"ok": True, "set": True}, kind="auth")


@password_group.command("clear")
def password_clear() -> None:
    """Disable GUI login. Existing API keys still work."""
    password.clear()
    emit({"ok": True, "set": False}, kind="auth")


@auth_group.group("keys", invoke_without_command=True)
@click.pass_context
def keys_group(ctx: click.Context) -> None:
    """List or create API keys. Secrets are shown once at create."""
    if ctx.invoked_subcommand is None:
        listed = keys.list_keys()
        emit({"ok": True, "keys": listed, "count": len(listed)}, kind="auth")


@keys_group.command("create")
@click.argument("name", required=False, default="key")
def keys_create(name: str) -> None:
    """Create a key named NAME and print the secret once."""
    try:
        created = keys.create(name)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    emit({"ok": True, **created}, kind="auth")


@keys_group.command("revoke")
@click.argument("key_id")
def keys_revoke(key_id: str) -> None:
    """Revoke the key with ID."""
    if not keys.revoke(key_id):
        raise click.UsageError("unknown key")
    emit({"ok": True, "id": key_id}, kind="auth")


@auth_group.group("sessions")
def sessions_group() -> None:
    """File sessions under ~/.looking-glass/data/sessions."""


@sessions_group.command("clear")
def sessions_clear() -> None:
    """Delete every on-disk GUI session."""
    removed = session.clear_all()
    emit({"ok": True, "removed": removed}, kind="auth")
