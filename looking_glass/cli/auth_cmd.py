"""Click commands for PAM admin allowlist and sessions."""

from __future__ import annotations

import click

from ..auth import session, users
from .render import emit


@click.group("auth")
def auth_group() -> None:
    """Manage GUI admin users and file sessions.

    The first successful PAM login (never root) is added automatically.
    Later logins must be on the allowlist. Passwords stay in PAM.

    \b
    looking-glass auth users
    looking-glass auth users add alice
    looking-glass auth users remove alice
    looking-glass auth sessions clear
    """


@auth_group.group("users", invoke_without_command=True)
@click.pass_context
def users_group(ctx: click.Context) -> None:
    """List or edit the admin allowlist in ~/.looking-glass/config.json."""
    if ctx.invoked_subcommand is None:
        names = users.list_users()
        emit({"ok": True, "users": names, "count": len(names)}, kind="auth")


@users_group.command("add")
@click.argument("name")
def users_add(name: str) -> None:
    """Allow NAME to log in after PAM succeeds."""
    try:
        names = users.add_user(name)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    emit({"ok": True, "users": names, "count": len(names)}, kind="auth")


@users_group.command("remove")
@click.argument("name")
def users_remove(name: str) -> None:
    """Remove NAME from the admin allowlist."""
    names = users.remove_user(name)
    emit({"ok": True, "users": names, "count": len(names)}, kind="auth")


@auth_group.group("sessions")
def sessions_group() -> None:
    """File sessions under ~/.looking-glass/data/sessions."""


@sessions_group.command("clear")
def sessions_clear() -> None:
    """Delete every on-disk GUI session."""
    removed = session.clear_all()
    emit({"ok": True, "removed": removed}, kind="auth")
