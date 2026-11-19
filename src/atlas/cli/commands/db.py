"""``atlas db`` — schema migration wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

import typer
from sqlalchemy import inspect, text

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, success
from atlas.errors import DatabaseError
from atlas.services.bootstrap import migrations_dir, run_migrations

if TYPE_CHECKING:
    from alembic.config import Config

__all__ = ["app"]

app = typer.Typer(help="Database schema operations.", no_args_is_help=True)


def _alembic_config(context: AppContext) -> Config:
    try:
        from alembic.config import Config
    except ImportError as exc:  # pragma: no cover - dependency is pinned
        raise DatabaseError("alembic is not installed") from exc
    config = Config()
    config.set_main_option("script_location", str(migrations_dir()))
    config.set_main_option("sqlalchemy.url", context.settings.database.url)
    return config


@app.command("upgrade")
def upgrade(ctx: typer.Context) -> None:
    """Apply all pending migrations (``alembic upgrade head``)."""

    context: AppContext = ctx.obj
    run_migrations(context.settings)
    emit(context, {"migrated": True, "revision": _current(context)})
    if not context.json_output:
        success(context, f"schema at {_current(context) or 'unknown'}")


@app.command("current")
def current(ctx: typer.Context) -> None:
    """Print the applied schema revision."""

    context: AppContext = ctx.obj
    revision = _current(context)
    emit(context, {"revision": revision})
    if not context.json_output:
        context.console.print(revision or "not migrated")


@app.command("revision")
def revision(
    ctx: typer.Context,
    message: Annotated[str, typer.Option("--message", "-m", help="Migration message.")],
    autogenerate: Annotated[bool, typer.Option("--autogenerate/--empty")] = True,
) -> None:
    """Create a new migration (developer use)."""

    context: AppContext = ctx.obj
    from alembic import command

    config = _alembic_config(context)
    command.revision(config, message=message, autogenerate=autogenerate)
    emit(context, {"created": True, "message": message})
    if not context.json_output:
        success(context, f"migration created: {message}")


def _current(context: AppContext) -> str | None:
    inspector = inspect(context.engine)
    if not inspector.has_table("alembic_version"):
        return None
    with context.engine.connect() as connection:
        row = connection.execute(text("SELECT version_num FROM alembic_version")).first()
    return str(row[0]) if row else None
