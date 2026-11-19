"""``atlas version`` — build and schema information."""

from __future__ import annotations

import platform

import typer
from sqlalchemy import inspect, text

from atlas import __codename__, __version__
from atlas.cli.context import AppContext
from atlas.cli.ui import emit
from atlas.errors import DatabaseError
from atlas.logging import get_logger

__all__ = ["version"]

log = get_logger("cli.version")


def version(ctx: typer.Context) -> None:
    """Print version, runtime and schema revision."""

    context: AppContext = ctx.obj
    schema = _schema_revision(context)

    payload = {
        "name": "ATLAS",
        "version": __version__,
        "codename": __codename__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "database": context.settings.database.url.split("://", 1)[0],
        "schema_revision": schema,
    }

    emit(context, payload)
    if context.json_output:
        return

    context.console.print(f"[bold]ATLAS[/bold] {__version__} — {__codename__}")
    context.console.print(f"  python          {payload['python']}")
    context.console.print(f"  platform        {payload['platform']}")
    context.console.print(f"  database        {payload['database']}")
    context.console.print(f"  schema revision {schema or '[yellow]not migrated[/yellow]'}")


def _schema_revision(context: AppContext) -> str | None:
    try:
        inspector = inspect(context.engine)
        if not inspector.has_table("alembic_version"):
            return None
        with context.engine.connect() as connection:
            row = connection.execute(text("SELECT version_num FROM alembic_version")).first()
        return str(row[0]) if row else None
    except DatabaseError:
        return None
    except Exception as exc:
        log.debug("schema revision unavailable: %s", exc)
        return None
