"""``atlas audit`` — append-only audit feed."""

from __future__ import annotations

from typing import Annotated

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, print_table
from atlas.core.time import isoformat
from atlas.services.audit import list_events

__all__ = ["app"]

app = typer.Typer(help="Inspect the audit trail.", no_args_is_help=True)


@app.command("list")
def list_command(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("--limit", min=1, max=1000)] = 50,
    action: Annotated[str | None, typer.Option("--action", help="Filter by action name.")] = None,
    project: Annotated[
        bool, typer.Option("--project", help="Restrict to the active project.")
    ] = False,
) -> None:
    """List audit events, newest first."""

    context: AppContext = ctx.obj
    rows: list[dict[str, object]] = []
    with context.session() as session:
        project_id = context.project(session).id if project else None
        for event in list_events(session, project_id=project_id, action=action, limit=limit):
            rows.append(
                {
                    "created_at": isoformat(event.created_at),
                    "actor": event.actor,
                    "action": event.action,
                    "object": f"{event.object_type or '-'}:{event.object_id or '-'}",
                    "outcome": event.outcome,
                    "detail": event.detail,
                }
            )

    emit(context, rows)
    if context.json_output:
        return
    print_table(
        context,
        title="audit",
        columns=["when", "actor", "action", "object", "outcome"],
        rows=[
            (row["created_at"], row["actor"], row["action"], row["object"], row["outcome"])
            for row in rows
        ],
        empty="no audit events",
    )
