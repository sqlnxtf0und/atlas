"""``atlas project`` — project lifecycle."""

from __future__ import annotations

from typing import Annotated

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, info, print_table, success
from atlas.core.time import isoformat
from atlas.services.projects import (
    create_project,
    delete_project,
    get_project,
    list_projects,
    project_stats,
)

__all__ = ["app"]

app = typer.Typer(help="Create, inspect and remove projects.", no_args_is_help=True)


@app.command("create")
def create(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Human-readable project name.")],
    slug: Annotated[str | None, typer.Option("--slug", help="Override the derived slug.")] = None,
    description: Annotated[str | None, typer.Option("--description")] = None,
    retention_days: Annotated[int | None, typer.Option("--retention-days", min=1, max=3650)] = None,
) -> None:
    """Create a project."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = create_project(
            session,
            name=name,
            slug=slug,
            description=description,
            retention_days=retention_days,
            actor=context.actor,
        )
        payload = {
            "id": str(project.id),
            "slug": project.slug,
            "name": project.name,
            "description": project.description,
            "retention_days": project.retention_days,
        }

    emit(context, payload)
    if context.json_output:
        return
    success(context, f"project '{payload['slug']}' created")


@app.command("list")
def list_command(ctx: typer.Context) -> None:
    """List projects with counters."""

    context: AppContext = ctx.obj
    rows: list[dict[str, object]] = []
    with context.session() as session:
        for project in list_projects(session):
            stats = project_stats(session, project)
            rows.append(
                {
                    "slug": project.slug,
                    "name": project.name,
                    "assets": stats["assets"],
                    "findings": stats["findings"],
                    "scope_rules": stats["scope_rules"],
                    "created_at": isoformat(project.created_at),
                }
            )

    emit(context, rows)
    if context.json_output:
        return
    print_table(
        context,
        title="projects",
        columns=["slug", "name", "assets", "findings", "scope", "created"],
        rows=[
            (
                row["slug"],
                row["name"],
                row["assets"],
                row["findings"],
                row["scope_rules"],
                row["created_at"],
            )
            for row in rows
        ],
        empty="no projects — run `atlas init`",
    )


@app.command("show")
def show(
    ctx: typer.Context,
    slug: Annotated[str | None, typer.Argument(help="Project slug (default: --project).")] = None,
) -> None:
    """Show project detail and counters."""

    context: AppContext = ctx.obj
    target = slug or context.project_slug
    with context.session() as session:
        project = get_project(session, target)
        stats = project_stats(session, project)
        payload = {
            "id": str(project.id),
            "slug": project.slug,
            "name": project.name,
            "description": project.description,
            "retention_days": project.retention_days,
            "is_archived": project.is_archived,
            "created_at": isoformat(project.created_at),
            "counters": stats,
        }

    emit(context, payload)
    if context.json_output:
        return
    context.console.print(f"[bold]{payload['slug']}[/bold] — {payload['name']}")
    if payload["description"]:
        info(context, str(payload["description"]))
    for key, value in stats.items():
        context.console.print(f"  {key:<14} {value}")
    context.console.print(f"  {'retention':<14} {payload['retention_days']} days")


@app.command("delete")
def delete(
    ctx: typer.Context,
    slug: Annotated[str, typer.Argument(help="Project slug.")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Confirm deletion.")] = False,
) -> None:
    """Delete a project and everything under it."""

    context: AppContext = ctx.obj
    if not yes:
        raise typer.BadParameter("refusing to delete without --yes")

    with context.session() as session:
        delete_project(session, slug, actor=context.actor)

    emit(context, {"deleted": slug})
    if context.json_output:
        return
    success(context, f"project '{slug}' deleted")
