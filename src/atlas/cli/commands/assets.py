"""``atlas assets`` — inventory queries."""

from __future__ import annotations

from typing import Annotated

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, print_table
from atlas.db.enums import AssetKind
from atlas.services.assets import asset_detail, asset_summary, get_asset, list_assets

__all__ = ["app"]

app = typer.Typer(help="Inspect collected assets.", no_args_is_help=True)


@app.command("list")
def list_command(
    ctx: typer.Context,
    kind: Annotated[AssetKind | None, typer.Option("--kind")] = None,
    active: Annotated[
        bool | None,
        typer.Option("--active/--inactive", help="Filter by observation state."),
    ] = None,
    search: Annotated[str | None, typer.Option("--search", help="Substring match on key.")] = None,
    limit: Annotated[int, typer.Option("--limit", min=1, max=10000)] = 100,
) -> None:
    """List assets for the active project."""

    context: AppContext = ctx.obj
    rows: list[dict[str, object]] = []
    with context.session() as session:
        project = context.project(session)
        for asset in list_assets(
            session, project, kind=kind, active=active, search=search, limit=limit
        ):
            rows.append(asset_summary(asset))

    emit(context, rows)
    if context.json_output:
        return
    print_table(
        context,
        title=f"assets — {context.project_slug}",
        columns=["kind", "key", "active", "conf", "first seen", "last seen"],
        rows=[
            (
                row["kind"],
                row["key"],
                "yes" if row["is_active"] else "no",
                f"{row['confidence']:.2f}",
                row["first_seen"],
                row["last_seen"],
            )
            for row in rows
        ],
        empty="no assets — collection lands in phase 2",
    )


@app.command("show")
def show(
    ctx: typer.Context,
    key: Annotated[str, typer.Argument(help="Asset key, e.g. example.com or 203.0.113.10")],
) -> None:
    """Show one asset with kind-specific detail."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        asset = get_asset(session, project, key)
        payload = asset_detail(session, asset)

    emit(context, payload)
    if context.json_output:
        return

    context.console.print(f"[bold]{payload['key']}[/bold] ({payload['kind']})")
    context.console.print(f"  id         {payload['id']}")
    context.console.print(f"  source     {payload['source']}  confidence {payload['confidence']}")
    context.console.print(f"  active     {'yes' if payload['is_active'] else 'no'}")
    context.console.print(f"  first seen {payload['first_seen']}")
    context.console.print(f"  last seen  {payload['last_seen']}")
    for section in ("domain", "ip_address", "certificate", "service"):
        block = payload.get(section)
        if isinstance(block, dict):
            context.console.print(f"  [bold]{section}[/bold]")
            for key_name, value in block.items():
                context.console.print(f"    {key_name:<16} {value}")
    context.console.print(
        f"  relationships  out={payload['relationships']['out']} "
        f"in={payload['relationships']['in']}"
    )
    context.console.print(f"  findings       {payload['findings']}")
