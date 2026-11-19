"""``atlas http`` — HTTP observation views."""

from __future__ import annotations

from typing import Annotated

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, info, print_table
from atlas.services.http import http_services, http_snapshot, http_snapshots

__all__ = ["app"]

app = typer.Typer(help="Inspect collected HTTP observations.", no_args_is_help=True)


@app.command("show")
def show(
    ctx: typer.Context,
    host: Annotated[str, typer.Argument(help="Host name or address that was collected.")],
) -> None:
    """Show the most recent HTTP observation for a host."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        payload = http_snapshot(session, project, host)
        services = http_services(session, project, host=host)

    emit(context, {"http": payload, "services": services})
    if context.json_output:
        return

    context.console.print(f"[bold]{payload.get('host') or host}[/bold] {payload.get('url')}")
    context.console.print(
        f"  status        {payload.get('status')} {payload.get('reason') or ''}".rstrip()
    )
    if payload.get("final_url") and payload.get("final_url") != payload.get("url"):
        context.console.print(f"  final url     {payload['final_url']}")
    context.console.print(
        f"  scheme        {payload.get('scheme')} (port {payload.get('port')})"
        f"   tls {payload.get('tls_version') or '—'}"
    )
    context.console.print(f"  server        {payload.get('server') or '—'}")
    context.console.print(f"  title         {payload.get('title') or '—'}")
    if payload.get("remote_ip"):
        context.console.print(f"  address       {payload['remote_ip']}")

    print_table(
        context,
        title="technologies (evidence, not exploitability)",
        columns=["name", "category", "version", "confidence", "evidence"],
        rows=[
            (
                tech.get("name"),
                tech.get("category"),
                tech.get("version") or "—",
                tech.get("confidence"),
                tech.get("evidence") or "—",
            )
            for tech in payload.get("technologies") or []
        ],
        empty="no technology markers matched",
    )
    print_table(
        context,
        title="cookies (attributes as sent)",
        columns=["name", "secure", "http-only", "same-site", "domain"],
        rows=[
            (
                cookie.get("name"),
                "yes" if cookie.get("secure") else "no",
                "yes" if cookie.get("http_only") else "no",
                cookie.get("same_site") or "—",
                cookie.get("domain") or "—",
            )
            for cookie in payload.get("cookies") or []
        ],
        empty="no Set-Cookie headers",
    )
    if services:
        print_table(
            context,
            title="services",
            columns=["port", "transport", "protocol", "tls", "banner"],
            rows=[
                (
                    service["port"],
                    service["transport"],
                    service["protocol"] or "—",
                    service["tls_version"] or ("yes" if service["tls_enabled"] else "no"),
                    service["banner"] or "—",
                )
                for service in services
            ],
            empty="no services recorded",
        )


@app.command("list")
def list_snapshots(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("--limit", min=1, max=5000)] = 50,
) -> None:
    """List archived HTTP observations, newest first."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        rows = http_snapshots(session, project, limit=limit)

    emit(context, {"observations": rows})
    if context.json_output:
        return

    if not rows:
        info(context, "no HTTP observations recorded — run: atlas collect <host> --type http")
        return
    print_table(
        context,
        title="http observations",
        columns=["host", "status", "server", "title", "observed"],
        rows=[
            (
                row.get("host") or "—",
                row.get("status") if row.get("status") is not None else "—",
                row.get("server") or "—",
                row.get("title") or "—",
                row.get("observed_at") or "—",
            )
            for row in rows
        ],
        empty="none",
    )
