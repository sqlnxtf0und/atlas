"""``atlas sources`` — third-party intelligence sources.

A source is an observer ATLAS reads, never one it submits to. ``urlscan`` accepts a
scan id (or a public urlscan.io result URL) and ingests what that scan already
captured. The scope gate applies to the captured page, so a scan of infrastructure
outside the project raises and aborts.
"""

from __future__ import annotations

from typing import Annotated

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, info, print_table, success, warn
from atlas.services.urlscan import ingest_urlscan_scan, urlscan_scan

__all__ = ["app"]

app = typer.Typer(help="Read third-party intelligence sources.", no_args_is_help=True)


@app.command("urlscan")
def urlscan(
    ctx: typer.Context,
    scan_id: Annotated[str, typer.Argument(help="urlscan.io scan UUID or result URL.")],
    show_only: Annotated[
        bool, typer.Option("--show", help="Only print a previously ingested scan.")
    ] = False,
) -> None:
    """Ingest (or show) one urlscan.io scan result."""

    context: AppContext = ctx.obj
    if show_only:
        with context.session() as session:
            project = context.project(session)
            payload = urlscan_scan(session, project, scan_id)
        emit(context, payload)
        if context.json_output:
            return
        context.console.print(
            f"[bold]{payload['page_url'] or payload['page_domain']}[/bold] ({payload['scan_id']})"
        )
        context.console.print(f"  scanned      {payload['scanned_at'] or '—'}")
        context.console.print(
            f"  verdict      score={payload['verdict_score']} "
            f"malicious={payload['verdict_malicious']} (urlscan.io opinion)"
        )
        for host in payload["hosts"]:
            context.console.print(
                f"  host         {host.get('host')} [{host.get('kind')}] "
                f"{'in scope' if host.get('in_scope') else 'out of scope'}"
            )
        info(context, f"{len(payload['requests'])} archived request(s)")
        return

    with context.session() as session:
        project = context.project(session)
        ingestion = ingest_urlscan_scan(
            session, project, context.settings, scan_id, actor=context.actor
        )

    emit(context, ingestion.as_dict())
    if context.json_output:
        if ingestion.status == "succeeded":
            return
        raise typer.Exit(1)

    outcome = ingestion.outcome
    context.console.print(
        f"[bold]{outcome.page_url or outcome.page_domain}[/bold] ({outcome.scan_id})"
    )
    context.console.print(f"  scans        {outcome.scans}")
    context.console.print(
        f"  hosts        {outcome.hosts_in_scope} in scope, "
        f"{outcome.hosts_out_of_scope} out of scope (archived, not promoted)"
    )
    context.console.print(f"  requests     {outcome.requests}")
    context.console.print(f"  relationships {outcome.relationships}")
    if outcome.verdict_score is not None:
        print_table(
            context,
            title="urlscan.io verdict (third-party opinion, provenance only)",
            columns=["score", "malicious"],
            rows=[(outcome.verdict_score, outcome.verdict_malicious)],
            empty="—",
        )
    for error in ingestion.errors:
        warn(context, f"{error.get('operation')}: {error.get('message')}")
    if ingestion.status == "succeeded":
        success(context, f"job {ingestion.job_id} ingested scan {outcome.scan_id}")
    else:
        warn(context, f"job {ingestion.job_id} finished {ingestion.status}")
        raise typer.Exit(1)
