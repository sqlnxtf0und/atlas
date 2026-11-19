"""``atlas dns`` — DNS intelligence views."""

from __future__ import annotations

from typing import Annotated

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, info, print_table, warn
from atlas.db.enums import DnsRecordType
from atlas.services.dns import (
    dangling_cnames,
    dns_history,
    dns_records,
    nameserver_summary,
)

__all__ = ["app"]

app = typer.Typer(help="Inspect collected DNS intelligence.", no_args_is_help=True)


def _parse_types(value: str | None) -> list[DnsRecordType] | None:
    if not value:
        return None
    from atlas.errors import ValidationError

    parsed: list[DnsRecordType] = []
    for raw in value.replace(",", " ").split():
        try:
            parsed.append(DnsRecordType(raw.strip().upper()))
        except ValueError as exc:
            raise ValidationError(f"unknown record type: {raw!r}") from exc
    return parsed or None


@app.command("show")
def show(
    ctx: typer.Context,
    fqdn: Annotated[str, typer.Argument(help="Fully qualified domain name.")],
    types: Annotated[
        str | None, typer.Option("--types", help="Comma-separated record types.")
    ] = None,
    all_records: Annotated[
        bool, typer.Option("--all", help="Include retired (no longer observed) records.")
    ] = False,
) -> None:
    """Show the current DNS records for a name."""

    context: AppContext = ctx.obj
    requested = _parse_types(types)

    with context.session() as session:
        project = context.project(session)
        records = dns_records(
            session, project, fqdn, active_only=not all_records, record_types=requested
        )
        rows = [
            {
                "record_type": record.record_type.value,
                "value": record.value,
                "ttl": record.ttl,
                "priority": record.priority,
                "is_active": record.is_active,
                "first_seen": record.first_seen.isoformat(),
                "last_seen": record.last_seen.isoformat(),
                "source": record.source,
            }
            for record in records
        ]

    emit(context, {"fqdn": fqdn, "records": rows})
    if context.json_output:
        return

    print_table(
        context,
        title=f"dns — {fqdn}",
        columns=["type", "value", "ttl", "priority", "active"],
        rows=[
            (
                row["record_type"],
                row["value"],
                "" if row["ttl"] is None else row["ttl"],
                "" if row["priority"] is None else row["priority"],
                "yes" if row["is_active"] else "no",
            )
            for row in rows
        ],
        empty="no records — run: atlas discover <domain>",
    )


@app.command("history")
def history(
    ctx: typer.Context,
    fqdn: Annotated[str, typer.Argument(help="Fully qualified domain name.")],
) -> None:
    """Show every record ever observed for a name, with its observation window."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        payload = dns_history(session, project, fqdn)

    emit(context, payload)
    if context.json_output:
        return

    context.console.print(
        f"[bold]{payload['fqdn']}[/bold] registrable={payload['registrable_domain']} "
        f"apex={'yes' if payload['is_apex'] else 'no'}"
    )
    context.console.print(
        f"  active records {payload['active']}   retired records {payload['retired']}"
    )
    for record_type, entries in payload["records"].items():
        print_table(
            context,
            title=record_type,
            columns=["value", "ttl", "active", "first seen", "last seen"],
            rows=[
                (
                    entry["value"],
                    "" if entry["ttl"] is None else entry["ttl"],
                    "yes" if entry["is_active"] else "no",
                    entry["first_seen"],
                    entry["last_seen"],
                )
                for entry in entries
            ],
            empty="—",
        )


@app.command("nameservers")
def nameservers(
    ctx: typer.Context,
    fqdn: Annotated[str, typer.Argument(help="Fully qualified domain name.")],
) -> None:
    """Show nameservers for a name and other collected names sharing them."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        payload = nameserver_summary(session, project, fqdn)

    emit(context, payload)
    if context.json_output:
        return

    if not payload["nameservers"]:
        info(context, "no nameserver records collected for this name")
        return
    context.console.print(f"[bold]{payload['fqdn']}[/bold] nameservers")
    for server in payload["nameservers"]:
        context.console.print(f"  {server}")
    print_table(
        context,
        title="shared nameservers (shared infrastructure, not shared ownership)",
        columns=["fqdn", "shared"],
        rows=[
            (entry["fqdn"], ", ".join(entry["shared_nameservers"]))
            for entry in payload["shared_with"]
        ],
        empty="no other collected name shares these nameservers",
    )


@app.command("dangling")
def dangling(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("--limit", min=1, max=100000)] = 5000,
) -> None:
    """Report CNAME targets that answered NXDOMAIN when they were observed."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        findings = dangling_cnames(session, project, limit=limit)

    emit(context, findings)
    if context.json_output:
        return

    if not findings:
        info(context, "no dangling CNAME indicators recorded")
        return
    print_table(
        context,
        title="dangling CNAME indicators",
        columns=["cname", "target", "status", "observed"],
        rows=[
            (
                finding["cname"],
                finding["target"],
                finding["target_status"],
                finding["evidence"]["observed_at"],
            )
            for finding in findings
        ],
        empty="none",
    )
    warn(context, "confirm with a fresh lookup before treating a target as claimable")
