"""``atlas certs`` — certificate intelligence views.

Expiry is reported as a date and a day count. Whether a certificate that expires in
nine days is a problem is an operator call, not this command's — no severity is
assigned here.
"""

from __future__ import annotations

from typing import Annotated, Any

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, info, print_table, warn
from atlas.services.certificates import (
    certificate_detail,
    certificates_list,
    expiring_certificates,
)

__all__ = ["app"]

app = typer.Typer(help="Inspect collected certificate intelligence.", no_args_is_help=True)


#: Expiry is rendered as a date plus a day count: the exact timestamp belongs in
#: ``--json`` output and ``certs show``, where it is read deliberately.
_COLUMNS = ["host", "subject", "issuer", "expires", "days", "self-signed"]
_WIDTHS = {"host": 44, "subject": 30, "issuer": 32}


def _clip(value: str, width: int) -> str:
    return value if len(value) <= width else value[: width - 1] + "…"


def _row(cert: dict[str, Any]) -> tuple[Any, ...]:
    expires = cert.get("not_after")
    days = cert.get("days_until_expiry")
    hosts = cert.get("presented_by") or []
    # One certificate can be presented by many hosts; the count is what tells the
    # operator the row is shared without spending the column on a host list.
    host = hosts[0] if hosts else "—"
    if len(hosts) > 1:
        host = f"{host} (+{len(hosts) - 1})"
    return (
        _clip(host, _WIDTHS["host"]),
        _clip(cert.get("subject_cn") or "—", _WIDTHS["subject"]),
        _clip(cert.get("issuer_cn") or "—", _WIDTHS["issuer"]),
        expires[:10] if expires else "—",
        "expired" if cert.get("expired") else (days if days is not None else "—"),
        "yes" if cert.get("is_self_signed") else "no",
    )


@app.command("list")
def list_certificates(
    ctx: typer.Context,
    days: Annotated[
        int | None,
        typer.Option("--days", help="Only certificates expiring within this many days."),
    ] = None,
    include_expired: Annotated[
        bool,
        typer.Option("--include-expired/--hide-expired", help="Show already-expired certificates."),
    ] = True,
    limit: Annotated[int, typer.Option("--limit", min=1, max=10000)] = 200,
) -> None:
    """List collected certificates, soonest expiry first."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        rows = certificates_list(
            session, project, days=days, include_expired=include_expired, limit=limit
        )

    emit(context, {"certificates": rows})
    if context.json_output:
        return

    print_table(
        context,
        title="certificates",
        columns=_COLUMNS,
        rows=[_row(row) for row in rows],
        empty="no certificates — run: atlas collect <host> --type certificates",
    )


@app.command("expiring")
def expiring(
    ctx: typer.Context,
    days: Annotated[int, typer.Option("--days", min=0, max=3650)] = 30,
    include_expired: Annotated[
        bool,
        typer.Option(
            "--include-expired/--hide-expired", help="Include already-expired certificates."
        ),
    ] = True,
) -> None:
    """Report certificates inside an expiry window."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        rows = expiring_certificates(session, project, days=days, include_expired=include_expired)

    emit(context, {"days": days, "certificates": rows})
    if context.json_output:
        return

    if not rows:
        info(context, f"no certificates expiring within {days} day(s)")
        return
    print_table(
        context,
        title=f"certificates expiring within {days} day(s)",
        columns=_COLUMNS,
        rows=[_row(row) for row in rows],
        empty="none",
    )


@app.command("show")
def show(
    ctx: typer.Context,
    fingerprint: Annotated[str, typer.Argument(help="SHA-256 fingerprint (hex).")],
) -> None:
    """Show one certificate and every host that has presented it."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        payload = certificate_detail(session, project, fingerprint)

    emit(context, payload)
    if context.json_output:
        return

    context.console.print(
        f"[bold]{payload['subject_cn'] or payload['fingerprint_sha256'][:16]}[/bold]"
    )
    context.console.print(f"  fingerprint   {payload['fingerprint_sha256']}")
    context.console.print(f"  issuer        {payload['issuer_cn'] or '—'}")
    context.console.print(f"  serial        {payload['serial_number'] or '—'}")
    context.console.print(
        f"  validity      {payload['not_before'] or '—'} → {payload['not_after'] or '—'}"
    )
    key_bits = payload["key_bits"]
    bits = f" {key_bits} bits" if key_bits is not None else ""
    context.console.print(
        f"  key           {payload['key_algorithm'] or '—'}{bits}"
        f"   signature {payload['signature_algorithm'] or '—'}"
    )
    context.console.print(
        f"  self-signed   {'yes' if payload['is_self_signed'] else 'no'}"
        f"   ca {'yes' if payload['is_ca'] else 'no'}"
    )
    if payload["san"]:
        context.console.print(f"  san           {', '.join(payload['san'])}")

    print_table(
        context,
        title="presented by",
        columns=["host", "kind", "first seen", "last seen"],
        rows=[
            (entry["host"], entry["kind"], entry["first_seen"], entry["last_seen"])
            for entry in payload["presented_by"]
        ],
        empty="no bindings recorded",
    )
    if payload.get("shared_note"):
        warn(context, payload["shared_note"])
