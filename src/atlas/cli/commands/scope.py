"""``atlas scope`` — authorization rules for a project."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, info, print_table, success
from atlas.core.time import isoformat, utcnow
from atlas.db.enums import ScopeKind, ScopeMode
from atlas.errors import ValidationError
from atlas.services.scopes import (
    add_rule,
    build_scope_set,
    check_value,
    list_rules,
    remove_rules,
    summarize,
)

__all__ = ["app"]

app = typer.Typer(help="Manage and evaluate authorized scope.", no_args_is_help=True)


def _parse_expiry(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValidationError(f"--expires must be an ISO date (YYYY-MM-DD): {value!r}") from exc
    return parsed


@app.command("add")
def add(
    ctx: typer.Context,
    pattern: Annotated[str, typer.Argument(help="Domain, IP, CIDR, ASN or URL.")],
    kind: Annotated[
        ScopeKind | None, typer.Option("--kind", help="Rule kind (inferred when omitted).")
    ] = None,
    mode: Annotated[ScopeMode, typer.Option("--mode")] = ScopeMode.INCLUDE,
    no_subdomains: Annotated[
        bool, typer.Option("--no-subdomains", help="Match the exact domain only.")
    ] = False,
    note: Annotated[str | None, typer.Option("--note")] = None,
    expires: Annotated[str | None, typer.Option("--expires", help="YYYY-MM-DD")] = None,
) -> None:
    """Add an include or exclude rule."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        rule = add_rule(
            session,
            project,
            pattern=pattern,
            kind=kind,
            mode=mode,
            include_subdomains=not no_subdomains,
            note=note,
            expires_at=_parse_expiry(expires),
            actor=context.actor,
        )
        payload = summarize(rule)

    emit(context, payload)
    if context.json_output:
        return
    success(
        context,
        f"{payload['mode']} {payload['kind']} {payload['pattern']}"
        + (" (subdomains)" if payload["include_subdomains"] else ""),
    )


@app.command("list")
def list_command(
    ctx: typer.Context,
    all_rules: Annotated[bool, typer.Option("--all", help="Include inactive rules.")] = False,
) -> None:
    """List scope rules for the active project."""

    context: AppContext = ctx.obj
    rows: list[dict[str, Any]] = []
    with context.session() as session:
        project = context.project(session)
        for rule in list_rules(session, project, include_inactive=all_rules):
            rows.append(summarize(rule))

    emit(context, rows)
    if context.json_output:
        return
    print_table(
        context,
        title=f"scope — {context.project_slug}",
        columns=["mode", "kind", "pattern", "subdomains", "active", "expires", "note"],
        rows=[
            (
                row["mode"],
                row["kind"],
                row["pattern"],
                "yes" if row["include_subdomains"] else "no",
                "yes" if row["is_active"] else "no",
                (row["expires_at"] or "")[:10],
                row["note"] or "",
            )
            for row in rows
        ],
        empty="no scope rules — collection is denied by default",
    )


@app.command("remove")
def remove(
    ctx: typer.Context,
    pattern: Annotated[str, typer.Argument(help="Rule pattern to remove.")],
    kind: Annotated[ScopeKind | None, typer.Option("--kind")] = None,
    mode: Annotated[ScopeMode | None, typer.Option("--mode")] = None,
) -> None:
    """Remove matching scope rules."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        removed = remove_rules(
            session, project, pattern=pattern, kind=kind, mode=mode, actor=context.actor
        )

    emit(context, {"removed": removed, "pattern": pattern})
    if context.json_output:
        return
    success(context, f"removed {removed} rule(s) for {pattern}")


@app.command("check")
def check(
    ctx: typer.Context,
    value: Annotated[str, typer.Argument(help="Hostname, IP, CIDR or URL to evaluate.")],
) -> None:
    """Evaluate a value against the project scope (same code path collectors use)."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        decision = check_value(session, project, context.settings, value, actor=context.actor)
        payload = decision.as_dict()

    emit(context, payload)
    if not context.json_output:
        style = "green" if decision.permitted else "red"
        context.console.print(
            f"[{style}]{'PERMITTED' if decision.permitted else 'DENIED'}[/{style}] {value}"
        )
        context.console.print(f"  reason  {decision.reason}")
        if decision.normalized:
            context.console.print(f"  matched {decision.normalized}")

    if not decision.permitted:
        raise typer.Exit(code=3)


@app.command("export")
def export(ctx: typer.Context) -> None:
    """Emit the effective scope as JSON."""

    context: AppContext = ctx.obj
    with context.session() as session:
        project = context.project(session)
        scope = build_scope_set(session, project, context.settings)
        payload = {
            "project": project.slug,
            "generated_at": isoformat(utcnow()),
            **scope.effective(),
        }

    emit(context, payload)
    if not context.json_output:
        include = len(payload["include"])
        exclude = len(payload["exclude"])
        info(context, f"{include} include rule(s), {exclude} exclude rule(s)")
