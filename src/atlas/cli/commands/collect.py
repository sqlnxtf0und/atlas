"""``atlas discover`` and ``atlas collect`` — run authorized collection.

The two verbs differ only in how much of the pipeline they run:

* ``discover`` runs the passive DNS view of a target (Phase 2's discovery surface);
* ``collect`` runs every registered collector (``--type`` narrows it).

Both refuse an out-of-scope target before a job row exists, and both exit with
:data:`~atlas.errors.EXIT_SCOPE_VIOLATION` when the scope gate denies them.
"""

from __future__ import annotations

from typing import Annotated

import typer

from atlas.cli.context import AppContext
from atlas.cli.ui import emit, info, print_table, success, warn
from atlas.db.enums import JobType
from atlas.errors import EXIT_ERROR, EXIT_OK, ValidationError
from atlas.services.discovery import DiscoveryOutcome, discover
from atlas.services.targets import resolve_target

__all__ = ["collect_command", "discover_command"]

_TYPE_CHOICES = {
    "discover": JobType.DISCOVER,
    "dns": JobType.DNS,
    "certificates": JobType.CERTIFICATES,
    "certs": JobType.CERTIFICATES,
    "http": JobType.HTTP,
    "urlscan": JobType.URLSCAN,
    "full": JobType.FULL,
}


def _render(context: AppContext, outcome: DiscoveryOutcome) -> None:
    if context.json_output:
        emit(context, outcome.as_dict())
        return

    emit(context, outcome.as_dict())
    for result in outcome.collectors:
        summary = result.summary()
        context.console.print(
            f"[bold]{summary['collector']}[/bold] "
            f"{summary['observations']} observation(s) in {summary['duration_seconds']}s"
        )

    if outcome.dns is not None:
        dns = outcome.dns
        context.console.print(f"  name status   {dns.name_status}")
        context.console.print(f"  active records {dns.active_records}")
        if dns.addresses:
            context.console.print(f"  addresses     {', '.join(dns.addresses)}")
        if dns.nameservers:
            context.console.print(f"  nameservers   {', '.join(dns.nameservers)}")
        if dns.added:
            print_table(
                context,
                title="new records",
                columns=["type", "value"],
                rows=[(change.record_type.value, change.value) for change in dns.added],
                empty="no new records",
            )
        if dns.removed:
            print_table(
                context,
                title="retired records",
                columns=["type", "value"],
                rows=[(change.record_type.value, change.value) for change in dns.removed],
                empty="nothing retired",
            )
        for indicator in dns.dangling_cnames:
            warn(
                context,
                f"dangling CNAME: {indicator['cname']} -> {indicator['target']} "
                f"({indicator['target_status']})",
            )

    if outcome.certs is not None:
        certs = outcome.certs
        context.console.print(
            f"  certificate   {certs.subject_cn or '—'} "
            f"issued by {certs.issuer_cn or '—'} "
            f"({'created' if certs.certificate_created else 'known'})"
        )
        context.console.print(
            f"  expires       {certs.not_after or '—'}"
            f"{'' if certs.days_until_expiry is None else f' ({certs.days_until_expiry}d)'}"
            f"{'  EXPIRED' if certs.expired else ''}"
        )
        context.console.print(f"  tls           {certs.tls_version or '—'}")
        if certs.shared_with:
            warn(
                context,
                "certificate also presented by: "
                + ", ".join(certs.shared_with)
                + " — shared infrastructure, not shared ownership",
            )

    if outcome.http is not None:
        http = outcome.http
        context.console.print(
            f"  http          {http.status} {http.final_url or http.url} "
            f"(port {http.port}, {'tls' if http.tls_enabled else 'clear'})"
        )
        if http.server:
            context.console.print(f"  server        {http.server}")
        if http.technologies:
            print_table(
                context,
                title="technology markers (evidence, not exploitability)",
                columns=["name", "category", "version", "confidence"],
                rows=[
                    (
                        tech.get("name"),
                        tech.get("category"),
                        tech.get("version") or "—",
                        tech.get("confidence"),
                    )
                    for tech in http.technologies
                ],
                empty="no markers matched",
            )

    if outcome.urlscan is not None:
        urlscan = outcome.urlscan
        context.console.print(
            f"  urlscan       {urlscan.scans} scan(s), "
            f"{urlscan.hosts_in_scope} in-scope host(s), "
            f"{urlscan.hosts_out_of_scope} archived out-of-scope host(s)"
        )

    for skipped in outcome.skipped_collectors:
        info(context, f"skipped {skipped['collector']}: {skipped['reason']}")

    for error in outcome.errors:
        warn(context, f"{error.get('collector', 'collector')}: {error['message']}")

    if outcome.succeeded:
        success(context, f"job {outcome.job_id} succeeded")
    else:
        warn(context, f"job {outcome.job_id} finished {outcome.status}")


def _run(context: AppContext, target: str, job_type: JobType, scan_id: str | None = None) -> None:
    with context.session() as session:
        project = context.project(session)
        outcome = discover(
            session,
            project,
            context.settings,
            target,
            job_type=job_type,
            actor=context.actor,
            scan_id=scan_id,
        )

    _render(context, outcome)
    if outcome.succeeded or context.json_output:
        raise typer.Exit(EXIT_OK)
    raise typer.Exit(EXIT_ERROR)


def discover_command(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Domain, IP, CIDR or URL inside the scope.")],
    full: Annotated[
        bool,
        typer.Option("--full", help="Run every registered collector instead of DNS only."),
    ] = False,
) -> None:
    """Discover the infrastructure of an authorized target."""

    context: AppContext = ctx.obj
    _run(context, target, JobType.FULL if full else JobType.DISCOVER)


def collect_command(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Domain, IP, CIDR or URL inside the scope.")],
    job_type: Annotated[
        str,
        typer.Option(
            "--type",
            help="dns | certificates | http | urlscan | discover | full",
            case_sensitive=False,
        ),
    ] = "full",
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Check scope and print the plan without collecting.")
    ] = False,
    scan_id: Annotated[
        str | None,
        typer.Option("--scan-id", help="urlscan.io scan UUID (only with --type urlscan)."),
    ] = None,
) -> None:
    """Run a collection pass over an authorized target."""

    context: AppContext = ctx.obj
    resolved_type = _TYPE_CHOICES.get(job_type.lower())
    if resolved_type is None:
        raise ValidationError(
            f"unknown collection type: {job_type!r} ({' | '.join(sorted(set(_TYPE_CHOICES)))})"
        )
    if scan_id is not None and resolved_type is not JobType.URLSCAN:
        raise ValidationError("--scan-id is only valid with --type urlscan")

    if dry_run:
        from atlas.services.scopes import build_scope_set

        with context.session() as session:
            project = context.project(session)
            resolved = resolve_target(target)
            decision = build_scope_set(session, project, context.settings).check(
                resolved.collection_value
            )
        payload = {
            "target": resolved.normalized,
            "kind": resolved.kind.value,
            "collection_value": resolved.collection_value,
            "job_type": resolved_type.value,
            "permitted": decision.permitted,
            "reason": decision.reason,
        }
        emit(context, payload)
        if not context.json_output:
            info(context, f"{payload['reason']}")
        if not decision.permitted:
            raise typer.Exit(EXIT_ERROR)
        return

    _run(context, target, resolved_type, scan_id)
