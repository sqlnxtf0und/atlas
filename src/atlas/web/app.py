"""A locally hosted operator console for ATLAS.

The point is to make the first run legible: declare scope, launch a collection pass,
read what came back — without memorising a CLI. It is the same services the CLI calls,
with the same scope gate and the same persistence, exposed over loopback.

Three properties are deliberate and are not configuration options:

* **The scope gate is not bypassable here.** Every collection goes through
  :func:`atlas.services.discovery.discover`, which performs the check, audits the
  denial and refuses before a socket is opened. There is no "run anyway" path.
* **No write endpoint is unauthenticated beyond loopback.** The console has no login.
  That is acceptable exactly because it binds ``127.0.0.1``; binding a routable
  interface is an explicit act (``atlas serve --allow-remote``) that prints a warning.
* **Read views never invent data.** An empty project renders empty tables, not demo
  rows; a missing artifact is a 404 with the command that would produce it.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker
from starlette.responses import Response

from atlas import __version__
from atlas.config import Settings
from atlas.db.enums import AssetKind, JobType, ScopeKind
from atlas.db.models import (
    Asset, DnsRecord, Domain, Project, ScanJob, ScanResult,
    Target, Snapshot, SnapshotAsset, AssetChange, Relationship, Finding, Evidence,
    ScopeRule, AuditEvent,
)
from atlas.db.session import build_engine, build_session_factory, session_scope
from atlas.errors import (
    AtlasError,
    ConfigurationError,
    NotFoundError,
    ScopeViolation,
    ValidationError,
)
from atlas.services.assets import asset_detail, asset_summary, get_asset, list_assets
from atlas.services.audit import list_events
from atlas.services.certificates import (
    certificate_detail,
    certificates_list,
    expiring_certificates,
)
from atlas.services.discovery import discover, job_summary, recent_jobs
from atlas.services.dns import dangling_cnames, dns_history, dns_records, nameserver_summary
from atlas.services.http import http_services, http_snapshot, http_snapshots
from atlas.services.projects import get_project, list_projects, project_stats
from atlas.services.scopes import (
    add_rule,
    build_scope_set,
    list_rules,
    remove_rules,
    summarize,
)
from atlas.services.targets import resolve_target
from atlas.services.urlscan import ingest_urlscan_scan, urlscan_scans

__all__ = ["JOB_TYPES", "STATIC_DIR", "build_api", "create_app"]

STATIC_DIR = Path(__file__).resolve().parent / "static"

#: Human labels for the collection types the console offers.
JOB_TYPES: dict[str, str] = {
    JobType.DISCOVER.value: "DNS only",
    JobType.DNS.value: "DNS only (explicit)",
    JobType.CERTIFICATES.value: "TLS certificates",
    JobType.HTTP.value: "HTTP observation",
    JobType.URLSCAN.value: "urlscan.io scan",
    JobType.FULL.value: "Full pass (DNS + TLS + HTTP + sources)",
}

#: How many rows a read endpoint returns when the caller does not say.
_DEFAULT_LIMIT = 200

_ERROR_STATUS: dict[str, int] = {
    "validation_error": 400,
    "scope_violation": 403,
    "authorization_error": 403,
    "not_found": 404,
    "conflict": 409,
    "configuration_error": 500,
    "database_error": 503,
    "cancelled": 409,
}


@dataclass(slots=True)
class Database:
    """The process-wide engine behind the console, owned by the app lifespan."""

    settings: Settings
    engine: Engine
    factory: sessionmaker[Session]

    @classmethod
    def build(cls, settings: Settings) -> Database:
        engine = build_engine(settings)
        return cls(settings=settings, engine=engine, factory=build_session_factory(engine))

    def session(self) -> Any:
        return session_scope(self.factory)

    def close(self) -> None:
        self.engine.dispose()


def _error_response(exc: AtlasError) -> JSONResponse:
    """Render an ATLAS error as JSON with the HTTP status that matches its slug."""

    return JSONResponse(exc.as_dict(), status_code=_ERROR_STATUS.get(exc.slug, 500))


def _iso(value: Any) -> str | None:
    from atlas.core.time import isoformat

    return isoformat(value) if value is not None else None


def _positive(value: int, *, ceiling: int = 10_000) -> int:
    return max(1, min(int(value), ceiling))


@dataclass(frozen=True, slots=True)
class RecordRow:
    """One DNS record, flattened for the console's JSON."""

    record_type: str
    value: str
    ttl: int | None
    priority: int | None
    is_active: bool
    first_seen: str | None
    last_seen: str | None
    source: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
            "priority": self.priority,
            "is_active": self.is_active,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source": self.source,
        }


def _record_rows(records: list[DnsRecord]) -> list[dict[str, Any]]:
    return [
        RecordRow(
            record_type=record.record_type.value,
            value=record.value,
            ttl=record.ttl,
            priority=record.priority,
            is_active=record.is_active,
            first_seen=_iso(record.first_seen),
            last_seen=_iso(record.last_seen),
            source=record.source,
        ).as_dict()
        for record in records
    ]


def _do_purge(session: Session, pid: Any) -> None:
    """Delete everything for a project except the project row itself.

    Order respects FK constraints — children before parents.
    Assets cascade to domains, asns, ip_addresses, certificates,
    certificate_bindings, services, dns_records automatically.
    """
    session.query(ScanResult).filter(ScanResult.project_id == pid).delete(synchronize_session=False)
    session.query(ScanJob).filter(ScanJob.project_id == pid).delete(synchronize_session=False)
    snap_ids = [r[0] for r in session.query(Snapshot.id).filter(Snapshot.project_id == pid).all()]
    if snap_ids:
        session.query(SnapshotAsset).filter(SnapshotAsset.snapshot_id.in_(snap_ids)).delete(synchronize_session=False)
    session.query(Snapshot).filter(Snapshot.project_id == pid).delete(synchronize_session=False)
    session.query(AssetChange).filter(AssetChange.project_id == pid).delete(synchronize_session=False)
    session.query(Evidence).filter(Evidence.project_id == pid).delete(synchronize_session=False)
    session.query(Finding).filter(Finding.project_id == pid).delete(synchronize_session=False)
    session.query(Relationship).filter(Relationship.project_id == pid).delete(synchronize_session=False)
    session.query(Asset).filter(Asset.project_id == pid).delete(synchronize_session=False)
    session.query(Target).filter(Target.project_id == pid).delete(synchronize_session=False)
    session.query(ScopeRule).filter(ScopeRule.project_id == pid).delete(synchronize_session=False)
    session.query(AuditEvent).filter(AuditEvent.project_id == pid).delete(synchronize_session=False)
    session.commit()


def create_app(settings: Settings, *, project_slug: str = "default") -> FastAPI:
    """Build the console app. Callers own the lifecycle (uvicorn does in production)."""

    database = Database.build(settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # The engine is built eagerly and the project is resolved once, so a typo in
        # ``--project`` or an unmigrated database fails at boot with a message, not on
        # the first page load with an empty screen.
        with database.session() as session:
            known = [slug for (slug,) in session.execute(select(Project.slug)).all()]
            if project_slug not in known:
                raise ConfigurationError(
                    f"project not found: {project_slug}",
                    context={"slug": project_slug, "projects": known},
                )
        yield
        database.close()

    app = FastAPI(
        title="ATLAS local console",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        redoc_url=None,
    )

    def active_project(session: Session) -> Any:
        return get_project(session, project_slug)

    # ------------------------------------------------------------------ #
    # Shell                                                               #
    # ------------------------------------------------------------------ #

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index() -> Response:
        page = STATIC_DIR / "index.html"
        if not page.is_file():  # pragma: no cover - packaging error
            return HTMLResponse("<h1>console assets missing</h1>", status_code=500)
        return HTMLResponse(page.read_text(encoding="utf-8"))

    if STATIC_DIR.is_dir():  # pragma: no cover - always true in a built package
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # ------------------------------------------------------------------ #
    # State                                                               #
    # ------------------------------------------------------------------ #

    @app.get("/api/state")
    def state() -> dict[str, Any]:
        with database.session() as session:
            project = active_project(session)
            rules = [summarize(rule) for rule in list_rules(session, project)]
            sources = settings.sources
            return {
                "version": __version__,
                "project": {
                    "slug": project.slug,
                    "name": project.name,
                    "description": project.description,
                },
                "counts": project_stats(session, project),
                "scope": rules,
                "scope_configured": any(
                    rule["mode"] == "include" and rule["is_active"] for rule in rules
                ),
                "collectors": [
                    {"name": "dns", "label": "DNS", "ready": True, "reason": None},
                    {"name": "tls", "label": "TLS certificates", "ready": True, "reason": None},
                    {"name": "http", "label": "HTTP", "ready": True, "reason": None},
                    {
                        "name": "urlscan",
                        "label": "urlscan.io",
                        "ready": sources.urlscan_enabled,
                        "reason": None
                        if sources.urlscan_enabled
                        else "needs sources.urlscan_api_key",
                    },
                ],
                "job_types": [{"value": key, "label": label} for key, label in JOB_TYPES.items()],
                "projects": [
                    {"slug": entry.slug, "name": entry.name, "active": entry.slug == project_slug}
                    for entry in list_projects(session)
                ],
                "cli": f"atlas --project {project_slug}",
                "settings": {
                    # The URL may embed a password; only the backend is shown.
                    "database_backend": settings.database.url.split(":", 1)[0],
                    "allow_private_addresses": settings.security.allow_private_addresses,
                    "requests_per_second": settings.collector.requests_per_second,
                    "job_deadline_seconds": settings.collector.job_deadline_seconds,
                    "max_body_bytes": settings.collector.max_body_bytes,
                },
            }

    # ------------------------------------------------------------------ #
    # Projects                                                            #
    # ------------------------------------------------------------------ #

    @app.get("/api/projects")
    def projects() -> dict[str, Any]:
        """Every project in the database, with the one this console serves marked."""

        with database.session() as session:
            return {
                "active": project_slug,
                "projects": [
                    {
                        "slug": entry.slug,
                        "name": entry.name,
                        "description": entry.description,
                        "retention_days": entry.retention_days,
                        "active": entry.slug == project_slug,
                    }
                    for entry in list_projects(session)
                ],
            }

    # ------------------------------------------------------------------ #
    # Scope                                                               #
    # ------------------------------------------------------------------ #

    @app.get("/api/scope")
    def scope_list() -> dict[str, Any]:
        with database.session() as session:
            project = active_project(session)
            return {"scope": [summarize(rule) for rule in list_rules(session, project)]}

    @app.post("/api/scope")
    async def scope_add(request: Request) -> Any:
        body = await request.json()
        pattern = str(body.get("pattern") or "").strip()
        if not pattern:
            raise HTTPException(status_code=400, detail="pattern is required")
        kind_raw = body.get("kind")
        try:
            kind = ScopeKind(str(kind_raw)) if kind_raw else None
        except ValueError:
            raise HTTPException(status_code=400, detail=f"unknown scope kind: {kind_raw}") from None
        try:
            with database.session() as session:
                project = active_project(session)
                rule = add_rule(
                    session,
                    project,
                    pattern=pattern,
                    kind=kind,
                    include_subdomains=bool(body.get("include_subdomains", True)),
                    note=str(body["note"]) if body.get("note") else None,
                    actor="console",
                )
                return {"rule": summarize(rule)}
        except AtlasError as exc:
            return _error_response(exc)

    @app.delete("/api/scope/{rule_id}")
    def scope_remove(rule_id: str) -> Any:
        try:
            rule_uuid = uuid.UUID(rule_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="rule id must be a UUID") from None
        try:
            with database.session() as session:
                project = active_project(session)
                match = next(
                    (
                        rule
                        for rule in list_rules(session, project, include_inactive=True)
                        if rule.id == rule_uuid
                    ),
                    None,
                )
                if match is None:
                    raise NotFoundError(f"no scope rule with id {rule_id}", context={"id": rule_id})
                remove_rules(session, project, pattern=match.pattern, kind=match.kind)
        except AtlasError as exc:
            return _error_response(exc)
        return {"removed": rule_id}

    @app.get("/api/scope/check")
    def scope_check(value: str) -> Any:
        """Evaluate a value without collecting, using the matcher the gate uses."""

        try:
            resolved = resolve_target(value)
        except AtlasError as exc:
            return _error_response(exc)
        with database.session() as session:
            project = active_project(session)
            decision = build_scope_set(session, project, settings).check(resolved.collection_value)
        return {
            "value": resolved.normalized,
            "kind": resolved.kind.value,
            "collection_value": resolved.collection_value,
            "permitted": decision.permitted,
            "reason": decision.reason,
        }

    # ------------------------------------------------------------------ #
    # Collection                                                          #
    # ------------------------------------------------------------------ #

    @app.post("/api/collect")
    async def collect(request: Request) -> Any:
        body = await request.json()
        target = str(body.get("target") or "").strip()
        if not target:
            raise HTTPException(status_code=400, detail="target is required")
        job_type_raw = str(body.get("job_type") or JobType.FULL.value)
        try:
            job_type = JobType(job_type_raw)
        except ValueError:
            raise HTTPException(
                status_code=400, detail=f"unknown job type: {job_type_raw}"
            ) from None
        scan_id = str(body["scan_id"]) if body.get("scan_id") else None

        try:
            with database.session() as session:
                outcome = discover(
                    session,
                    active_project(session),
                    settings,
                    target,
                    job_type=job_type,
                    actor="console",
                    scan_id=scan_id,
                )
                return outcome.as_dict()
        except ScopeViolation as exc:
            return _error_response(exc)
        except AtlasError as exc:
            return _error_response(exc)

    @app.post("/api/urlscan")
    async def urlscan_ingest(request: Request) -> Any:
        body = await request.json()
        scan_id = str(body.get("scan_id") or "").strip()
        if not scan_id:
            raise HTTPException(status_code=400, detail="scan_id is required")
        try:
            with database.session() as session:
                ingestion = ingest_urlscan_scan(
                    session, active_project(session), settings, scan_id, actor="console"
                )
                return ingestion.as_dict()
        except AtlasError as exc:
            return _error_response(exc)

    # ------------------------------------------------------------------ #
    # Read views                                                          #
    # ------------------------------------------------------------------ #

    @app.get("/api/assets")
    def assets(
        kind: str | None = None, search: str | None = None, limit: int = _DEFAULT_LIMIT
    ) -> dict[str, Any]:
        asset_kind = None
        if kind:
            try:
                asset_kind = AssetKind(kind)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"unknown asset kind: {kind}") from None
        with database.session() as session:
            rows = list_assets(
                session,
                active_project(session),
                kind=asset_kind,
                search=search,
                limit=_positive(limit),
            )
            return {"assets": [asset_summary(asset) for asset in rows]}

    @app.get("/api/assets/{key:path}")
    def asset(key: str) -> Any:
        try:
            with database.session() as session:
                project = active_project(session)
                return asset_detail(session, get_asset(session, project, key))
        except AtlasError as exc:
            return _error_response(exc)

    @app.get("/api/dns")
    def dns_index() -> dict[str, Any]:
        """Every collected name, so the console can offer a picker instead of a blank box."""

        with database.session() as session:
            project = active_project(session)
            rows = session.execute(
                select(Domain.fqdn, Asset.is_active)
                .join(Asset, Asset.id == Domain.asset_id)
                .where(Domain.project_id == project.id)
                .order_by(Domain.fqdn)
            ).all()
            return {"names": [{"fqdn": fqdn, "active": bool(active)} for fqdn, active in rows]}

    @app.get("/api/dns-dangling")
    def dns_dangling() -> dict[str, Any]:
        with database.session() as session:
            return {"dangling": dangling_cnames(session, active_project(session))}

    @app.get("/api/dns/{fqdn:path}")
    def dns(fqdn: str) -> Any:
        """One name's records, history and nameservers.

        ``dns_history`` raises a validation error for a name that was never
        collected; from an HTTP reader's point of view that is a missing resource, so
        it is translated here rather than reported as a malformed request.
        """

        try:
            with database.session() as session:
                project = active_project(session)
                records = dns_records(session, project, fqdn, active_only=False)
                if not records:
                    raise NotFoundError(
                        f"no DNS records for {fqdn}: run atlas collect {fqdn} --type dns",
                        context={"fqdn": fqdn},
                    )
                history = dns_history(session, project, fqdn)
                return {
                    "fqdn": fqdn,
                    "records": _record_rows(records),
                    "history": history,
                    "nameservers": nameserver_summary(session, project, fqdn),
                }
        except AtlasError as exc:
            return _error_response(exc)

    @app.get("/api/certs")
    def certs(days: int | None = None, limit: int = _DEFAULT_LIMIT) -> dict[str, Any]:
        with database.session() as session:
            project = active_project(session)
            rows = (
                expiring_certificates(session, project, days=days, limit=_positive(limit))
                if days is not None
                else certificates_list(session, project, limit=_positive(limit))
            )
            return {"certificates": rows, "window_days": days}

    @app.get("/api/certs/{fingerprint}")
    def cert(fingerprint: str) -> Any:
        try:
            with database.session() as session:
                return certificate_detail(session, active_project(session), fingerprint)
        except AtlasError as exc:
            return _error_response(exc)

    @app.get("/api/http")
    def http_index(limit: int = 100) -> dict[str, Any]:
        with database.session() as session:
            return {
                "observations": http_snapshots(
                    session, active_project(session), limit=_positive(limit)
                )
            }

    @app.get("/api/http/{host:path}")
    def http_host(host: str) -> Any:
        """The latest observation for one host. A host never fetched is a 404."""

        try:
            with database.session() as session:
                project = active_project(session)
                snapshot = http_snapshot(session, project, host)
                return {
                    "http": snapshot,
                    "services": http_services(session, project, host=host),
                }
        except ValidationError as exc:
            return _error_response(NotFoundError(exc.message, context={"host": host}))
        except AtlasError as exc:
            return _error_response(exc)

    @app.get("/api/jobs")
    def jobs(limit: int = 25) -> dict[str, Any]:
        with database.session() as session:
            rows = recent_jobs(session, active_project(session), limit=_positive(limit))
            return {"jobs": [job_summary(job) for job in rows]}

    @app.delete("/api/jobs")
    def jobs_clear() -> dict[str, Any]:
        """Delete all scan_jobs (and their results via cascade) for this project."""
        with database.session() as session:
            project = active_project(session)
            deleted = (
                session.query(ScanJob)
                .filter(ScanJob.project_id == project.id)
                .delete(synchronize_session=False)
            )
            session.commit()
            return {"deleted": deleted}

    @app.post("/api/jobs-clear-beacon")
    def jobs_clear_beacon() -> dict[str, Any]:
        """POST-only alias used by navigator.sendBeacon on page unload."""
        with database.session() as session:
            project = active_project(session)
            deleted = (
                session.query(ScanJob)
                .filter(ScanJob.project_id == project.id)
                .delete(synchronize_session=False)
            )
            session.commit()
            return {"deleted": deleted}

    @app.delete("/api/purge")
    def purge_collected() -> dict[str, Any]:
        """Wipe everything for this project except the project row itself."""
        with database.session() as session:
            pid = active_project(session).id
            _do_purge(session, pid)
            return {"purged": True}

    @app.post("/api/purge-beacon")
    def purge_beacon() -> dict[str, Any]:
        """POST alias for navigator.sendBeacon on page unload."""
        with database.session() as session:
            pid = active_project(session).id
            _do_purge(session, pid)
            return {"purged": True}

    @app.get("/api/audit")
    def audit(limit: int = 100, action: str | None = None) -> dict[str, Any]:
        with database.session() as session:
            project = active_project(session)
            rows = list_events(
                session, project_id=project.id, action=action, limit=_positive(limit)
            )
            return {
                "events": [
                    {
                        "id": str(event.id),
                        "action": event.action,
                        "outcome": event.outcome,
                        "actor": event.actor,
                        "object_type": event.object_type,
                        "object_id": event.object_id,
                        "detail": dict(event.detail or {}),
                        "created_at": _iso(event.created_at),
                    }
                    for event in rows
                ]
            }

    @app.get("/api/urlscan")
    def urlscan_index(limit: int = 25) -> dict[str, Any]:
        with database.session() as session:
            return {
                "scans": urlscan_scans(session, active_project(session), limit=_positive(limit))
            }

    @app.get("/api/export")
    def export() -> Any:
        """Everything this project holds, as one JSON document.

        Omitted on purpose: nothing outside the project, no settings, no secrets.
        Untruncated on purpose: this is the backup/handoff path, so the ceiling is
        high and raising the limit is the operator's decision.
        """

        with database.session() as session:
            project = active_project(session)
            return {
                "project": {"slug": project.slug, "name": project.name},
                "exported_version": __version__,
                "assets": [
                    asset_summary(asset) for asset in list_assets(session, project, limit=100_000)
                ],
                "certificates": certificates_list(session, project, limit=100_000),
                "http": http_snapshots(session, project, limit=100_000),
                "jobs": [job_summary(job) for job in recent_jobs(session, project, limit=5_000)],
                "scope": [summarize(rule) for rule in list_rules(session, project)],
            }

    return app


def build_api(settings: Settings, *, project_slug: str = "default") -> FastAPI:
    """Alias used by tests and by any embedding caller."""

    return create_app(settings, project_slug=project_slug)
