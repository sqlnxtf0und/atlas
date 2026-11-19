"""urlscan.io persistence.

The urlscan collector is a *third-party* observer, so persistence is deliberately
conservative:

* Only hosts the collector marked ``in_scope`` become assets. Everything else is
  archived as provenance and left alone — a scan result is not a licence to widen
  the attack surface ATLAS is allowed to track.
* Confidences are lower than ATLAS's own observations (a scan happened at some
  point in the past, on someone else's network) and the evidence source says so.
* ``UrlscanCertificateObservation`` carries no fingerprint, so it never creates a
  ``Certificate`` row. Certificate names from urlscan are kept as observations,
  not promoted into the certificate graph.
* urlscan's verdict score is never copied into a finding. It is a third-party
  opinion and is recorded as such.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.collect.base import (
    CollectionTarget,
    CollectorResult,
    UrlscanCertificateObservation,
    UrlscanHostObservation,
    UrlscanRequestObservation,
    UrlscanScanObservation,
)
from atlas.core.time import utcnow
from atlas.db.enums import AssetKind, JobStatus, JobType, RelationshipType, ServiceState, TargetKind
from atlas.db.models import Asset, Domain, Project, ScanJob, ScanResult
from atlas.errors import ConfigurationError, ScopeViolation
from atlas.scope.normalize import normalize_domain, split_hostname
from atlas.services.observations import ensure_domain, ensure_ip_address, upsert_service
from atlas.services.relationships import upsert_relationship

__all__ = [
    "UrlscanIngest",
    "UrlscanOutcome",
    "ingest_urlscan_scan",
    "persist_urlscan_result",
    "urlscan_scan",
    "urlscan_scans",
]

#: A third-party observation of a host existing. Lower than a direct ATLAS hit.
_HOST_CONFIDENCE = 0.7
#: A page→address mapping read from a third-party capture.
_RESOLVES_CONFIDENCE = 0.6
#: Parent/child domain structure is reliable even from a third-party capture.
_SUBDOMAIN_CONFIDENCE = 0.9


@dataclass(slots=True)
class UrlscanOutcome:
    """What one urlscan persistence pass produced."""

    scan_id: str = ""
    page_url: str = ""
    page_domain: str = ""
    scans: int = 0
    hosts_in_scope: int = 0
    hosts_out_of_scope: int = 0
    assets: int = 0
    services: int = 0
    relationships: int = 0
    certificate_names: int = 0
    requests: int = 0
    verdict_score: int | None = None
    verdict_malicious: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "page_url": self.page_url,
            "page_domain": self.page_domain,
            "scans": self.scans,
            "hosts_in_scope": self.hosts_in_scope,
            "hosts_out_of_scope": self.hosts_out_of_scope,
            "assets": self.assets,
            "services": self.services,
            "relationships": self.relationships,
            "certificate_names": self.certificate_names,
            "requests": self.requests,
            "verdict_score": self.verdict_score,
            "verdict_malicious": self.verdict_malicious,
        }


def persist_urlscan_result(
    session: Session,
    project: Project,
    result: CollectorResult,
    *,
    scan_job_id: uuid.UUID | None = None,
    link_relationships: bool = True,
) -> UrlscanOutcome | None:
    """Write a urlscan.io result: in-scope hosts become assets; the rest is evidence."""

    scans = tuple(
        observation
        for observation in result.observations
        if isinstance(observation, UrlscanScanObservation)
    )
    hosts = tuple(
        observation
        for observation in result.observations
        if isinstance(observation, UrlscanHostObservation)
    )
    requests = tuple(
        observation
        for observation in result.observations
        if isinstance(observation, UrlscanRequestObservation)
    )
    certificates = tuple(
        observation
        for observation in result.observations
        if isinstance(observation, UrlscanCertificateObservation)
    )
    if not scans and not hosts and not requests:
        return None

    outcome = UrlscanOutcome(
        scans=len(scans),
        requests=len(requests),
        certificate_names=len(certificates),
    )
    if scans:
        scan = scans[0]
        outcome.scan_id = scan.scan_id
        outcome.page_url = scan.page_url
        outcome.page_domain = scan.page_domain
        outcome.verdict_score = scan.verdict_score
        outcome.verdict_malicious = scan.verdict_malicious

    page_asset: Asset | None = None
    page_ip = ""
    if scans:
        page_ip = scans[0].page_ip or ""
    if outcome.page_domain and scans and scans[0].page_in_scope:
        domain = ensure_domain(
            session,
            project,
            normalize_domain(outcome.page_domain),
            source=result.collector,
            observed_at=scans[0].observed_at,
            scan_job_id=scan_job_id,
        )
        page_asset = session.get(Asset, domain.asset_id)
        outcome.assets += 1

    for observation in hosts:
        if not observation.in_scope:
            outcome.hosts_out_of_scope += 1
            continue
        outcome.hosts_in_scope += 1
        asset = _ensure_host(session, project, observation, result, scan_job_id)
        if asset is None:
            continue
        outcome.assets += 1
        if link_relationships:
            outcome.relationships += _link_subdomain(session, project, asset, observation)

    if link_relationships and page_asset is not None and page_ip:
        outcome.relationships += _link_page_address(session, project, page_asset, page_ip, result)

    for request in requests:
        if not request.in_scope:
            continue
        service_asset = session.scalar(
            select(Asset).where(
                Asset.project_id == project.id,
                Asset.key == request.host,
                Asset.kind.in_([AssetKind.DOMAIN, AssetKind.IP_ADDRESS]),
            )
        )
        if service_asset is None:
            continue
        scheme = request.scheme.lower()
        port = request.port or (443 if scheme == "https" else 80)
        _service, created = upsert_service(
            session,
            project,
            service_asset,
            port=port,
            transport="tcp",
            protocol=scheme or None,
            state=ServiceState.OPEN,
            tls_enabled=scheme == "https",
            tls_version=request.tls_protocol,
            banner=request.server,
            source=result.collector,
            observed_at=request.observed_at,
        )
        if created:
            outcome.services += 1

    return outcome


def _ensure_host(
    session: Session,
    project: Project,
    observation: UrlscanHostObservation,
    result: CollectorResult,
    scan_job_id: uuid.UUID | None,
) -> Asset | None:
    if observation.kind == "ip":
        try:
            address = ensure_ip_address(
                session,
                project,
                observation.host,
                source=result.collector,
                observed_at=observation.observed_at,
                scan_job_id=scan_job_id,
            )
        except ValueError:  # pragma: no cover - the collector validated the shape
            return None
        return session.get(Asset, address.asset_id)

    try:
        domain = ensure_domain(
            session,
            project,
            normalize_domain(observation.host),
            source=result.collector,
            observed_at=observation.observed_at,
            scan_job_id=scan_job_id,
        )
    except Exception:
        return None
    return session.get(Asset, domain.asset_id)


def _link_subdomain(
    session: Session,
    project: Project,
    asset: Asset,
    observation: UrlscanHostObservation,
) -> int:
    if observation.kind != "domain":
        return 0
    subdomain, registrable = split_hostname(observation.host)
    if not subdomain:
        return 0
    parent = session.scalar(
        select(Domain).where(Domain.project_id == project.id, Domain.fqdn == registrable)
    )
    if parent is None:
        return 0
    parent_asset = session.get(Asset, parent.asset_id)
    if parent_asset is None or parent_asset.id == asset.id:  # pragma: no cover - defensive
        return 0
    upsert_relationship(
        session,
        project,
        source=asset,
        target=parent_asset,
        rel_type=RelationshipType.SUBDOMAIN_OF,
        evidence_source="urlscan",
        confidence=_SUBDOMAIN_CONFIDENCE,
        observed_at=observation.observed_at,
        attributes={"note": "parent/child structure read from a third-party capture"},
    )
    return 1


def _link_page_address(
    session: Session,
    project: Project,
    page_asset: Asset,
    page_ip: str,
    result: CollectorResult,
) -> int:
    try:
        ipaddress.ip_address(page_ip)
    except ValueError:
        return 0
    address = ensure_ip_address(
        session,
        project,
        page_ip,
        source=result.collector,
        observed_at=result.started_at,
    )
    ip_asset = session.get(Asset, address.asset_id)
    if ip_asset is None or ip_asset.id == page_asset.id:
        return 0
    upsert_relationship(
        session,
        project,
        source=page_asset,
        target=ip_asset,
        rel_type=RelationshipType.RESOLVES_TO,
        evidence_source="urlscan",
        confidence=_RESOLVES_CONFIDENCE,
        observed_at=result.started_at,
        attributes={"note": "address read from a third-party capture, not an ATLAS lookup"},
    )
    return 1


# --------------------------------------------------------------------------- #
# Explicit scan ingestion (``atlas sources urlscan <scan-id>``)                #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class UrlscanIngest:
    """The job plus the outcome of one explicitly requested scan ingestion."""

    job_id: str
    status: str
    outcome: UrlscanOutcome
    errors: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "urlscan": self.outcome.as_dict(),
            "errors": list(self.errors),
        }


def ingest_urlscan_scan(
    session: Session,
    project: Project,
    settings: Any,
    scan_id: str,
    *,
    actor: str = "cli",
) -> UrlscanIngest:
    """Read one urlscan.io scan and persist it, with the scope gate applied.

    A scan id is not an authorization. The collector refuses a scan whose captured
    page domain is outside the project's scope, and that refusal is raised — not
    softened into a partial result.
    """

    from atlas.collect.registry import CollectorRegistry
    from atlas.collect.runtime import build_context
    from atlas.collect.urlscan import UrlscanCollector, normalize_scan_id
    from atlas.services.audit import record_event
    from atlas.services.discovery import record_scan_results
    from atlas.services.scopes import build_scope_set

    normalized = normalize_scan_id(scan_id)
    # Fail before a job row exists: a missing API key is a configuration gap, not a
    # scan that ran and found nothing.
    available, reason = UrlscanCollector(settings=settings).available(settings)
    if not available:
        raise ConfigurationError(reason, context={"source": "urlscan", "scan_id": normalized})
    scope = build_scope_set(session, project, settings)

    job = ScanJob(
        project_id=project.id,
        job_type=JobType.URLSCAN,
        status=JobStatus.RUNNING,
        params={"scan_id": normalized},
        requested_by=actor,
        started_at=utcnow(),
    )
    session.add(job)
    session.flush()
    # The job row outlives a crash; commit before any remote call is made.
    session.commit()

    registry = CollectorRegistry()
    registry.register(
        UrlscanCollector.name,
        lambda settings: UrlscanCollector(settings=settings, scan_id=normalized),
        job_type=JobType.URLSCAN,
    )
    collector = registry.create(UrlscanCollector.name, settings)
    context = build_context(settings, scope, job_id=job.id, actor=actor)
    target = CollectionTarget(kind=TargetKind.DOMAIN, value=normalized, display=normalized)
    # A scan is authorized by the page it captured, not by the id. When no rule
    # covers that page the collector raises ``ScopeViolation`` mid-read, so the
    # gate runs first and the job is closed out with the refusal recorded.
    try:
        result = collector.collect(target, context)
    except ScopeViolation as exc:
        job.status = JobStatus.FAILED
        job.finished_at = utcnow()
        job.error = exc.message[:4000]
        record_event(
            session,
            action="urlscan.ingest",
            project_id=project.id,
            actor=actor,
            object_type="scan_job",
            object_id=str(job.id),
            outcome="denied",
            detail={"scan_id": normalized, "reason": exc.message},
        )
        session.commit()
        raise

    errors: list[dict[str, Any]] = []
    result = collector.collect(target, context)
    errors.extend(error.as_dict() for error in result.errors)
    record_scan_results(session, project, job, result)
    outcome = persist_urlscan_result(session, project, result, scan_job_id=job.id)
    if outcome is None:
        outcome = UrlscanOutcome()

    if outcome.scans:
        status = JobStatus.PARTIAL if result.errors else JobStatus.SUCCEEDED
    else:
        status = JobStatus.FAILED

    job.status = status
    job.finished_at = utcnow()
    job.stats = {
        "scans": outcome.scans,
        "hosts_in_scope": outcome.hosts_in_scope,
        "hosts_out_of_scope": outcome.hosts_out_of_scope,
        "requests": outcome.requests,
        "relationships": outcome.relationships,
    }
    job.error = (
        "\n".join(f"{error.operation}: {error.error_type}" for error in result.errors)[:4000]
        or None
    )
    record_event(
        session,
        action="urlscan.ingest",
        project_id=project.id,
        actor=actor,
        object_type="scan_job",
        object_id=str(job.id),
        outcome="success" if status is JobStatus.SUCCEEDED else status.value,
        detail={"scan_id": normalized, "page_domain": outcome.page_domain},
    )
    session.commit()

    return UrlscanIngest(job_id=str(job.id), status=status.value, outcome=outcome, errors=errors)


# --------------------------------------------------------------------------- #
# Queries used by the CLI and API                                              #
# --------------------------------------------------------------------------- #


def urlscan_scans(session: Session, project: Project, *, limit: int = 50) -> list[dict[str, Any]]:
    """Archived urlscan scans, newest first."""

    rows = session.scalars(
        select(ScanResult)
        .where(
            ScanResult.project_id == project.id,
            ScanResult.result_type == "urlscan.scan",
        )
        .order_by(ScanResult.observed_at.desc())
        .limit(max(1, limit))
    )
    return [dict(row.payload or {}) for row in rows]


def urlscan_scan(session: Session, project: Project, scan_id: str) -> dict[str, Any]:
    """One archived scan by id, with its hosts and requests."""

    from atlas.errors import NotFoundError

    scan: dict[str, Any] | None = None
    for payload in urlscan_scans(session, project, limit=5000):
        if str(payload.get("scan_id")) == scan_id:
            scan = payload
            break
    if scan is None:
        raise NotFoundError(
            f"no urlscan result recorded for {scan_id}",
            context={"scan_id": scan_id},
        )

    hosts: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    rows = session.scalars(
        select(ScanResult)
        .where(
            ScanResult.project_id == project.id,
            ScanResult.result_type.in_(["urlscan.host", "urlscan.request"]),
        )
        .order_by(ScanResult.observed_at.desc())
        .limit(20_000)
    )
    for row in rows:
        payload = dict(row.payload or {})
        if row.result_type == "urlscan.host":
            hosts.append(payload)
        else:
            requests.append(payload)

    return {
        "scan_id": scan.get("scan_id"),
        "page_url": scan.get("page_url"),
        "page_domain": scan.get("page_domain"),
        "scanned_at": scan.get("scanned_at"),
        "observed_at": scan.get("observed_at"),
        "verdict_score": scan.get("verdict_score"),
        "verdict_malicious": scan.get("verdict_malicious"),
        "verdict_note": ("verdict values are urlscan.io's opinion, archived as provenance only"),
        "hosts": hosts,
        "requests": requests,
    }
