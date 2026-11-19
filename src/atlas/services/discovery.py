"""Discovery orchestration — the pipeline the CLI and the task queue both drive.

    target → scope gate → scan job → collectors → persistence → scan results → job finalize

Three properties this module is responsible for:

* **The scope gate runs first and runs again.** The value is checked before a job
  row exists, and every collector re-checks at its own boundary.
* **The job row outlives a crash.** It is committed before collection starts, so a
  failed run leaves an auditable record instead of vanishing.
* **Raw observations are archived.** Every observation is written as a
  ``ScanResult`` with its own timestamp and source, so any later finding can be
  traced back to what was actually seen.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from atlas.collect import CollectionTarget, CollectorResult, Observation, default_registry
from atlas.collect.registry import CollectorRegistry
from atlas.collect.runtime import build_context
from atlas.config import Settings
from atlas.core.time import isoformat, utcnow
from atlas.db.enums import JobStatus, JobType, TargetKind
from atlas.db.models import Project, ScanJob, ScanResult, Target
from atlas.errors import ScopeViolation, ValidationError
from atlas.logging import get_logger
from atlas.services.audit import record_event
from atlas.services.certificates import CertOutcome, persist_certificate_result
from atlas.services.dns import DnsOutcome, persist_dns_result
from atlas.services.http import HttpOutcome, persist_http_result
from atlas.services.scopes import build_scope_set
from atlas.services.targets import ResolvedTarget, resolve_target, upsert_target
from atlas.services.urlscan import UrlscanOutcome, persist_urlscan_result

__all__ = ["DiscoveryOutcome", "discover", "record_scan_results"]

log = get_logger("services.discovery")

_RESULT_TYPE_BY_CLASS: dict[str, str] = {
    "CertificateObservation": "tls.certificate",
    "CookieObservation": "http.cookie",
    "DnsAnswerObservation": "dns.answer",
    "HttpObservation": "http.response",
    "NameStatusObservation": "dns.status",
    "TechnologyObservation": "http.technology",
    "UrlscanCertificateObservation": "urlscan.certificate",
    "UrlscanHostObservation": "urlscan.host",
    "UrlscanRequestObservation": "urlscan.request",
    "UrlscanScanObservation": "urlscan.scan",
}

#: Collector name → the persistence hook that owns its observations. Certificates,
#: HTTP and urlscan each have a dedicated service; DNS keeps its diff semantics.
_PERSISTERS = {
    "dns": "dns",
    "tls": "certificates",
    "http": "http",
    "urlscan": "urlscan",
}


@dataclass(slots=True)
class DiscoveryOutcome:
    """Everything one discovery run produced, ready for rendering."""

    job_id: str
    target: str
    target_kind: str
    job_type: str
    status: str
    collectors: list[CollectorResult] = field(default_factory=list)
    dns: DnsOutcome | None = None
    certs: CertOutcome | None = None
    http: HttpOutcome | None = None
    urlscan: UrlscanOutcome | None = None
    scan_results: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    scope_reason: str = ""
    skipped_collectors: list[dict[str, str]] = field(default_factory=list)

    @property
    def observations(self) -> int:
        return sum(len(result.observations) for result in self.collectors)

    @property
    def succeeded(self) -> bool:
        return self.status == JobStatus.SUCCEEDED.value

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "job_id": self.job_id,
            "target": self.target,
            "target_kind": self.target_kind,
            "job_type": self.job_type,
            "status": self.status,
            "observations": self.observations,
            "scan_results": self.scan_results,
            "collectors": [result.summary() for result in self.collectors],
            "errors": self.errors,
            "scope_reason": self.scope_reason,
            "skipped_collectors": self.skipped_collectors,
        }
        if self.dns is not None:
            payload["dns"] = self.dns.as_dict()
        if self.certs is not None:
            payload["certs"] = self.certs.as_dict()
        if self.http is not None:
            payload["http"] = self.http.as_dict()
        if self.urlscan is not None:
            payload["urlscan"] = self.urlscan.as_dict()
        return payload


def _collectors_for(
    job_type: JobType, registry: CollectorRegistry, settings: Settings
) -> list[Any]:
    if job_type is JobType.FULL:
        return [registry.create(name, settings) for name in registry.names]
    return registry.for_job_type(job_type, settings)


def _result_type(observation: Observation) -> str:
    return _RESULT_TYPE_BY_CLASS.get(type(observation).__name__, "observation")


def record_scan_results(
    session: Session,
    project: Project,
    job: ScanJob,
    result: CollectorResult,
    *,
    asset_id: object | None = None,
) -> int:
    """Archive every observation produced by one collector run."""

    written = 0
    for observation in result.observations:
        session.add(
            ScanResult(
                project_id=project.id,
                scan_job_id=job.id,
                asset_id=asset_id,
                result_type=_result_type(observation),
                source=observation.source or result.collector,
                payload=observation.as_dict(),
                observed_at=observation.observed_at,
            )
        )
        written += 1
    if written:
        session.flush()
    return written


def _rule_id(spec: object | None) -> uuid.UUID | None:
    """The matched rule's primary key, parsed from the spec's string reference."""

    reference = getattr(spec, "reference", None)
    if not reference:
        return None
    try:
        return uuid.UUID(str(reference))
    except (TypeError, ValueError):  # pragma: no cover - malformed fixture data
        return None


def _start_job(
    session: Session,
    project: Project,
    *,
    job_type: JobType,
    resolved: ResolvedTarget,
    actor: str,
) -> ScanJob:
    job = ScanJob(
        project_id=project.id,
        job_type=job_type,
        status=JobStatus.RUNNING,
        params={"target": resolved.normalized, "target_kind": resolved.kind.value},
        requested_by=actor,
        started_at=utcnow(),
    )
    session.add(job)
    session.flush()
    # Commit immediately: a crash during collection must not erase the evidence
    # that a run was authorized and started.
    session.commit()
    return job


def _finish_job(
    session: Session,
    job: ScanJob,
    *,
    results: list[CollectorResult],
    status: JobStatus,
    extra_stats: dict[str, Any] | None = None,
) -> None:
    job.status = status
    job.finished_at = utcnow()
    stats: dict[str, Any] = {
        "collectors": len(results),
        "observations": sum(len(r.observations) for r in results),
        "errors": sum(len(r.errors) for r in results),
    }
    if extra_stats:
        stats.update(extra_stats)
    job.stats = stats
    messages = [
        f"{error.operation}: {error.error_type}: {error.message}"
        for result in results
        for error in result.errors
    ]
    job.error = "\n".join(messages)[:4000] or None
    session.flush()


def discover(
    session: Session,
    project: Project,
    settings: Settings,
    value: str,
    *,
    job_type: JobType = JobType.DISCOVER,
    actor: str = "cli",
    registry: CollectorRegistry | None = None,
    scan_id: str | None = None,
) -> DiscoveryOutcome:
    """Run one authorized collection pass over ``value``.

    ``scan_id`` is only meaningful for ``JobType.URLSCAN``: it names one
    urlscan.io result to read instead of searching by page domain. The scan's
    captured page must still be inside the scope, which the collector enforces.

    Raises :class:`~atlas.errors.ScopeViolation` when the value is not covered by
    an active include rule. The denial is audited first.
    """

    if scan_id is not None and job_type is not JobType.URLSCAN:
        raise ValidationError(
            "--scan-id is only meaningful for urlscan ingestion",
            context={"scan_id": scan_id, "job_type": job_type.value},
        )
    normalized_scan: str | None = None
    if scan_id is not None:
        from atlas.collect.urlscan import normalize_scan_id

        normalized_scan = normalize_scan_id(scan_id)

    resolved = resolve_target(value)
    scope = build_scope_set(session, project, settings)
    decision = scope.check(resolved.collection_value)
    if not decision.permitted:
        record_event(
            session,
            action="discovery.denied",
            project_id=project.id,
            actor=actor,
            object_type="target",
            object_id=resolved.normalized[:120],
            outcome="denied",
            detail={"reason": decision.reason, "value": resolved.collection_value},
        )
        # A denial is evidence and must survive the exception that follows.
        session.commit()
        raise ScopeViolation(
            f"{resolved.collection_value} is outside the authorized scope: {decision.reason}",
            context={
                "value": resolved.collection_value,
                "reason": decision.reason,
                "hint": "add it with: atlas scope add <pattern>",
            },
        )

    target = upsert_target(
        session, project, resolved, scope_rule_id=_rule_id(decision.matched_rule)
    )
    job = _start_job(session, project, job_type=job_type, resolved=resolved, actor=actor)
    job.target_id = target.id
    record_event(
        session,
        action="discovery.start",
        project_id=project.id,
        actor=actor,
        object_type="scan_job",
        object_id=str(job.id),
        detail={
            "target": resolved.normalized,
            "kind": resolved.kind.value,
            "job_type": job_type.value,
            "permitted_by": decision.matched_rule.pattern if decision.matched_rule else None,
        },
    )
    session.commit()

    registry = registry or default_registry()
    collectors = _collectors_for(job_type, registry, settings)
    context = build_context(settings, scope, job_id=job.id, actor=actor)

    results: list[CollectorResult] = []
    dns_outcome: DnsOutcome | None = None
    cert_outcome: CertOutcome | None = None
    http_outcome: HttpOutcome | None = None
    urlscan_outcome: UrlscanOutcome | None = None
    scan_results = 0
    errors: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []

    for collector in collectors:
        available, reason = collector.available(settings)
        if not available:
            # A full pass treats an unconfigured source as absent, not as a fault.
            # An explicitly named job type still reports why it could not run.
            skipped.append({"collector": collector.name, "reason": reason})
            if job_type is not JobType.FULL:
                errors.append(
                    {
                        "collector": collector.name,
                        "error_type": "not_configured",
                        "message": reason,
                    }
                )
            continue

        collection_target = CollectionTarget(kind=resolved.kind, value=resolved.collection_value)
        if collector.name == "urlscan" and hasattr(collector, "scan_id"):
            if collector.scan_id:
                collection_target = CollectionTarget(
                    kind=resolved.kind, value=collector.scan_id, display=resolved.normalized
                )
            elif normalized_scan:
                collector.scan_id = normalized_scan
                collection_target = CollectionTarget(
                    kind=resolved.kind, value=normalized_scan, display=resolved.normalized
                )
        try:
            result = collector.collect(collection_target, context)
        except ScopeViolation:
            raise
        except Exception as exc:
            log.exception("collector crashed", extra={"atlas": {"collector": collector.name}})
            errors.append(
                {
                    "collector": collector.name,
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                }
            )
            continue

        results.append(result)
        errors.extend({"collector": collector.name, **error.as_dict()} for error in result.errors)
        scan_results += record_scan_results(session, project, job, result)

        persisted = _PERSISTERS.get(collector.name)
        if persisted == "dns":
            dns_outcome = persist_dns_result(session, project, result, scan_job_id=job.id)
        elif persisted == "certificates":
            cert_outcome = persist_certificate_result(session, project, result, scan_job_id=job.id)
        elif persisted == "http":
            http_outcome = persist_http_result(session, project, result, scan_job_id=job.id)
        elif persisted == "urlscan":
            urlscan_outcome = persist_urlscan_result(session, project, result, scan_job_id=job.id)

    if not collectors:
        status = JobStatus.FAILED
    elif any(error.get("error_type") == "not_configured" for error in errors):
        # A source that could not run is a configuration gap the operator can fix,
        # not a crash: it is reported as partial whether or not a peer collector ran.
        status = JobStatus.PARTIAL
    elif not results or all(result.failed for result in results):
        status = JobStatus.FAILED
    elif any(result.errors for result in results):
        status = JobStatus.PARTIAL
    else:
        status = JobStatus.SUCCEEDED

    _finish_job(
        session,
        job,
        results=results,
        status=status,
        extra_stats={
            "scan_results": scan_results,
            "skipped_collectors": skipped or None,
            "dns_changes": (
                {"added": len(dns_outcome.added), "removed": len(dns_outcome.removed)}
                if dns_outcome is not None
                else None
            ),
        },
    )
    target.last_scan_at = job.finished_at
    record_event(
        session,
        action="discovery.finish",
        project_id=project.id,
        actor=actor,
        object_type="scan_job",
        object_id=str(job.id),
        outcome="success" if status is JobStatus.SUCCEEDED else status.value,
        detail={
            "status": status.value,
            "observations": sum(len(r.observations) for r in results),
            "skipped": [entry["collector"] for entry in skipped],
        },
    )
    session.commit()

    return DiscoveryOutcome(
        job_id=str(job.id),
        target=resolved.normalized,
        target_kind=resolved.kind.value,
        job_type=job_type.value,
        status=status.value,
        collectors=results,
        dns=dns_outcome,
        certs=cert_outcome,
        http=http_outcome,
        urlscan=urlscan_outcome,
        scan_results=scan_results,
        errors=errors,
        scope_reason=decision.reason,
        skipped_collectors=skipped,
    )


def job_summary(job: ScanJob) -> dict[str, Any]:
    return {
        "id": str(job.id),
        "job_type": job.job_type.value,
        "status": job.status.value,
        "requested_by": job.requested_by,
        "params": dict(job.params or {}),
        "stats": dict(job.stats or {}),
        "error": job.error,
        "started_at": isoformat(job.started_at) if job.started_at else None,
        "finished_at": isoformat(job.finished_at) if job.finished_at else None,
    }


def recent_jobs(session: Session, project: Project, *, limit: int = 20) -> list[ScanJob]:
    from sqlalchemy import select

    return list(
        session.scalars(
            select(ScanJob)
            .where(ScanJob.project_id == project.id)
            .order_by(ScanJob.created_at.desc())
            .limit(max(1, limit))
        )
    )


def target_kind_of(value: str) -> TargetKind:
    return resolve_target(value).kind


def target_for(session: Session, project: Project, normalized: str) -> Target | None:
    from sqlalchemy import select

    return session.scalar(
        select(Target).where(Target.project_id == project.id, Target.normalized == normalized)
    )
