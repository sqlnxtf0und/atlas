"""Discovery orchestration: scope gate, job lifecycle, and provenance."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.collect.base import (
    CollectionTarget,
    Collector,
    CollectorContext,
    CollectorResult,
)
from atlas.collect.dns import DnsCollector
from atlas.collect.registry import CollectorRegistry
from atlas.config import Settings
from atlas.db.enums import AssetKind, DnsRecordType, JobStatus, JobType, TargetKind
from atlas.db.models import (
    Asset,
    AuditEvent,
    DnsRecord,
    Project,
    ScanJob,
    ScanResult,
    Target,
)
from atlas.errors import ScopeViolation
from atlas.services.discovery import discover
from atlas.services.scopes import add_rule
from support import FakeResolver, zone_of


def dns_registry(resolver: FakeResolver, *, follow: bool = True) -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(
        DnsCollector.name,
        lambda settings: DnsCollector(settings=settings, resolver=resolver, follow_cnames=follow),
        job_type=JobType.DNS,
    )
    return registry


def authorize(session: Session, project: Project, pattern: str) -> None:
    add_rule(session, project, pattern=pattern)
    session.flush()


def test_target_outside_scope_is_denied_and_audited(session: Session, project: Project) -> None:
    with pytest.raises(ScopeViolation) as excinfo:
        discover(
            session,
            project,
            Settings(),
            "not-permitted.example.com",
            registry=dns_registry(FakeResolver()),
        )

    assert excinfo.value.exit_code == 3
    event = session.scalar(select(AuditEvent).where(AuditEvent.action == "discovery.denied"))
    assert event is not None
    assert event.outcome == "denied"
    # No job row is created for a denied target.
    assert session.scalar(select(ScanJob)) is None


def test_successful_discovery_records_job_target_and_evidence(
    session: Session, project: Project
) -> None:
    authorize(session, project, "example.com")
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"], "NS": ["ns1.registrar.example."]}})

    outcome = discover(
        session,
        project,
        Settings(),
        "example.com",
        job_type=JobType.DNS,
        registry=dns_registry(resolver),
    )

    assert outcome.status == JobStatus.SUCCEEDED.value
    assert outcome.observations == 2
    assert outcome.scan_results == 2
    assert outcome.dns is not None
    assert {c.record_type for c in outcome.dns.added} == {
        DnsRecordType.A,
        DnsRecordType.NS,
    }

    job = session.get(ScanJob, __import__("uuid").UUID(outcome.job_id))
    assert job is not None
    assert job.status is JobStatus.SUCCEEDED
    assert job.finished_at is not None
    assert job.stats["observations"] == 2

    target = session.scalar(select(Target))
    assert target is not None
    assert target.kind is TargetKind.DOMAIN
    assert target.last_scan_at is not None

    assert session.scalar(select(ScanResult)) is not None
    assert session.scalar(select(Asset).where(Asset.kind == AssetKind.IP_ADDRESS)) is not None
    assert session.scalar(select(DnsRecord)) is not None


def test_scope_rule_reference_is_stored_on_the_target(session: Session, project: Project) -> None:
    authorize(session, project, "example.com")
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})

    discover(session, project, Settings(), "example.com", registry=dns_registry(resolver))

    target = session.scalar(select(Target))
    assert target is not None
    assert target.scope_rule_id is not None


def test_partial_job_when_a_record_type_fails(session: Session, project: Project) -> None:
    authorize(session, project, "example.com")
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    resolver.failures[("example.com", "MX")] = TimeoutError("slow")

    outcome = discover(
        session,
        project,
        Settings(),
        "example.com",
        job_type=JobType.DNS,
        registry=dns_registry(resolver),
    )

    assert outcome.status == JobStatus.PARTIAL.value
    job = session.get(ScanJob, __import__("uuid").UUID(outcome.job_id))
    assert job is not None and job.error is not None
    assert "MX" in job.error


def test_failed_job_when_every_type_fails(session: Session, project: Project) -> None:
    authorize(session, project, "example.com")
    resolver = FakeResolver()
    resolver.names.add("example.com")
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        resolver.failures[("example.com", record_type)] = TimeoutError("dead")

    outcome = discover(
        session,
        project,
        Settings(),
        "example.com",
        job_type=JobType.DNS,
        registry=dns_registry(resolver),
    )

    assert outcome.status == JobStatus.FAILED.value


class ExplodingCollector(Collector):
    name = "exploding"
    job_type = JobType.FULL

    def collect(self, target: CollectionTarget, context: CollectorContext) -> CollectorResult:
        raise RuntimeError("boom")


def test_collector_crash_does_not_erase_the_job(session: Session, project: Project) -> None:
    authorize(session, project, "example.com")
    registry = CollectorRegistry()
    registry.register(
        ExplodingCollector.name, lambda settings: ExplodingCollector(), job_type=JobType.DNS
    )

    outcome = discover(
        session, project, Settings(), "example.com", job_type=JobType.DNS, registry=registry
    )

    assert outcome.status == JobStatus.FAILED.value
    assert outcome.errors[0]["error_type"] == "RuntimeError"
    job = session.get(ScanJob, __import__("uuid").UUID(outcome.job_id))
    assert job is not None
    assert job.status is JobStatus.FAILED


def test_second_run_extends_the_observation_window(session: Session, project: Project) -> None:
    authorize(session, project, "example.com")
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    registry = dns_registry(resolver)

    first = discover(
        session, project, Settings(), "example.com", job_type=JobType.DNS, registry=registry
    )
    asset = session.scalar(select(Asset).where(Asset.kind == AssetKind.DOMAIN))
    assert asset is not None
    first_seen = asset.first_seen

    discover(session, project, Settings(), "example.com", job_type=JobType.DNS, registry=registry)

    session.refresh(asset)
    assert asset.first_seen == first_seen
    assert asset.last_seen >= first_seen
    assert first.job_id != ""
    jobs = list(session.scalars(select(ScanJob)))
    assert len(jobs) == 2


def test_full_job_type_runs_every_registered_collector(session: Session, project: Project) -> None:
    authorize(session, project, "example.com")
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})

    outcome = discover(
        session,
        project,
        Settings(),
        "example.com",
        job_type=JobType.FULL,
        registry=dns_registry(resolver),
    )

    assert [result.collector for result in outcome.collectors] == ["dns"]
    assert outcome.status == JobStatus.SUCCEEDED.value


def test_discover_job_type_only_runs_collectors_registered_for_it(
    session: Session, project: Project
) -> None:
    authorize(session, project, "example.com")
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    registry = CollectorRegistry()
    registry.register(
        DnsCollector.name,
        lambda settings: DnsCollector(settings=settings, resolver=resolver),
        job_type=JobType.DNS,  # deliberately not DISCOVER
    )

    outcome = discover(
        session,
        project,
        Settings(),
        "example.com",
        job_type=JobType.DISCOVER,
        registry=registry,
    )

    assert outcome.collectors == []
    assert outcome.status == JobStatus.FAILED.value


def test_target_is_reactivated_on_a_later_run(session: Session, project: Project) -> None:
    authorize(session, project, "example.com")
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    registry = dns_registry(resolver)
    discover(session, project, Settings(), "example.com", job_type=JobType.DNS, registry=registry)

    target = session.scalar(select(Target))
    assert target is not None
    target.is_active = False
    session.flush()

    discover(session, project, Settings(), "example.com", job_type=JobType.DNS, registry=registry)

    assert session.get(Target, target.id).is_active is True
    assert len(list(session.scalars(select(Target)))) == 1


def test_scope_rule_reference_updates_when_authorized_by_a_new_rule(
    session: Session, project: Project
) -> None:
    authorize(session, project, "one.example.com")
    resolver = zone_of({"one.example.com": {"A": ["203.0.113.10"]}})
    registry = dns_registry(resolver)
    discover(
        session, project, Settings(), "one.example.com", job_type=JobType.DNS, registry=registry
    )
    first = session.scalar(select(Target))
    assert first is not None
    first_rule = first.scope_rule_id
    assert first_rule is not None

    # A second, broader rule now also covers the target; the newest decision wins.
    authorize(session, project, "example.com")
    discover(
        session, project, Settings(), "one.example.com", job_type=JobType.DNS, registry=registry
    )

    session.refresh(first)
    second_rule = first.scope_rule_id
    assert second_rule is not None
    assert second_rule != first_rule
