"""DNS intelligence service: persistence, diffs, and evidence-backed indicators."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.collect.base import CollectionTarget, CollectorContext, CollectorResult
from atlas.collect.dns import DnsCollector
from atlas.config import Settings
from atlas.db.enums import (
    AssetKind,
    DnsRecordType,
    JobStatus,
    JobType,
    RelationshipType,
    TargetKind,
)
from atlas.db.models import (
    Asset,
    DnsRecord,
    Domain,
    Project,
    Relationship,
    ScanJob,
    ScanResult,
)
from atlas.services.discovery import record_scan_results
from atlas.services.dns import (
    dangling_cnames,
    dns_history,
    dns_records,
    nameserver_summary,
    persist_dns_result,
)
from support import FakeResolver, make_context, zone_of


def run_dns(
    resolver: FakeResolver,
    fqdn: str,
    patterns: list[str] | None = None,
    *,
    follow: bool = True,
) -> tuple[CollectorResult, CollectorContext]:
    settings = Settings()
    context = make_context(settings, patterns or [fqdn])
    collector = DnsCollector(settings=settings, resolver=resolver, follow_cnames=follow)
    target = CollectionTarget(kind=TargetKind.DOMAIN, value=fqdn)
    return collector.collect(target, context), context


def test_persist_creates_assets_records_and_edges(session: Session, project: Project) -> None:
    resolver = zone_of(
        {
            "example.com": {
                "A": ["203.0.113.10"],
                "MX": ["10 mail.example.com."],
                "NS": ["ns1.registrar.example."],
            }
        }
    )
    result, _ = run_dns(resolver, "example.com")

    outcome = persist_dns_result(session, project, result)

    assert outcome.fqdn == "example.com"
    assert outcome.domain_created is True
    assert {change.record_type for change in outcome.added} == {
        DnsRecordType.A,
        DnsRecordType.MX,
        DnsRecordType.NS,
    }
    assert outcome.nameservers == ["ns1.registrar.example"]
    assert outcome.name_status == "UNKNOWN"  # no NXDOMAIN, no explicit status
    assert outcome.active_records == 3

    domain_asset = session.scalar(
        select(Asset).where(Asset.kind == AssetKind.DOMAIN, Asset.key == "example.com")
    )
    assert domain_asset is not None
    ip_asset = session.scalar(
        select(Asset).where(Asset.kind == AssetKind.IP_ADDRESS, Asset.key == "203.0.113.10")
    )
    assert ip_asset is not None

    edge = session.scalar(
        select(Relationship).where(
            Relationship.source_asset_id == domain_asset.id,
            Relationship.target_asset_id == ip_asset.id,
        )
    )
    assert edge is not None
    assert edge.rel_type is RelationshipType.RESOLVES_TO
    assert edge.evidence_source == "dns"
    assert edge.confidence == pytest.approx(0.95)


def test_second_run_reports_added_and_removed(session: Session, project: Project) -> None:
    first = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    result, _ = run_dns(first, "example.com")
    persist_dns_result(session, project, result)

    second = zone_of({"example.com": {"A": ["203.0.113.99"]}})
    result2, _ = run_dns(second, "example.com")
    outcome = persist_dns_result(session, project, result2)

    assert [c.value for c in outcome.added] == ["203.0.113.99"]
    assert [c.value for c in outcome.removed] == ["203.0.113.10"]
    assert outcome.changed is True

    records = {
        (r.value, r.is_active)
        for r in dns_records(session, project, "example.com", active_only=False)
    }
    assert ("203.0.113.10", False) in records
    assert ("203.0.113.99", True) in records


def test_failed_type_does_not_retire_its_records(session: Session, project: Project) -> None:
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"], "MX": ["10 mail.example.com."]}})
    result, _ = run_dns(resolver, "example.com")
    persist_dns_result(session, project, result)

    broken = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    broken.failures[("example.com", "MX")] = TimeoutError("timed out")
    result2, _ = run_dns(broken, "example.com")
    outcome = persist_dns_result(session, project, result2)

    assert outcome.removed == []
    mx = session.scalar(select(DnsRecord).where(DnsRecord.record_type == DnsRecordType.MX))
    assert mx is not None and mx.is_active is True


def test_nxdomain_retires_everything(session: Session, project: Project) -> None:
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    result, _ = run_dns(resolver, "example.com")
    persist_dns_result(session, project, result)

    gone = FakeResolver()
    result2, _ = run_dns(gone, "example.com")
    outcome = persist_dns_result(session, project, result2)

    assert outcome.name_status == "NXDOMAIN"
    assert [c.value for c in outcome.removed] == ["203.0.113.10"]


def test_dangling_cname_is_reported_with_evidence(session: Session, project: Project) -> None:
    resolver = zone_of({"www.example.com": {"CNAME": ["unclaimed.example.net."]}})
    result, _ = run_dns(resolver, "www.example.com")

    outcome = persist_dns_result(session, project, result)

    assert len(outcome.dangling_cnames) == 1
    indicator = outcome.dangling_cnames[0]
    assert indicator["cname"] == "www.example.com"
    assert indicator["target"] == "unclaimed.example.net"
    assert indicator["target_status"] == "NXDOMAIN"


def test_cname_to_known_domain_creates_edge(session: Session, project: Project) -> None:
    # app.example.com already exists as an asset, so the CNAME can be linked.
    seed = zone_of({"app.example.com": {"A": ["203.0.113.20"]}})
    seed_result, _ = run_dns(seed, "app.example.com")
    persist_dns_result(session, project, seed_result)

    resolver = zone_of(
        {
            "www.example.com": {"CNAME": ["app.example.com."]},
            "app.example.com": {"A": ["203.0.113.20"]},
        }
    )
    result, _ = run_dns(resolver, "www.example.com")
    outcome = persist_dns_result(session, project, result)

    edge = session.scalar(
        select(Relationship).where(Relationship.rel_type == RelationshipType.CNAME_TO)
    )
    assert edge is not None
    assert edge.evidence_source == "dns"
    assert outcome.relationships >= 1


def test_unknown_cname_target_is_not_promoted_to_an_asset(
    session: Session, project: Project
) -> None:
    resolver = zone_of({"www.example.com": {"CNAME": ["cdn.vendor.example."]}})
    result, _ = run_dns(resolver, "www.example.com")

    persist_dns_result(session, project, result)

    keys = {asset.key for asset in session.scalars(select(Asset))}
    assert "cdn.vendor.example" not in keys
    record = session.scalar(select(DnsRecord).where(DnsRecord.record_type == DnsRecordType.CNAME))
    assert record is not None and record.value == "cdn.vendor.example"


def test_shared_nameserver_edge_is_labelled_as_infrastructure(
    session: Session, project: Project
) -> None:
    first = zone_of({"a.example.com": {"NS": ["ns1.shared.example."]}})
    persist_dns_result(session, project, run_dns(first, "a.example.com")[0])

    second = zone_of({"b.example.com": {"NS": ["ns1.shared.example."]}})
    persist_dns_result(session, project, run_dns(second, "b.example.com")[0])

    edge = session.scalar(
        select(Relationship).where(Relationship.rel_type == RelationshipType.SHARES_NAMESERVER)
    )
    assert edge is not None
    assert edge.confidence == pytest.approx(0.3)
    assert "not shared ownership" in edge.attributes["note"]
    assert edge.attributes["shared_nameservers"] == ["ns1.shared.example"]


def test_dns_history_reports_windows(session: Session, project: Project) -> None:
    resolver = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    persist_dns_result(session, project, run_dns(resolver, "example.com")[0])

    history = dns_history(session, project, "example.com")

    assert history["fqdn"] == "example.com"
    assert history["active"] == 1
    assert history["retired"] == 0
    assert history["records"]["A"][0]["value"] == "203.0.113.10"
    assert history["records"]["A"][0]["first_seen"].endswith("Z")


def test_nameserver_summary_lists_peers(session: Session, project: Project) -> None:
    shared = {"NS": ["ns1.shared.example."]}
    persist_dns_result(
        session, project, run_dns(zone_of({"a.example.com": shared}), "a.example.com")[0]
    )
    persist_dns_result(
        session, project, run_dns(zone_of({"b.example.com": shared}), "b.example.com")[0]
    )

    summary = nameserver_summary(session, project, "a.example.com")

    assert summary["nameservers"] == ["ns1.shared.example"]
    assert [entry["fqdn"] for entry in summary["shared_with"]] == ["b.example.com"]
    assert "not shared ownership" in summary["note"]


def test_dangling_from_scan_result_evidence(session: Session, project: Project) -> None:
    job = ScanJob(
        project_id=project.id,
        job_type=JobType.DNS,
        status=JobStatus.SUCCEEDED,
    )
    session.add(job)
    session.flush()

    resolver = zone_of({"www.example.com": {"CNAME": ["gone.example.net."]}})
    result, _ = run_dns(resolver, "www.example.com")
    record_scan_results(session, project, job, result)

    findings = dangling_cnames(session, project)

    assert len(findings) == 1
    assert findings[0]["target"] == "gone.example.net"
    assert findings[0]["evidence"]["scan_job_id"] == str(job.id)
    assert session.scalar(select(ScanResult).limit(1)) is not None


def test_dangling_absent_without_nxdomain_evidence(session: Session, project: Project) -> None:
    job = ScanJob(project_id=project.id, job_type=JobType.DNS, status=JobStatus.SUCCEEDED)
    session.add(job)
    session.flush()

    resolver = zone_of(
        {
            "www.example.com": {"CNAME": ["app.example.net."]},
            "app.example.net": {"A": ["203.0.113.5"]},
        }
    )
    result, _ = run_dns(resolver, "www.example.com", ["www.example.com", "app.example.net"])
    record_scan_results(session, project, job, result)

    assert dangling_cnames(session, project) == []


def test_history_for_unknown_name_is_an_error(session: Session, project: Project) -> None:
    from atlas.errors import ValidationError

    with pytest.raises(ValidationError):
        dns_history(session, project, "never-collected.example.com")


def test_domain_is_reused_across_runs(session: Session, project: Project) -> None:
    first = zone_of({"example.com": {"A": ["203.0.113.10"]}})
    second = zone_of({"example.com": {"A": ["203.0.113.11"]}})
    persist_dns_result(session, project, run_dns(first, "example.com")[0])
    persist_dns_result(session, project, run_dns(second, "example.com")[0])
    assert len(list(session.scalars(select(Domain)))) == 1
