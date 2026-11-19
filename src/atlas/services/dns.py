"""DNS intelligence: persistence, change detection, and DNS-specific indicators.

What this service adds on top of the collector:

* **Observations become state.** Records are upserted with an observation window;
  records that stopped appearing are retired rather than deleted.
* **Change detection is a diff, not a guess.** Every added/removed/refreshed
  record is derived from comparing the pre-write active set with the post-write
  one, and the result is returned to the caller (and recorded as a scan event).
* **Dangling CNAMEs are evidence-backed.** A CNAME is reported as dangling only
  when a ``NameStatusObservation`` from the same run says the target answered
  NXDOMAIN. A resolver error never produces a dangling claim.
* **Shared nameservers are shared infrastructure.** The edge is written as
  ``SHARES_NAMESERVER`` with a low confidence and an explicit note, so it can
  never be presented as common ownership.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.collect.base import (
    CollectorResult,
    DnsAnswerObservation,
    NameStatusObservation,
)
from atlas.core.time import isoformat
from atlas.db.enums import AssetKind, DnsRecordType, RelationshipType, TargetKind
from atlas.db.models import Asset, DnsRecord, Domain, Project, ScanResult
from atlas.errors import ValidationError
from atlas.scope.normalize import normalize_domain
from atlas.services.observations import (
    ensure_domain,
    ensure_ip_address,
    retire_dns_records,
    upsert_dns_record,
)
from atlas.services.relationships import upsert_relationship

__all__ = [
    "DnsChange",
    "DnsOutcome",
    "dangling_cnames",
    "dns_history",
    "dns_records",
    "nameserver_summary",
    "persist_dns_result",
]

_RESOLVES_TO_CONFIDENCE = 0.95
_CNAME_TO_CONFIDENCE = 0.9
_SHARED_NAMESERVER_CONFIDENCE = 0.3
_MAX_NAMESERVER_PEERS = 200


@dataclass(frozen=True, slots=True)
class DnsChange:
    """One difference between the previous and current record set."""

    record_type: DnsRecordType
    value: str
    change: str  # added | removed | refreshed

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type.value,
            "value": self.value,
            "change": self.change,
        }


@dataclass(slots=True)
class DnsOutcome:
    """What a DNS persistence pass did, in enough detail to render a report."""

    fqdn: str
    domain_created: bool = False
    added: list[DnsChange] = field(default_factory=list)
    removed: list[DnsChange] = field(default_factory=list)
    refreshed: int = 0
    addresses: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    dangling_cnames: list[dict[str, Any]] = field(default_factory=list)
    name_status: str = "UNKNOWN"
    relationships: int = 0
    active_records: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "fqdn": self.fqdn,
            "domain_created": self.domain_created,
            "changed": self.changed,
            "added": [c.as_dict() for c in self.added],
            "removed": [c.as_dict() for c in self.removed],
            "refreshed": self.refreshed,
            "addresses": list(self.addresses),
            "nameservers": list(self.nameservers),
            "dangling_cnames": list(self.dangling_cnames),
            "name_status": self.name_status,
            "relationships": self.relationships,
            "active_records": self.active_records,
        }


def persist_dns_result(
    session: Session,
    project: Project,
    result: CollectorResult,
    *,
    scan_job_id: Any = None,
    link_relationships: bool = True,
) -> DnsOutcome:
    """Write a DNS collector result to the database and report the diff."""

    if result.target.kind not in {TargetKind.DOMAIN, TargetKind.URL}:
        # Address targets only yield PTR observations; there is no domain row to
        # attach them to, and inventing one would misrepresent the observation.
        return DnsOutcome(fqdn=result.target.value)

    fqdn = normalize_domain(result.target.value)
    answers = tuple(o for o in result.observations if isinstance(o, DnsAnswerObservation))
    statuses = tuple(o for o in result.observations if isinstance(o, NameStatusObservation))

    before = _active_record_keys(session, project, fqdn)
    domain_existed = session.scalar(
        select(Domain.id).where(Domain.project_id == project.id, Domain.fqdn == fqdn)
    )
    domain = ensure_domain(
        session,
        project,
        fqdn,
        source=result.collector,
        observed_at=result.started_at,
        scan_job_id=scan_job_id,
    )

    seen: set[tuple[DnsRecordType, str]] = set()
    added: list[DnsChange] = []
    refreshed = 0
    nameservers: list[str] = []
    addresses: list[str] = []

    for observation in answers:
        record, created = upsert_dns_record(
            session,
            domain,
            record_type=observation.record_type,
            value=observation.value,
            source=observation.source or result.collector,
            observed_at=observation.observed_at,
            ttl=observation.ttl,
            priority=observation.priority,
        )
        key = (record.record_type, record.value)
        seen.add(key)
        if created:
            added.append(DnsChange(record.record_type, record.value, "added"))
        elif key in before:
            refreshed += 1
        else:
            added.append(DnsChange(record.record_type, record.value, "added"))

        if observation.record_type is DnsRecordType.NS and observation.value not in nameservers:
            nameservers.append(observation.value)
        if observation.record_type in {DnsRecordType.A, DnsRecordType.AAAA}:
            if observation.value not in addresses:
                addresses.append(observation.value)
            if link_relationships:
                ensure_ip_address(
                    session,
                    project,
                    observation.value,
                    source=result.collector,
                    observed_at=observation.observed_at,
                    scan_job_id=scan_job_id,
                )

    checked_types = {
        DnsRecordType(str(value))
        for value in result.stats.get("checked_types", [])
        if _is_record_type(value)
    }
    retired = retire_dns_records(session, domain, checked_types=checked_types, seen=seen)
    removed = [DnsChange(r.record_type, r.value, "removed") for r in retired]

    name_status = _name_status(statuses, fqdn)
    dangling = _dangling_from_statuses(answers, statuses)

    outcome = DnsOutcome(
        fqdn=fqdn,
        domain_created=domain_existed is None,
        added=added,
        removed=removed,
        refreshed=refreshed,
        addresses=addresses,
        nameservers=nameservers,
        dangling_cnames=dangling,
        name_status=name_status,
    )

    if link_relationships:
        outcome.relationships += _link_dns_relationships(
            session,
            project,
            domain_asset_id=domain.asset_id,
            answers=answers,
            nameservers=nameservers,
            observed_at=result.started_at,
        )

    outcome.active_records = len(list(_records(session, domain, active_only=True)))
    return outcome


def _is_record_type(value: object) -> bool:
    try:
        DnsRecordType(str(value))
    except ValueError:
        return False
    return True


def _records(session: Session, domain: Domain, *, active_only: bool = False) -> list[DnsRecord]:
    statement = select(DnsRecord).where(DnsRecord.domain_id == domain.id)
    if active_only:
        statement = statement.where(DnsRecord.is_active.is_(True))
    return list(session.scalars(statement.order_by(DnsRecord.record_type, DnsRecord.value)))


def _active_record_keys(
    session: Session, project: Project, fqdn: str
) -> set[tuple[DnsRecordType, str]]:
    domain = session.scalar(
        select(Domain).where(Domain.project_id == project.id, Domain.fqdn == fqdn)
    )
    if domain is None:
        return set()
    return {(r.record_type, r.value) for r in _records(session, domain, active_only=True)}


def _name_status(statuses: Iterable[NameStatusObservation], fqdn: str) -> str:
    for status in statuses:
        if status.query_name == fqdn:
            return status.status
    return "UNKNOWN"


def _dangling_from_statuses(
    answers: Iterable[DnsAnswerObservation], statuses: Iterable[NameStatusObservation]
) -> list[dict[str, Any]]:
    """Dangling = CNAME target explicitly answered NXDOMAIN in this same run."""

    negative = {
        status.query_name: status
        for status in statuses
        if not status.exists and status.status == "NXDOMAIN"
    }
    findings: list[dict[str, Any]] = []
    for answer in answers:
        if answer.record_type is not DnsRecordType.CNAME:
            continue
        status = negative.get(answer.value)
        if status is None:
            continue
        findings.append(
            {
                "cname": answer.query_name,
                "target": answer.value,
                "target_status": status.status,
                "observed_at": isoformat(status.observed_at),
                "indicator": "cname_target_nxdomain",
                "note": (
                    "The CNAME target does not exist in DNS. Verify before claiming "
                    "the resource is claimable."
                ),
            }
        )
    return findings


def _link_dns_relationships(
    session: Session,
    project: Project,
    *,
    domain_asset_id: Any,
    answers: Iterable[DnsAnswerObservation],
    nameservers: list[str],
    observed_at: datetime,
) -> int:
    created_or_refreshed = 0
    source_asset = session.get(Asset, domain_asset_id)
    if source_asset is None:  # pragma: no cover - defensive
        return 0

    for answer in answers:
        if answer.record_type not in {DnsRecordType.A, DnsRecordType.AAAA}:
            continue
        ip_asset = session.scalar(
            select(Asset).where(
                Asset.project_id == project.id,
                Asset.kind == AssetKind.IP_ADDRESS,
                Asset.key == answer.value,
            )
        )
        if ip_asset is None:  # pragma: no cover - the caller just created it
            continue
        upsert_relationship(
            session,
            project,
            source=source_asset,
            target=ip_asset,
            rel_type=RelationshipType.RESOLVES_TO,
            evidence_source="dns",
            confidence=_RESOLVES_TO_CONFIDENCE,
            observed_at=observed_at,
            attributes={"record_type": answer.record_type.value, "ttl": answer.ttl},
        )
        created_or_refreshed += 1

    for answer in answers:
        if answer.record_type is not DnsRecordType.CNAME:
            continue
        # Only link to a domain ATLAS already knows about. A CNAME target outside
        # the collected set is recorded on the DNS record, never promoted to an
        # asset — discovery must not widen the authorized scope.
        target_domain = session.scalar(
            select(Domain).where(
                Domain.project_id == project.id,
                Domain.fqdn == answer.value,
            )
        )
        if target_domain is None:
            continue
        target_asset = session.get(Asset, target_domain.asset_id)
        if target_asset is None or target_asset.id == source_asset.id:  # pragma: no cover
            continue
        upsert_relationship(
            session,
            project,
            source=source_asset,
            target=target_asset,
            rel_type=RelationshipType.CNAME_TO,
            evidence_source="dns",
            confidence=_CNAME_TO_CONFIDENCE,
            observed_at=observed_at,
            attributes={"ttl": answer.ttl},
        )
        created_or_refreshed += 1

    if nameservers:
        created_or_refreshed += _link_shared_nameservers(
            session,
            project,
            source_asset=source_asset,
            nameservers=nameservers,
            observed_at=observed_at,
        )
    return created_or_refreshed


def _link_shared_nameservers(
    session: Session,
    project: Project,
    *,
    source_asset: Asset,
    nameservers: list[str],
    observed_at: datetime,
) -> int:
    peer_rows = session.execute(
        select(Domain.fqdn, DnsRecord.value)
        .join(Asset, Asset.id == Domain.asset_id)
        .join(DnsRecord, DnsRecord.domain_id == Domain.id)
        .where(
            Domain.project_id == project.id,
            DnsRecord.record_type == DnsRecordType.NS,
            DnsRecord.is_active.is_(True),
            DnsRecord.value.in_(nameservers),
            Domain.asset_id != source_asset.id,
        )
        .limit(_MAX_NAMESERVER_PEERS * 4)
    ).all()

    peers: dict[str, set[str]] = {}
    for fqdn, ns_value in peer_rows:
        peers.setdefault(str(fqdn), set()).add(str(ns_value))

    linked = 0
    for fqdn, shared in list(peers.items())[:_MAX_NAMESERVER_PEERS]:
        peer_asset = session.scalar(
            select(Asset)
            .join(Domain, Domain.asset_id == Asset.id)
            .where(Asset.project_id == project.id, Domain.fqdn == fqdn)
        )
        if peer_asset is None or peer_asset.id == source_asset.id:  # pragma: no cover
            continue
        upsert_relationship(
            session,
            project,
            source=source_asset,
            target=peer_asset,
            rel_type=RelationshipType.SHARES_NAMESERVER,
            evidence_source="dns",
            confidence=_SHARED_NAMESERVER_CONFIDENCE,
            observed_at=observed_at,
            attributes={
                "shared_nameservers": sorted(shared),
                "note": (
                    "Shared nameservers indicate shared DNS infrastructure, not shared ownership."
                ),
            },
        )
        linked += 1
    return linked


# --------------------------------------------------------------------------- #
# Queries used by the CLI and API                                              #
# --------------------------------------------------------------------------- #


def dns_records(
    session: Session,
    project: Project,
    fqdn: str,
    *,
    active_only: bool = True,
    record_types: Iterable[DnsRecordType] | None = None,
) -> list[DnsRecord]:
    normalized = normalize_domain(fqdn)
    domain = session.scalar(
        select(Domain).where(Domain.project_id == project.id, Domain.fqdn == normalized)
    )
    if domain is None:
        return []
    statement = select(DnsRecord).where(DnsRecord.domain_id == domain.id)
    if active_only:
        statement = statement.where(DnsRecord.is_active.is_(True))
    if record_types is not None:
        statement = statement.where(DnsRecord.record_type.in_(list(record_types)))
    return list(session.scalars(statement.order_by(DnsRecord.record_type, DnsRecord.value)))


def dns_history(session: Session, project: Project, fqdn: str) -> dict[str, Any]:
    """Every record ever observed for a name, with its observation window."""

    normalized = normalize_domain(fqdn)
    domain = session.scalar(
        select(Domain).where(Domain.project_id == project.id, Domain.fqdn == normalized)
    )
    if domain is None:
        raise ValidationError(f"no DNS history for {normalized}: the name was never collected")

    records = _records(session, domain, active_only=False)
    by_type: dict[str, list[dict[str, Any]]] = {}
    for record in sorted(records, key=lambda r: (r.record_type, r.first_seen)):
        by_type.setdefault(record.record_type.value, []).append(
            {
                "value": record.value,
                "ttl": record.ttl,
                "priority": record.priority,
                "is_active": record.is_active,
                "first_seen": isoformat(record.first_seen),
                "last_seen": isoformat(record.last_seen),
                "source": record.source,
            }
        )

    return {
        "fqdn": normalized,
        "registrable_domain": domain.registrable_domain,
        "is_apex": domain.is_apex,
        "records": by_type,
        "active": sum(1 for r in records if r.is_active),
        "retired": sum(1 for r in records if not r.is_active),
        "cname_targets": sorted({r.value for r in records if r.record_type is DnsRecordType.CNAME}),
    }


def nameserver_summary(session: Session, project: Project, fqdn: str) -> dict[str, Any]:
    records = dns_records(session, project, fqdn, record_types=[DnsRecordType.NS])
    nameservers = sorted({record.value for record in records})
    if not nameservers:
        return {"fqdn": normalize_domain(fqdn), "nameservers": [], "shared_with": []}

    peer_rows = session.execute(
        select(Domain.fqdn, DnsRecord.value)
        .join(Asset, Asset.id == Domain.asset_id)
        .join(DnsRecord, DnsRecord.domain_id == Domain.id)
        .where(
            Domain.project_id == project.id,
            Domain.fqdn != normalize_domain(fqdn),
            DnsRecord.record_type == DnsRecordType.NS,
            DnsRecord.is_active.is_(True),
            DnsRecord.value.in_(nameservers),
        )
        .limit(_MAX_NAMESERVER_PEERS)
    ).all()

    shared: dict[str, list[str]] = {}
    for peer_fqdn, ns_value in peer_rows:
        shared.setdefault(str(peer_fqdn), []).append(str(ns_value))

    return {
        "fqdn": normalize_domain(fqdn),
        "nameservers": nameservers,
        "shared_with": [
            {"fqdn": name, "shared_nameservers": sorted(set(values))}
            for name, values in sorted(shared.items())
        ],
        "note": "Shared nameservers indicate shared providers, not shared ownership.",
    }


def dangling_cnames(
    session: Session, project: Project, *, limit: int = 5000
) -> list[dict[str, Any]]:
    """Project-wide dangling-CNAME indicators, rebuilt from stored evidence.

    Only ``ScanResult`` rows count: a CNAME is reported dangling when a run
    recorded the exact NXDOMAIN answer for its target. Nothing is inferred from
    the mere absence of a name.
    """

    rows = session.scalars(
        select(ScanResult)
        .where(
            ScanResult.project_id == project.id,
            ScanResult.result_type.in_(["dns.answer", "dns.status"]),
        )
        .order_by(ScanResult.observed_at.desc())
        .limit(max(1, limit))
    )

    negative: dict[str, dict[str, Any]] = {}
    cnames: list[dict[str, Any]] = []
    for row in rows:
        payload = dict(row.payload or {})
        if row.result_type == "dns.status":
            name = str(payload.get("query_name") or "")
            if name and payload.get("exists") is False and payload.get("status") == "NXDOMAIN":
                negative.setdefault(
                    name,
                    {
                        "scan_job_id": str(row.scan_job_id),
                        "observed_at": isoformat(row.observed_at),
                    },
                )
        elif payload.get("record_type") == "CNAME":
            cnames.append(payload)

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for payload in cnames:
        source = str(payload.get("query_name") or "")
        target = str(payload.get("value") or "")
        if not source or not target or (source, target) in seen:
            continue
        evidence = negative.get(target)
        if evidence is None:
            continue
        seen.add((source, target))
        findings.append(
            {
                "cname": source,
                "target": target,
                "target_status": "NXDOMAIN",
                "indicator": "cname_target_nxdomain",
                "evidence": evidence,
                "note": (
                    "The CNAME target answered NXDOMAIN when it was observed. Confirm "
                    "with a fresh lookup before treating the resource as claimable."
                ),
            }
        )
    return findings
