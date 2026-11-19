"""Observation persistence — the write side of collection.

This module is the only place where a collector's output becomes database state.
Three rules hold everywhere below:

1. **Identity is explicit.** ``(project_id, kind, key)`` for assets,
   ``(domain_id, record_type, value)`` for DNS records.
2. **Observation windows only widen.** ``first_seen`` can move earlier,
   ``last_seen`` can move later, and neither is ever reset to "now" by a write
   that did not observe the thing.
3. **Absence is recorded, not deleted.** A record that stopped appearing sets
   ``is_active = False``; the row and its window survive.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.core.time import ensure_utc, utcnow
from atlas.db.enums import AssetKind, DnsRecordType, ServiceState
from atlas.db.models import Asset, DnsRecord, Domain, IpAddress, Project, Service
from atlas.scope.normalize import normalize_domain, split_hostname
from atlas.scope.policy import AddressClass, classify_address

__all__ = [
    "AssetUpsert",
    "ensure_domain",
    "ensure_ip_address",
    "merge_observation_window",
    "retire_dns_records",
    "upsert_asset",
    "upsert_dns_record",
    "upsert_service",
]


@dataclass(frozen=True, slots=True)
class AssetUpsert:
    """Result of an idempotent asset write."""

    asset: Asset
    created: bool


def merge_observation_window(
    existing_first: datetime | None,
    existing_last: datetime | None,
    observed_at: datetime,
) -> tuple[datetime, datetime]:
    """Narrow the window: earliest first-seen, latest last-seen."""

    moment = ensure_utc(observed_at)
    first = moment if existing_first is None else min(ensure_utc(existing_first), moment)
    last = moment if existing_last is None else max(ensure_utc(existing_last), moment)
    return first, last


def upsert_asset(
    session: Session,
    project: Project,
    *,
    kind: AssetKind,
    key: str,
    source: str,
    observed_at: datetime | None = None,
    label: str | None = None,
    confidence: float = 1.0,
    attributes: dict[str, object] | None = None,
    scan_job_id: uuid.UUID | None = None,
) -> AssetUpsert:
    """Create or refresh one asset without ever overwriting history."""

    if not key:
        raise ValueError("asset key must not be empty")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")

    moment = ensure_utc(observed_at or utcnow())
    asset = session.scalar(
        select(Asset).where(
            Asset.project_id == project.id,
            Asset.kind == kind,
            Asset.key == key,
        )
    )

    if asset is None:
        asset = Asset(
            project_id=project.id,
            kind=kind,
            key=key,
            label=label,
            source=source,
            confidence=confidence,
            first_seen=moment,
            last_seen=moment,
            is_active=True,
            attributes=dict(attributes or {}),
            first_scan_job_id=scan_job_id,
        )
        session.add(asset)
        session.flush()
        return AssetUpsert(asset=asset, created=True)

    asset.first_seen, asset.last_seen = merge_observation_window(
        asset.first_seen, asset.last_seen, moment
    )
    asset.is_active = True
    asset.confidence = max(asset.confidence, confidence)
    if label and not asset.label:
        asset.label = label
    if attributes:
        merged = dict(asset.attributes or {})
        merged.update({k: v for k, v in attributes.items() if v is not None})
        asset.attributes = merged
    if scan_job_id is not None and asset.first_scan_job_id is None:
        asset.first_scan_job_id = scan_job_id
    session.flush()
    return AssetUpsert(asset=asset, created=False)


def ensure_domain(
    session: Session,
    project: Project,
    fqdn: str,
    *,
    source: str,
    observed_at: datetime | None = None,
    scan_job_id: uuid.UUID | None = None,
) -> Domain:
    """Upsert the domain asset and its ``domains`` detail row."""

    normalized = normalize_domain(fqdn)
    upsert = upsert_asset(
        session,
        project,
        kind=AssetKind.DOMAIN,
        key=normalized,
        source=source,
        observed_at=observed_at,
        label=normalized,
        scan_job_id=scan_job_id,
    )
    asset = upsert.asset

    domain = session.scalar(select(Domain).where(Domain.asset_id == asset.id))
    if domain is not None:
        return domain

    subdomain, registrable = split_hostname(normalized)
    parent = None
    if subdomain:
        parent = session.scalar(
            select(Domain).where(
                Domain.project_id == project.id,
                Domain.fqdn == registrable,
            )
        )

    domain = Domain(
        asset_id=asset.id,
        project_id=project.id,
        parent_id=parent.id if parent is not None else None,
        fqdn=normalized,
        registrable_domain=registrable,
        tld=normalized.rsplit(".", 1)[-1],
        is_apex=normalized == registrable,
    )
    session.add(domain)
    session.flush()
    return domain


def ensure_ip_address(
    session: Session,
    project: Project,
    address: str,
    *,
    source: str,
    observed_at: datetime | None = None,
    scan_job_id: uuid.UUID | None = None,
) -> IpAddress:
    """Upsert an IP asset and its classification flags."""

    parsed = ipaddress.ip_address(address.strip())
    canonical = str(parsed)
    classified = classify_address(parsed)

    upsert = upsert_asset(
        session,
        project,
        kind=AssetKind.IP_ADDRESS,
        key=canonical,
        source=source,
        observed_at=observed_at,
        label=canonical,
        scan_job_id=scan_job_id,
    )
    asset = upsert.asset

    ip = session.scalar(select(IpAddress).where(IpAddress.asset_id == asset.id))
    if ip is not None:
        return ip

    ip = IpAddress(
        asset_id=asset.id,
        project_id=project.id,
        address=canonical,
        version=parsed.version,
        is_private=classified
        in {
            AddressClass.PRIVATE,
            AddressClass.LOOPBACK,
            AddressClass.LINK_LOCAL,
        },
        is_reserved=classified in {AddressClass.RESERVED, AddressClass.DOCUMENTATION},
        is_global=parsed.is_global,
    )
    session.add(ip)
    session.flush()
    return ip


def upsert_dns_record(
    session: Session,
    domain: Domain,
    *,
    record_type: DnsRecordType,
    value: str,
    source: str,
    observed_at: datetime | None = None,
    ttl: int | None = None,
    priority: int | None = None,
) -> tuple[DnsRecord, bool]:
    """Record one DNS answer. Returns ``(record, created)``."""

    moment = ensure_utc(observed_at or utcnow())
    record = session.scalar(
        select(DnsRecord).where(
            DnsRecord.domain_id == domain.id,
            DnsRecord.record_type == record_type,
            DnsRecord.value == value,
        )
    )

    if record is None:
        record = DnsRecord(
            domain_id=domain.id,
            project_id=domain.project_id,
            record_type=record_type,
            value=value,
            ttl=ttl,
            priority=priority,
            source=source,
            is_active=True,
            first_seen=moment,
            last_seen=moment,
        )
        session.add(record)
        session.flush()
        return record, True

    record.first_seen, record.last_seen = merge_observation_window(
        record.first_seen, record.last_seen, moment
    )
    record.is_active = True
    if ttl is not None:
        record.ttl = ttl
    if priority is not None:
        record.priority = priority
    session.flush()
    return record, False


def upsert_service(
    session: Session,
    project: Project,
    asset: Asset,
    *,
    port: int,
    transport: str,
    protocol: str | None,
    state: ServiceState,
    tls_enabled: bool,
    tls_version: str | None,
    banner: str | None,
    source: str,
    observed_at: datetime | None = None,
) -> tuple[Service, bool]:
    """Record a service observed on a host, widening its observation window."""

    moment = ensure_utc(observed_at or utcnow())
    service = session.scalar(
        select(Service).where(
            Service.asset_id == asset.id,
            Service.port == port,
            Service.transport == transport,
        )
    )
    if service is None:
        service = Service(
            asset_id=asset.id,
            project_id=project.id,
            port=port,
            transport=transport,
            protocol=protocol,
            state=state,
            tls_enabled=tls_enabled,
            tls_version=tls_version,
            banner=banner,
            source=source,
            first_seen=moment,
            last_seen=moment,
        )
        session.add(service)
        session.flush()
        return service, True

    service.first_seen, service.last_seen = merge_observation_window(
        service.first_seen, service.last_seen, moment
    )
    service.state = state
    service.tls_enabled = tls_enabled
    if protocol:
        service.protocol = protocol
    if tls_version:
        service.tls_version = tls_version
    if banner:
        service.banner = banner
    session.flush()
    return service, False


def retire_dns_records(
    session: Session,
    domain: Domain,
    *,
    checked_types: set[DnsRecordType],
    seen: set[tuple[DnsRecordType, str]],
    observed_at: datetime | None = None,
) -> list[DnsRecord]:
    """Deactivate records of *successfully queried* types that no longer appear.

    ``checked_types`` is the safety valve: a record type whose lookup errored is
    never retired, because "we could not ask" is not the same as "it is gone".
    """

    del observed_at  # the window stays as last observed; no timestamp is invented
    if not checked_types:
        return []

    candidates = session.scalars(
        select(DnsRecord).where(
            DnsRecord.domain_id == domain.id,
            DnsRecord.is_active.is_(True),
        )
    )
    retired: list[DnsRecord] = []
    for record in candidates:
        if record.record_type not in checked_types:
            continue
        if (record.record_type, record.value) in seen:
            continue
        record.is_active = False
        retired.append(record)
    if retired:
        session.flush()
    return retired
