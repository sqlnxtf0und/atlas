"""Observation persistence: identity, observation windows, and honest retirement."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.core.time import ensure_utc, utcnow
from atlas.db.enums import AssetKind, DnsRecordType
from atlas.db.models import Asset, DnsRecord, Domain, IpAddress, Project
from atlas.services.observations import (
    ensure_domain,
    ensure_ip_address,
    merge_observation_window,
    retire_dns_records,
    upsert_asset,
    upsert_dns_record,
)


def test_asset_is_created_then_only_refreshed(session: Session, project: Project) -> None:
    first = utcnow() - timedelta(days=3)
    created = upsert_asset(
        session,
        project,
        kind=AssetKind.DOMAIN,
        key="api.example.com",
        source="dns",
        observed_at=first,
    )
    assert created.created is True
    assert ensure_utc(created.asset.first_seen) == ensure_utc(first)
    assert ensure_utc(created.asset.last_seen) == ensure_utc(first)

    later = utcnow()
    again = upsert_asset(
        session,
        project,
        kind=AssetKind.DOMAIN,
        key="api.example.com",
        source="dns",
        observed_at=later,
    )
    assert again.created is False
    assert again.asset.id == created.asset.id
    assert ensure_utc(again.asset.last_seen) == ensure_utc(later)
    assert ensure_utc(again.asset.first_seen) == ensure_utc(first)


def test_confidence_never_downgrades_and_timestamps_never_move_backwards(
    session: Session, project: Project
) -> None:
    now = utcnow()
    upsert_asset(
        session,
        project,
        kind=AssetKind.DOMAIN,
        key="example.com",
        source="dns",
        confidence=0.9,
        observed_at=now,
    )
    older = upsert_asset(
        session,
        project,
        kind=AssetKind.DOMAIN,
        key="example.com",
        source="dns",
        confidence=0.4,
        observed_at=now - timedelta(days=5),
    )
    assert older.asset.confidence == pytest.approx(0.9)
    assert ensure_utc(older.asset.last_seen) == ensure_utc(now)


def test_invalid_confidence_is_refused(session: Session, project: Project) -> None:
    with pytest.raises(ValueError):
        upsert_asset(
            session,
            project,
            kind=AssetKind.DOMAIN,
            key="example.com",
            source="dns",
            confidence=1.5,
        )


def test_merge_window() -> None:
    now = utcnow()
    first, last = merge_observation_window(now, now, now + timedelta(hours=1))
    assert first == now
    assert last == now + timedelta(hours=1)
    first, last = merge_observation_window(now, now, now - timedelta(hours=1))
    assert first == now - timedelta(hours=1)
    assert last == now


def test_domain_detail_and_apex_flag(session: Session, project: Project) -> None:
    apex = ensure_domain(session, project, "example.com", source="dns")
    sub = ensure_domain(session, project, "api.example.com", source="dns")

    assert apex.is_apex is True
    assert apex.registrable_domain == "example.com"
    assert apex.tld == "com"
    assert sub.is_apex is False
    assert sub.registrable_domain == "example.com"
    assert sub.parent_id == apex.id


def test_domain_upsert_is_idempotent(session: Session, project: Project) -> None:
    first = ensure_domain(session, project, "example.com", source="dns")
    second = ensure_domain(session, project, "EXAMPLE.COM.", source="dns")
    assert first.id == second.id
    assert session.scalar(select(Asset).where(Asset.kind == AssetKind.DOMAIN).limit(2)) is not None
    assert len(list(session.scalars(select(Domain)))) == 1


def test_multi_label_suffix_registrable_domain(session: Session, project: Project) -> None:
    domain = ensure_domain(session, project, "shop.example.co.uk", source="dns")
    assert domain.registrable_domain == "example.co.uk"
    assert domain.is_apex is False


def test_ip_classification_flags(session: Session, project: Project) -> None:
    public = ensure_ip_address(session, project, "203.0.113.10", source="dns")
    private = ensure_ip_address(session, project, "10.0.0.5", source="dns")

    assert public.address == "203.0.113.10"
    assert public.version == 4
    assert public.is_global is False  # documentation range is not globally routable
    assert private.is_private is True
    assert private.is_global is False


def test_ip_is_idempotent(session: Session, project: Project) -> None:
    first = ensure_ip_address(session, project, "203.0.113.10", source="dns")
    second = ensure_ip_address(session, project, "203.0.113.10", source="dns")
    assert first.id == second.id
    assert len(list(session.scalars(select(IpAddress)))) == 1


def test_dns_record_window_and_refresh(session: Session, project: Project) -> None:
    domain = ensure_domain(session, project, "example.com", source="dns")
    first_at = utcnow() - timedelta(days=2)
    record, created = upsert_dns_record(
        session,
        domain,
        record_type=DnsRecordType.A,
        value="203.0.113.10",
        source="dns",
        observed_at=first_at,
        ttl=300,
    )
    assert created is True

    again, created_again = upsert_dns_record(
        session,
        domain,
        record_type=DnsRecordType.A,
        value="203.0.113.10",
        source="dns",
        observed_at=utcnow(),
        ttl=600,
    )
    assert created_again is False
    assert again.id == record.id
    assert again.ttl == 600
    assert ensure_utc(again.first_seen) == ensure_utc(first_at)
    assert ensure_utc(again.last_seen) > ensure_utc(first_at)


def test_retirement_only_touches_checked_types(session: Session, project: Project) -> None:
    domain = ensure_domain(session, project, "example.com", source="dns")
    upsert_dns_record(
        session, domain, record_type=DnsRecordType.A, value="203.0.113.10", source="dns"
    )
    mx, _ = upsert_dns_record(
        session, domain, record_type=DnsRecordType.MX, value="mail.example.com", source="dns"
    )

    retired = retire_dns_records(
        session,
        domain,
        checked_types={DnsRecordType.A},
        seen=set(),
    )

    assert [r.record_type for r in retired] == [DnsRecordType.A]
    assert retired[0].is_active is False
    # MX was never checked, so it must stay active.
    assert session.get(DnsRecord, mx.id).is_active is True


def test_retirement_is_a_noop_without_checked_types(session: Session, project: Project) -> None:
    domain = ensure_domain(session, project, "example.com", source="dns")
    upsert_dns_record(
        session, domain, record_type=DnsRecordType.A, value="203.0.113.10", source="dns"
    )
    assert retire_dns_records(session, domain, checked_types=set(), seen=set()) == []
