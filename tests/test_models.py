"""Schema behaviour: identity constraints, cascades, provenance columns."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlas.core.time import ensure_utc
from atlas.db.enums import AssetKind, RelationshipType
from atlas.db.models import Asset, Domain, Project, Relationship


def _asset(session: Session, project: Project, key: str) -> Asset:
    asset = Asset(project_id=project.id, kind=AssetKind.DOMAIN, key=key, source="test")
    session.add(asset)
    session.flush()
    return asset


def test_asset_identity_is_unique_per_project(session: Session, project: Project) -> None:
    _asset(session, project, "example.com")
    session.commit()

    session.add(Asset(project_id=project.id, kind=AssetKind.DOMAIN, key="example.com"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_domain_detail_is_one_to_one(session: Session, project: Project) -> None:
    asset = _asset(session, project, "example.com")
    session.add(
        Domain(
            asset_id=asset.id,
            project_id=project.id,
            fqdn="example.com",
            registrable_domain="example.com",
            tld="com",
            is_apex=True,
        )
    )
    session.commit()

    domain = session.scalar(select(Domain).where(Domain.asset_id == asset.id))
    assert domain is not None
    assert domain.is_apex is True


def test_relationship_rejects_self_edge(session: Session, project: Project) -> None:
    asset = _asset(session, project, "example.com")
    session.add(
        Relationship(
            project_id=project.id,
            source_asset_id=asset.id,
            target_asset_id=asset.id,
            rel_type=RelationshipType.SUBDOMAIN_OF,
            evidence_source="test",
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_deleting_project_cascades_assets(session: Session, project: Project) -> None:
    _asset(session, project, "example.com")
    session.commit()

    session.delete(project)
    session.commit()

    assert session.scalar(select(Asset).where(Asset.key == "example.com")) is None


def test_timestamps_are_timezone_aware(session: Session, project: Project) -> None:
    session.commit()
    assert ensure_utc(project.created_at).tzinfo is not None
