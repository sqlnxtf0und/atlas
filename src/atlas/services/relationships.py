"""Relationship persistence primitive.

Correlation *rules* live in Phase 4. This module only knows how to write an edge
correctly: one row per ``(source, target, rel_type)``, an observation window that
never narrows, a confidence that never silently degrades, and an evidence source
that is always recorded.

A ``SHARES_CERTIFICATE`` or ``SHARES_ADDRESS`` edge is a *shared-infrastructure*
observation. It is never evidence of common ownership, and the attributes dict
says so explicitly so no presentation layer can imply otherwise.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.core.time import ensure_utc, utcnow
from atlas.db.enums import RelationshipType
from atlas.db.models import Asset, Project, Relationship
from atlas.services.observations import merge_observation_window

__all__ = ["SHARED_INFRASTRUCTURE_TYPES", "upsert_relationship"]

#: Edge types that indicate shared infrastructure, never shared ownership.
SHARED_INFRASTRUCTURE_TYPES: frozenset[RelationshipType] = frozenset(
    {
        RelationshipType.SHARES_CERTIFICATE,
        RelationshipType.SHARES_ADDRESS,
        RelationshipType.SHARES_NAMESERVER,
    }
)


def upsert_relationship(
    session: Session,
    project: Project,
    *,
    source: Asset,
    target: Asset,
    rel_type: RelationshipType,
    evidence_source: str,
    confidence: float,
    observed_at: datetime | None = None,
    attributes: dict[str, Any] | None = None,
) -> tuple[Relationship, bool]:
    """Create or refresh one edge. Returns ``(relationship, created)``."""

    if source.id == target.id:
        raise ValueError("a relationship cannot point at its own source")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")

    moment = ensure_utc(observed_at or utcnow())
    edge = session.scalar(
        select(Relationship).where(
            Relationship.project_id == project.id,
            Relationship.source_asset_id == source.id,
            Relationship.target_asset_id == target.id,
            Relationship.rel_type == rel_type,
        )
    )

    if edge is None:
        edge = Relationship(
            project_id=project.id,
            source_asset_id=source.id,
            target_asset_id=target.id,
            rel_type=rel_type,
            evidence_source=evidence_source,
            confidence=confidence,
            first_observed=moment,
            last_observed=moment,
            attributes=dict(attributes or {}),
        )
        session.add(edge)
        session.flush()
        return edge, True

    edge.first_observed, edge.last_observed = merge_observation_window(
        edge.first_observed, edge.last_observed, moment
    )
    edge.confidence = max(edge.confidence, confidence)
    if attributes:
        merged = dict(edge.attributes or {})
        merged.update(attributes)
        edge.attributes = merged
    session.flush()
    return edge, False
