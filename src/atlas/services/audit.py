"""Append-only audit trail.

Every mutating operation in the CLI and (from Phase 8) the API records an event.
Denied scope decisions are recorded too: a refusal is evidence.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.db.models import AuditEvent

__all__ = ["list_events", "record_event"]


def record_event(
    session: Session,
    *,
    action: str,
    project_id: uuid.UUID | None = None,
    actor: str = "cli",
    object_type: str | None = None,
    object_id: str | None = None,
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditEvent:
    """Append one audit row. The caller's transaction owns the commit."""

    event = AuditEvent(
        project_id=project_id,
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=object_id,
        outcome=outcome,
        detail=dict(detail or {}),
        ip_address=ip_address,
        user_agent=user_agent,
    )
    session.add(event)
    session.flush()
    return event


def list_events(
    session: Session,
    *,
    project_id: uuid.UUID | None = None,
    action: str | None = None,
    limit: int = 50,
) -> list[AuditEvent]:
    statement = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    if project_id is not None:
        statement = statement.where(AuditEvent.project_id == project_id)
    if action is not None:
        statement = statement.where(AuditEvent.action == action)
    return list(session.scalars(statement))
