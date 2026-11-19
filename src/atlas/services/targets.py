"""Target normalization and persistence.

A *target* is a named root an operator asked to collect. It is created only after
the scope gate has permitted it, and its ``scope_rule_id`` points at the rule
that permitted it — authorization is a property of the row, not of the request.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.db.enums import ScopeKind, TargetKind
from atlas.db.models import Project, Target
from atlas.errors import ValidationError
from atlas.scope.normalize import (
    infer_scope_kind,
    normalize_cidr,
    normalize_domain,
    normalize_ip,
    normalize_url,
)

__all__ = ["ResolvedTarget", "resolve_target", "upsert_target"]

_KIND_MAP: dict[ScopeKind, TargetKind] = {
    ScopeKind.DOMAIN: TargetKind.DOMAIN,
    ScopeKind.IP: TargetKind.IP,
    ScopeKind.CIDR: TargetKind.CIDR,
    ScopeKind.URL: TargetKind.URL,
}


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """A submitted value, classified and normalized once."""

    kind: TargetKind
    value: str
    normalized: str
    collection_value: str
    """What collectors should be pointed at (the host for URL targets)."""


def resolve_target(value: str) -> ResolvedTarget:
    """Classify and normalize an operator-supplied target string."""

    candidate = value.strip()
    if not candidate:
        raise ValidationError("target must not be empty")

    kind = _KIND_MAP[infer_scope_kind(candidate)]

    match kind:
        case TargetKind.DOMAIN:
            normalized = normalize_domain(candidate)
            collection_value = normalized
        case TargetKind.IP:
            normalized = normalize_ip(candidate)
            collection_value = normalized
        case TargetKind.CIDR:
            normalized = normalize_cidr(candidate)
            collection_value = normalized
        case TargetKind.URL:
            normalized = normalize_url(candidate)
            host = urlsplit(normalized).hostname
            if not host:
                raise ValidationError(f"URL target has no host: {value!r}")
            collection_value = normalize_domain(host)
        case _:  # pragma: no cover - the enum is closed
            raise ValidationError(f"unsupported target kind: {kind}")

    return ResolvedTarget(
        kind=kind, value=candidate, normalized=normalized, collection_value=collection_value
    )


def upsert_target(
    session: Session,
    project: Project,
    resolved: ResolvedTarget,
    *,
    scope_rule_id: uuid.UUID | None = None,
    notes: str | None = None,
) -> Target:
    """Create the target row, or reactivate the existing one."""

    target = session.scalar(
        select(Target).where(
            Target.project_id == project.id,
            Target.kind == resolved.kind,
            Target.normalized == resolved.normalized,
        )
    )
    if target is not None:
        target.value = resolved.value
        target.is_active = True
        # Re-authorization may come from a different rule; keep the row honest.
        if scope_rule_id is not None:
            target.scope_rule_id = scope_rule_id
        if notes:
            target.notes = notes
        session.flush()
        return target

    target = Target(
        project_id=project.id,
        scope_rule_id=scope_rule_id,
        kind=resolved.kind,
        value=resolved.value,
        normalized=resolved.normalized,
        is_active=True,
        notes=notes,
    )
    session.add(target)
    session.flush()
    return target
