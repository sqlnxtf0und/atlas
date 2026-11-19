"""Scope rule management and evaluation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from atlas.config import Settings
from atlas.core.time import utcnow
from atlas.db.enums import ScopeKind, ScopeMode
from atlas.db.models import Project, ScopeRule
from atlas.errors import ConflictError, NotFoundError, ValidationError
from atlas.scope.matcher import ScopeDecision, ScopeRuleSpec, ScopeSet
from atlas.scope.normalize import normalize_pattern
from atlas.scope.policy import NetworkPolicy
from atlas.services.audit import record_event

__all__ = [
    "add_rule",
    "build_scope_set",
    "check_value",
    "list_rules",
    "remove_rules",
]


def add_rule(
    session: Session,
    project: Project,
    *,
    pattern: str,
    kind: ScopeKind | None = None,
    mode: ScopeMode = ScopeMode.INCLUDE,
    include_subdomains: bool = True,
    note: str | None = None,
    expires_at: datetime | None = None,
    actor: str = "cli",
) -> ScopeRule:
    """Validate, normalize and persist one scope rule."""

    wildcard = pattern.strip().startswith("*.")
    resolved_kind, normalized = normalize_pattern(pattern, kind)
    if wildcard and resolved_kind is ScopeKind.DOMAIN:
        include_subdomains = True
    if resolved_kind is not ScopeKind.DOMAIN:
        include_subdomains = False

    if expires_at is not None and expires_at <= utcnow():
        raise ValidationError("expiry must be in the future")

    existing = session.scalar(
        select(ScopeRule).where(
            ScopeRule.project_id == project.id,
            ScopeRule.kind == resolved_kind,
            ScopeRule.pattern == normalized,
            ScopeRule.mode == mode,
        )
    )
    if existing is not None:
        raise ConflictError(
            f"scope rule already exists: {mode.value} {resolved_kind.value} {normalized}",
            context={"rule_id": str(existing.id)},
        )

    rule = ScopeRule(
        project_id=project.id,
        kind=resolved_kind,
        pattern=normalized,
        raw_pattern=pattern.strip(),
        mode=mode,
        include_subdomains=include_subdomains,
        note=note,
        expires_at=expires_at,
        created_by=actor,
    )
    session.add(rule)
    session.flush()
    record_event(
        session,
        action="scope.add",
        project_id=project.id,
        actor=actor,
        object_type="scope_rule",
        object_id=str(rule.id),
        detail={
            "kind": resolved_kind.value,
            "pattern": normalized,
            "mode": mode.value,
            "include_subdomains": include_subdomains,
        },
    )
    return rule


def list_rules(
    session: Session, project: Project, *, include_inactive: bool = False
) -> list[ScopeRule]:
    statement = select(ScopeRule).where(ScopeRule.project_id == project.id)
    if not include_inactive:
        statement = statement.where(ScopeRule.is_active.is_(True))
    return list(
        session.scalars(statement.order_by(ScopeRule.mode, ScopeRule.kind, ScopeRule.pattern))
    )


def remove_rules(
    session: Session,
    project: Project,
    *,
    pattern: str | None = None,
    kind: ScopeKind | None = None,
    mode: ScopeMode | None = None,
    actor: str = "cli",
) -> int:
    """Delete matching rules. Returns the number removed; zero is an error."""

    statement = delete(ScopeRule).where(ScopeRule.project_id == project.id)
    if pattern is not None:
        resolved_kind, normalized = normalize_pattern(pattern, kind)
        statement = statement.where(
            ScopeRule.pattern == normalized, ScopeRule.kind == resolved_kind
        )
    elif kind is not None:
        statement = statement.where(ScopeRule.kind == kind)
    if mode is not None:
        statement = statement.where(ScopeRule.mode == mode)

    result = session.execute(statement)
    removed = int(getattr(result, "rowcount", 0) or 0)
    if removed == 0:
        raise NotFoundError("no matching scope rule")
    record_event(
        session,
        action="scope.remove",
        project_id=project.id,
        actor=actor,
        object_type="scope_rule",
        detail={"pattern": pattern, "kind": kind.value if kind else None, "removed": removed},
    )
    return removed


def build_scope_set(
    session: Session, project: Project, settings: Settings, *, now: datetime | None = None
) -> ScopeSet:
    """Load every rule for the project into a matcher instance."""

    rules = list_rules(session, project, include_inactive=True)
    specs = [ScopeRuleSpec.from_orm(rule) for rule in rules]
    policy = NetworkPolicy.from_settings(settings)
    return ScopeSet.from_rules(specs, policy=policy, now=now)


def check_value(
    session: Session,
    project: Project,
    settings: Settings,
    value: str,
    *,
    actor: str = "cli",
    audit: bool = True,
) -> ScopeDecision:
    """Evaluate a value and audit the decision when it is a denial."""

    scope = build_scope_set(session, project, settings)
    decision = scope.check(value)
    if audit and not decision.permitted:
        record_event(
            session,
            action="scope.deny",
            project_id=project.id,
            actor=actor,
            object_type="scope_check",
            object_id=value[:64],
            outcome="denied",
            detail=decision.as_dict(),
        )
    return decision


def summarize(rule: ScopeRule) -> dict[str, Any]:
    return {
        "id": str(rule.id),
        "kind": rule.kind.value,
        "pattern": rule.pattern,
        "mode": rule.mode.value,
        "include_subdomains": rule.include_subdomains,
        "is_active": rule.is_active,
        "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
        "note": rule.note,
    }
