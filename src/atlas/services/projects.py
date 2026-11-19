"""Project lifecycle."""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from atlas.db.enums import FindingStatus
from atlas.db.models import Asset, Finding, Project, ScopeRule, Target
from atlas.errors import ConflictError, NotFoundError, ValidationError
from atlas.services.audit import record_event

__all__ = [
    "create_project",
    "delete_project",
    "get_project",
    "list_projects",
    "project_stats",
    "slugify",
]

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    """ASCII slug. Raises when nothing usable remains."""

    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    slug = _SLUG_STRIP.sub("-", normalized.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)[:64].strip("-")
    if not slug:
        raise ValidationError(f"cannot derive a slug from {value!r}")
    return slug


def get_project(session: Session, slug: str) -> Project:
    project = session.scalar(select(Project).where(Project.slug == slug))
    if project is None:
        raise NotFoundError(f"project not found: {slug}", context={"slug": slug})
    return project


def list_projects(session: Session) -> list[Project]:
    return list(session.scalars(select(Project).order_by(Project.created_at)))


def create_project(
    session: Session,
    *,
    name: str,
    slug: str | None = None,
    description: str | None = None,
    retention_days: int | None = None,
    actor: str = "cli",
) -> Project:
    resolved_slug = slug or slugify(name)
    if session.scalar(select(Project).where(Project.slug == resolved_slug)) is not None:
        raise ConflictError(
            f"project already exists: {resolved_slug}", context={"slug": resolved_slug}
        )

    project = Project(
        slug=resolved_slug,
        name=name.strip() or resolved_slug,
        description=description,
        retention_days=retention_days if retention_days is not None else 180,
    )
    session.add(project)
    session.flush()
    record_event(
        session,
        action="project.create",
        project_id=project.id,
        actor=actor,
        object_type="project",
        object_id=str(project.id),
        detail={"slug": project.slug, "name": project.name},
    )
    return project


def delete_project(session: Session, slug: str, *, actor: str = "cli") -> None:
    project = get_project(session, slug)
    record_event(
        session,
        action="project.delete",
        project_id=None,  # the row disappears with the project
        actor=actor,
        object_type="project",
        object_id=str(project.id),
        detail={"slug": project.slug},
    )
    session.delete(project)
    session.flush()


def project_stats(session: Session, project: Project) -> dict[str, int]:
    """Cheap counters for CLI/API project detail views."""

    def count(statement: Select[Any]) -> int:
        return int(session.scalar(statement) or 0)

    open_findings = count(
        select(func.count(Finding.id)).where(
            Finding.project_id == project.id,
            Finding.status == FindingStatus.OPEN,
        )
    )
    return {
        "scope_rules": count(
            select(func.count(ScopeRule.id)).where(ScopeRule.project_id == project.id)
        ),
        "targets": count(select(func.count(Target.id)).where(Target.project_id == project.id)),
        "assets": count(select(func.count(Asset.id)).where(Asset.project_id == project.id)),
        "findings": count(select(func.count(Finding.id)).where(Finding.project_id == project.id)),
        "open_findings": open_findings,
    }
