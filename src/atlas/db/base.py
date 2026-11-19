"""Declarative base, naming conventions and shared column mixins."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from atlas.core.time import utcnow

__all__ = ["Base", "TimestampMixin", "utc_now", "uuid_pk"]

# Deterministic constraint names keep Alembic autogenerate diffs stable.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def to_dict(self, *, exclude: set[str] | None = None) -> dict[str, Any]:
        """Shallow column dump, used by CLI/API serialisers and tests."""

        skip = exclude or set()
        return {
            column.key: getattr(self, column.key)
            for column in self.__table__.columns
            if column.key not in skip
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        identifier = getattr(self, "id", None)
        return f"<{type(self).__name__} id={identifier}>"


def uuid_pk() -> Mapped[uuid.UUID]:
    """UUIDv4 primary key column. Portable across PostgreSQL and SQLite."""

    return mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


def utc_now() -> datetime:
    """Client-side UTC default so SQLite returns aware datetimes too."""

    return utcnow()


class TimestampMixin:
    """``created_at`` / ``updated_at`` maintained by the ORM."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
