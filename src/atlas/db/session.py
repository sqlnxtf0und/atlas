"""Engine and session management.

Production uses PostgreSQL. SQLite is supported for development and the test
suite (with foreign keys enforced and a shared in-memory database when the URL
is ``sqlite+pysqlite:///:memory:``).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atlas.config import Settings, get_settings
from atlas.db.base import Base
from atlas.errors import DatabaseError
from atlas.logging import get_logger

__all__ = [
    "build_engine",
    "build_session_factory",
    "create_all",
    "get_engine",
    "get_session_factory",
    "ping",
    "reset_engine_cache",
    "session_scope",
]

log = get_logger("db.session")


def _engine_kwargs(settings: Settings) -> dict[str, Any]:
    url = settings.database.url
    if settings.database.is_sqlite:
        kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        return kwargs
    return {
        "pool_size": settings.database.pool_size,
        "max_overflow": settings.database.max_overflow,
        "pool_timeout": settings.database.pool_timeout,
        "pool_recycle": settings.database.pool_recycle,
        "pool_pre_ping": True,
    }


def build_engine(settings: Settings | None = None) -> Engine:
    """Create a new engine. Callers own its lifecycle."""

    resolved = settings or get_settings()
    try:
        engine = create_engine(
            resolved.database.url,
            echo=resolved.database.echo,
            future=True,
            **_engine_kwargs(resolved),
        )
    except SQLAlchemyError as exc:  # pragma: no cover - driver-level failure
        raise DatabaseError(f"cannot create engine: {exc}") from exc

    if resolved.database.is_sqlite:
        _install_sqlite_pragmas(engine)
    return engine


def _install_sqlite_pragmas(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection: Any, _record: Any) -> None:  # pragma: no cover
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


@lru_cache(maxsize=1)
def _cached_engine() -> Engine:
    return build_engine(get_settings())


@lru_cache(maxsize=1)
def _cached_factory() -> sessionmaker[Session]:
    return build_session_factory(_cached_engine())


def get_engine() -> Engine:
    """Process-wide engine built from the cached settings."""

    return _cached_engine()


def get_session_factory() -> sessionmaker[Session]:
    return _cached_factory()


def reset_engine_cache() -> None:
    """Dispose the cached engine and clear the caches (tests, ``atlas init``)."""

    if _cached_engine.cache_info().currsize:
        _cached_engine().dispose()
    _cached_factory.cache_clear()
    _cached_engine.cache_clear()


@contextmanager
def session_scope(factory: sessionmaker[Session] | None = None) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any exception."""

    session = (factory or get_session_factory())()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def create_all(engine: Engine) -> None:
    """Create every table. Development and tests only — production uses Alembic."""

    Base.metadata.create_all(bind=engine)


def ping(engine: Engine | None = None) -> None:
    """Raise :class:`DatabaseError` when the database is unreachable."""

    target = engine or get_engine()
    try:
        with target.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise DatabaseError(f"database is not reachable: {exc}") from exc
