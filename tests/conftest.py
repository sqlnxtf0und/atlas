"""Shared test fixtures.

The suite runs against SQLite. Every test gets its own schema in a temporary
file; the session fixture wraps each test in a transaction that is rolled back.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from atlas.config import Settings, load_settings
from atlas.db.base import Base
from atlas.db.models import Project
from atlas.db.session import build_engine
from atlas.services.projects import create_project


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    database = tmp_path / "atlas-test.db"
    return load_settings(
        database={"url": f"sqlite+pysqlite:///{database}", "echo": False},
        logging={"level": "warning", "json": False},
        environment="test",
    )


@pytest.fixture
def engine(settings: Settings) -> Iterator[Engine]:
    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    connection = engine.connect()
    transaction = connection.begin()
    factory = sessionmaker(bind=connection, autoflush=False, expire_on_commit=False)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def project(session: Session) -> Project:
    project = create_project(session, name="Test Project", slug="test")
    session.commit()
    return project
