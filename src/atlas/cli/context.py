"""CLI application context.

Holds the resolved settings, output mode and lazily-built database engine for the
duration of one invocation. A module-level context variable lets the error
boundary in :mod:`atlas.cli.main` render failures in the same mode as the command.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from atlas.config import Settings
from atlas.db.models import Project
from atlas.db.session import build_engine, build_session_factory, session_scope
from atlas.services.projects import get_project

__all__ = ["AppContext", "current_context", "set_context"]


@dataclass
class AppContext:
    settings: Settings
    console: Console
    error_console: Console
    json_output: bool = False
    project_slug: str = "default"
    actor: str = "cli"
    config_path: Path | None = None
    _engine: Engine | None = field(default=None, init=False, repr=False)
    _factory: sessionmaker[Session] | None = field(default=None, init=False, repr=False)

    @property
    def engine(self) -> Engine:
        if self._engine is None:
            self._engine = build_engine(self.settings)
        return self._engine

    @property
    def session_factory(self) -> sessionmaker[Session]:
        if self._factory is None:
            self._factory = build_session_factory(self.engine)
        return self._factory

    @contextmanager
    def session(self) -> Iterator[Session]:
        with session_scope(self.session_factory) as session:
            yield session

    def project(self, session: Session) -> Project:
        return get_project(session, self.project_slug)

    def close(self) -> None:
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None
        self._factory = None


_current: ContextVar[AppContext | None] = ContextVar("atlas_cli_context", default=None)


def set_context(context: AppContext | None) -> None:
    _current.set(context)


def current_context() -> AppContext | None:
    return _current.get()
