"""Workspace bootstrap: configuration file, schema migration, default project."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import atlas
from atlas.config import Settings
from atlas.db.session import build_engine, build_session_factory, session_scope
from atlas.errors import ConfigurationError, DatabaseError, NotFoundError
from atlas.logging import get_logger
from atlas.services.projects import create_project, get_project

__all__ = ["config_template", "init_workspace", "migrations_dir", "run_migrations", "write_config"]

log = get_logger("services.bootstrap")

CONFIG_TEMPLATE = """\
# ATLAS configuration
# Environment variables (ATLAS_*) override anything set here.
environment: development
instance_name: atlas

database:
  url: "{db_url}"
  echo: false
  pool_size: 10
  max_overflow: 20

security:
  # Scope enforcement is mandatory. Collection against an unauthorized target
  # is refused before a socket is opened.
  require_scope: true
  # Private / loopback / link-local address space is refused by default (SSRF guard).
  allow_private_addresses: false
  dns_rebinding_protection: true
  max_resolved_addresses: 16

collector:
  user_agent: "ATLAS/0.1 (+authorized-security-assessment)"
  connect_timeout: 5
  read_timeout: 10
  total_timeout: 30
  requests_per_second: 5
  per_host_concurrency: 2
  global_concurrency: 10
  max_body_bytes: 2097152
  max_redirects: 5
  max_retries: 2
  job_deadline_seconds: 900

api:
  host: 127.0.0.1
  port: 8000
  docs_enabled: true

celery:
  broker_url: "redis://localhost:6379/0"
  result_backend: "redis://localhost:6379/1"

graph:
  backend: networkx

reports:
  output_dir: "./reports"
  pdf_enabled: false

retention:
  default_days: 180
  keep_snapshots: 52
"""


def config_template(db_url: str) -> str:
    return CONFIG_TEMPLATE.format(db_url=db_url)


def write_config(path: Path, *, db_url: str, force: bool = False) -> Path:
    """Write the YAML config. Refuses to overwrite without ``force``."""

    target = Path(path).expanduser()
    if target.exists() and not force:
        raise ConfigurationError(
            f"configuration already exists: {target} (pass --force to overwrite)"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(config_template(db_url), encoding="utf-8")
    return target


def migrations_dir() -> Path:
    """Absolute path to the packaged Alembic environment."""

    return Path(atlas.__file__).resolve().parent / "migrations"


def run_migrations(settings: Settings) -> None:
    """Apply ``alembic upgrade head`` programmatically."""

    try:
        from alembic import command
        from alembic.config import Config
    except ImportError as exc:  # pragma: no cover - dependency is pinned
        raise DatabaseError("alembic is not installed; cannot migrate the schema") from exc

    directory = migrations_dir()
    if not directory.is_dir():  # pragma: no cover - packaging error
        raise DatabaseError(f"migration environment missing at {directory}")

    config = Config()
    config.set_main_option("script_location", str(directory))
    config.set_main_option("sqlalchemy.url", settings.database.url)
    try:
        command.upgrade(config, "head")
    except Exception as exc:  # alembic raises its own exception types
        raise DatabaseError(f"schema migration failed: {exc}") from exc


def init_workspace(
    settings: Settings,
    *,
    config_path: Path | None = None,
    force: bool = False,
    create_default_project: bool = True,
    actor: str = "cli",
) -> dict[str, Any]:
    """Full first-run bootstrap. Returns a summary dict for the CLI to render."""

    summary: dict[str, Any] = {
        "config_path": None,
        "database_url": settings.database.url,
        "migrated": False,
        "project": None,
        "project_created": False,
    }

    if config_path is not None:
        written = write_config(config_path, db_url=settings.database.url, force=force)
        summary["config_path"] = str(written)
        log.info("wrote configuration", extra={"atlas": {"path": str(written)}})

    run_migrations(settings)
    summary["migrated"] = True

    if create_default_project:
        engine = build_engine(settings)
        factory = build_session_factory(engine)
        try:
            with session_scope(factory) as session:
                try:
                    project = get_project(session, "default")
                except NotFoundError:
                    project = create_project(
                        session,
                        name="Default Project",
                        slug="default",
                        description="Created by atlas init",
                        retention_days=settings.retention.default_days,
                        actor=actor,
                    )
                    summary["project_created"] = True
                summary["project"] = project.slug
        finally:
            engine.dispose()

    return summary
