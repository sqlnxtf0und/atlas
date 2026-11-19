"""Configuration loading and validation.

Precedence, highest first:

1. Explicit constructor arguments (tests, embedded use).
2. Environment variables (``ATLAS_*``, nested with ``__``).
3. ``.env`` file in the working directory.
4. YAML configuration file (``--config``, ``ATLAS_CONFIG``, ``./atlas.yaml``,
   ``~/.config/atlas/atlas.yaml``).
5. Field defaults.

A malformed configuration raises :class:`atlas.errors.ConfigurationError` at load
time — the process never starts with a half-valid config.
"""

from __future__ import annotations

import os
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic import ValidationError as PydanticValidationError
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from atlas.errors import ConfigurationError

__all__ = [
    "ApiSettings",
    "CelerySettings",
    "CollectorSettings",
    "DatabaseSettings",
    "GraphSettings",
    "LoggingSettings",
    "MonitoringSettings",
    "ReportSettings",
    "RetentionSettings",
    "SecuritySettings",
    "Settings",
    "SourcesSettings",
    "get_settings",
    "load_settings",
    "reset_settings_cache",
]

CONFIG_ENV_VAR = "ATLAS_CONFIG"
DEFAULT_CONFIG_LOCATIONS: tuple[Path, ...] = (
    Path("atlas.yaml"),
    Path.home() / ".config" / "atlas" / "atlas.yaml",
)

_explicit_config_path: ContextVar[Path | None] = ContextVar(
    "atlas_explicit_config_path", default=None
)


def _candidate_paths() -> list[Path]:
    paths: list[Path] = []
    explicit = _explicit_config_path.get()
    if explicit is not None:
        paths.append(explicit)
    env_value = os.environ.get(CONFIG_ENV_VAR)
    if env_value:
        paths.append(Path(env_value).expanduser())
    paths.extend(DEFAULT_CONFIG_LOCATIONS)
    return paths


def resolve_config_path(explicit: Path | None = None) -> Path | None:
    """Return the first existing config file, or ``None`` when running on env only."""

    candidates = ([explicit] if explicit is not None else []) + _candidate_paths()
    for candidate in candidates:
        expanded = Path(candidate).expanduser()
        if expanded.is_file():
            return expanded.resolve()
    if explicit is not None:
        raise ConfigurationError(f"configuration file not found: {explicit}")
    return None


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DatabaseSettings(_Model):
    url: str = "sqlite+pysqlite:///./atlas.db"
    echo: bool = False
    pool_size: int = Field(default=10, ge=1, le=100)
    max_overflow: int = Field(default=20, ge=0, le=200)
    pool_timeout: float = Field(default=30.0, gt=0, le=300)
    pool_recycle: int = Field(default=1800, ge=0)

    @field_validator("url")
    @classmethod
    def _validate_scheme(cls, value: str) -> str:
        allowed = ("postgresql", "postgresql+psycopg", "sqlite", "sqlite+pysqlite")
        scheme = value.split("://", 1)[0].lower()
        if scheme not in allowed:
            raise ValueError(
                f"unsupported database scheme {scheme!r}; use postgresql+psycopg or sqlite+pysqlite"
            )
        return value

    @property
    def is_sqlite(self) -> bool:
        return self.url.startswith("sqlite")


class LoggingSettings(_Model):
    level: Literal["debug", "info", "warning", "error"] = "info"
    # ``json`` shadows ``BaseModel.json``; this model only ever reads fields, so
    # the collision is harmless at runtime and silenced here.
    json: bool = False  # type: ignore[assignment]
    redact_keys: tuple[str, ...] = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "private_key",
    )


class SecuritySettings(_Model):
    #: Scope enforcement is mandatory. The validator below refuses to boot with it off
    #: outside explicit development/test environments.
    require_scope: bool = True
    #: Private, loopback, link-local and reserved ranges are refused by default (SSRF guard).
    allow_private_addresses: bool = False
    #: Resolved addresses are re-validated after DNS and the request is pinned to them.
    dns_rebinding_protection: bool = True
    max_resolved_addresses: int = Field(default=16, ge=1, le=256)
    allowed_schemes: tuple[str, ...] = ("http", "https")
    api_key_header: str = "Authorization"

    @model_validator(mode="after")
    def _scope_required(self) -> SecuritySettings:
        if not self.require_scope and os.environ.get("ATLAS_ENVIRONMENT") not in {
            "development",
            "test",
        }:
            raise ValueError(
                "security.require_scope=false is only permitted in development or test"
            )
        return self


class CollectorSettings(_Model):
    user_agent: str = "ATLAS/0.1 (+authorized-security-assessment)"
    connect_timeout: float = Field(default=5.0, gt=0, le=60)
    read_timeout: float = Field(default=10.0, gt=0, le=120)
    total_timeout: float = Field(default=30.0, gt=0, le=300)
    requests_per_second: float = Field(default=5.0, gt=0, le=100)
    per_host_concurrency: int = Field(default=2, ge=1, le=16)
    global_concurrency: int = Field(default=10, ge=1, le=128)
    max_body_bytes: int = Field(default=2_097_152, ge=1024)
    max_redirects: int = Field(default=5, ge=0, le=20)
    max_retries: int = Field(default=2, ge=0, le=10)
    retry_backoff: float = Field(default=0.5, gt=0, le=30)
    job_deadline_seconds: int = Field(default=900, ge=10, le=86_400)


class ApiSettings(_Model):
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    root_path: str = ""
    cors_origins: tuple[str, ...] = ()
    docs_enabled: bool = True
    page_size_default: int = Field(default=50, ge=1, le=500)
    page_size_max: int = Field(default=500, ge=1, le=5000)


class CelerySettings(_Model):
    broker_url: str = "redis://localhost:6379/0"
    result_backend: str = "redis://localhost:6379/1"
    task_always_eager: bool = False
    task_time_limit: int = Field(default=1800, ge=30)
    task_soft_time_limit: int = Field(default=1500, ge=10)


class GraphSettings(_Model):
    backend: Literal["networkx", "neo4j"] = "networkx"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    max_nodes: int = Field(default=50_000, ge=100, le=1_000_000)


class ReportSettings(_Model):
    output_dir: Path = Path("./reports")
    pdf_enabled: bool = False
    include_evidence_blobs: bool = True
    max_evidence_bytes: int = Field(default=262_144, ge=1024)


class RetentionSettings(_Model):
    default_days: int = Field(default=180, ge=1, le=3650)
    keep_findings: bool = True
    keep_snapshots: int = Field(default=52, ge=1, le=1000)


class MonitoringSettings(_Model):
    default_interval_minutes: int = Field(default=1440, ge=5, le=43_200)
    max_concurrent_scans: int = Field(default=2, ge=1, le=32)


class SourcesSettings(_Model):
    """Third-party intelligence sources.

    A source is *read-only enrichment*: ATLAS reads what someone else already
    observed and never asks a source to touch a target on our behalf. When a
    source has no credential the collectors that need it report themselves as
    unavailable instead of failing a job.
    """

    #: urlscan.io API key. Required by every ``urlscan`` collector.
    urlscan_api_key: str = ""
    urlscan_base_url: str = "https://urlscan.io"
    urlscan_timeout: float = Field(default=20.0, gt=0, le=120)
    #: How many search hits one domain lookup may ingest.
    urlscan_result_limit: int = Field(default=1, ge=1, le=25)
    #: Ceiling on requests parsed out of a single scan result.
    urlscan_max_requests: int = Field(default=200, ge=1, le=5000)
    #: Ceiling on host names lifted out of a single scan result.
    urlscan_max_hosts: int = Field(default=500, ge=1, le=10_000)
    #: Bounded capture of response headers per request.
    urlscan_max_headers_per_response: int = Field(default=40, ge=1, le=200)

    @property
    def urlscan_enabled(self) -> bool:
        return bool(self.urlscan_api_key.strip())


class Settings(BaseSettings):
    """Root configuration object. Immutable once loaded."""

    model_config = SettingsConfigDict(
        env_prefix="ATLAS_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        frozen=True,
    )

    environment: Literal["development", "staging", "production", "test"] = "development"
    instance_name: str = "atlas"
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    collector: CollectorSettings = Field(default_factory=CollectorSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    celery: CelerySettings = Field(default_factory=CelerySettings)
    graph: GraphSettings = Field(default_factory=GraphSettings)
    reports: ReportSettings = Field(default_factory=ReportSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    sources: SourcesSettings = Field(default_factory=SourcesSettings)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            _YamlSettingsSource(settings_cls),
            file_secret_settings,
        )

    def redacted(self) -> dict[str, Any]:
        """Serialise the config with secret-bearing values masked."""

        data = self.model_dump(mode="json")
        secrets = {
            "neo4j_password",
            "url",  # database URL may embed a password
            "broker_url",
            "result_backend",
            "urlscan_api_key",
        }
        for section in ("database", "graph", "celery", "sources"):
            block = data.get(section)
            if isinstance(block, dict):
                for key in list(block):
                    if key in secrets:
                        block[key] = _mask(str(block[key]))
        return data


def _mask(value: str) -> str:
    if not value:
        return ""
    if "://" in value:
        scheme, rest = value.split("://", 1)
        if "@" in rest:
            creds, host = rest.split("@", 1)
            return f"{scheme}://***@{host}"
        return value
    return "***"


class _YamlSettingsSource(PydanticBaseSettingsSource):
    """Loads a YAML document from the first resolved config path."""

    def __init__(self, settings_cls: type[BaseSettings]) -> None:
        super().__init__(settings_cls)

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        # Whole-document source: individual field lookup is not used.
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        path = resolve_config_path()
        if path is None:
            return {}
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigurationError(f"cannot read configuration file {path}: {exc}") from exc
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            raise ConfigurationError(
                f"configuration file {path} must contain a mapping at the top level"
            )
        return raw


def load_settings(
    config_path: Path | None = None,
    **overrides: Any,
) -> Settings:
    """Load and validate settings.

    ``overrides`` are applied as the highest-priority source (used by tests).
    """

    token = _explicit_config_path.set(Path(config_path) if config_path is not None else None)
    try:
        if config_path is not None and not Path(config_path).expanduser().is_file():
            raise ConfigurationError(f"configuration file not found: {config_path}")
        try:
            return Settings(**overrides)
        except PydanticValidationError as exc:
            raise ConfigurationError(
                f"invalid configuration: {_format_pydantic_error(exc)}"
            ) from exc
    finally:
        _explicit_config_path.reset(token)


def _format_pydantic_error(exc: PydanticValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors():
        location = ".".join(str(item) for item in err.get("loc", ()))
        parts.append(f"{location}: {err.get('msg', 'invalid value')}")
    return "; ".join(parts) or "validation failed"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton (env + discovered config file)."""

    return load_settings()


def reset_settings_cache() -> None:
    """Clear the cached settings (tests, ``atlas init`` after writing a config)."""

    get_settings.cache_clear()
