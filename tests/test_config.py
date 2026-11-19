"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from atlas.config import load_settings
from atlas.errors import ConfigurationError


def test_defaults_are_safe() -> None:
    settings = load_settings()
    assert settings.security.require_scope is True
    assert settings.security.allow_private_addresses is False
    assert settings.collector.max_redirects <= 20
    assert settings.collector.global_concurrency >= settings.collector.per_host_concurrency


def test_env_overrides_yaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "atlas.yaml"
    config.write_text(
        yaml.safe_dump({"collector": {"requests_per_second": 1.0}, "instance_name": "from-yaml"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ATLAS_COLLECTOR__REQUESTS_PER_SECOND", "9.5")

    settings = load_settings(config)

    assert settings.instance_name == "from-yaml"
    assert settings.collector.requests_per_second == 9.5


def test_unknown_key_in_yaml_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "atlas.yaml"
    config.write_text("collector:\n  bogus_option: 1\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_settings(config)


def test_invalid_database_scheme_is_rejected() -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        load_settings(database={"url": "mysql://localhost/atlas"})
    assert "unsupported database scheme" in str(excinfo.value)


def test_private_addresses_refused_in_production_without_scope() -> None:
    with pytest.raises(ConfigurationError):
        load_settings(
            environment="production",
            security={"require_scope": False},
        )


def test_redaction_masks_credentials() -> None:
    settings = load_settings(
        database={"url": "postgresql+psycopg://atlas:hunter2@db:5432/atlas"},
        graph={"neo4j_password": "secret"},
    )
    redacted = settings.redacted()
    assert "hunter2" not in str(redacted)
    assert redacted["graph"]["neo4j_password"] == "***"


def test_missing_explicit_config_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError):
        load_settings(tmp_path / "nope.yaml")
