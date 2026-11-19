"""Collector registry: lookup, job-type grouping and failure modes."""

from __future__ import annotations

import pytest

from atlas.collect.base import CollectionTarget, Collector, CollectorContext, CollectorResult
from atlas.collect.dns import DnsCollector
from atlas.collect.registry import CollectorRegistry, default_registry
from atlas.config import Settings
from atlas.db.enums import JobType
from atlas.errors import NotFoundError


class StubCollector(Collector):
    name = "stub"

    def collect(self, target: CollectionTarget, context: CollectorContext) -> CollectorResult:
        return CollectorResult.empty(self.name, target, started_at=context.deadline)


def test_default_registry_exposes_every_phase_three_collector() -> None:
    registry = default_registry()
    assert registry.names == ("dns", "http", "tls", "urlscan")
    assert JobType.DISCOVER in registry.job_types("dns")
    assert JobType.DNS in registry.job_types("dns")

    settings = Settings()
    assert isinstance(registry.create("dns", settings), DnsCollector)
    assert len(registry.for_job_type(JobType.DNS, settings)) == 1
    assert len(registry.for_job_type(JobType.DISCOVER, settings)) == 1
    assert [c.name for c in registry.for_job_type(JobType.HTTP, settings)] == ["http"]
    assert [c.name for c in registry.for_job_type(JobType.CERTIFICATES, settings)] == ["tls"]
    assert [c.name for c in registry.for_job_type(JobType.URLSCAN, settings)] == ["urlscan"]


def test_unknown_collector_raises_not_found() -> None:
    registry = default_registry()
    with pytest.raises(NotFoundError) as excinfo:
        registry.create("nope", Settings())
    assert excinfo.value.exit_code == 4
    assert "dns" in excinfo.value.message


def test_register_rejects_empty_name_and_empty_job_types() -> None:
    registry = CollectorRegistry()
    with pytest.raises(ValueError):
        registry.register("", lambda settings: StubCollector(), job_type=JobType.DNS)
    with pytest.raises(ValueError):
        registry.register("stub", lambda settings: StubCollector(), job_type=())


def test_registry_contains_and_describe() -> None:
    registry = CollectorRegistry()
    registry.register(
        "stub", lambda settings: StubCollector(), job_type=(JobType.DNS, JobType.FULL)
    )

    assert "stub" in registry
    assert "other" not in registry
    assert registry.describe() == [
        {"name": "stub", "job_types": ["dns", "full"], "available": True}
    ]


def test_collector_describe_contract() -> None:
    described = DnsCollector(settings=Settings()).describe()
    assert described["name"] == "dns"
    assert described["job_type"] == JobType.DNS.value
    assert "A" in described["produces"]
