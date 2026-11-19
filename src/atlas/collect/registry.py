"""Collector registry.

Collectors are looked up by name from the CLI and (later) the task queue, so the
mapping has to be explicit rather than discovered by import side effects. A
factory takes :class:`~atlas.config.Settings` and returns a configured collector,
which keeps collector construction testable.

A collector may serve more than one job type — DNS runs for both ``discover``
(a quick passive pass) and ``dns`` (an explicit DNS-only job).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from atlas.collect.base import Collector
from atlas.collect.dns import DnsCollector
from atlas.collect.http import HttpCollector
from atlas.collect.tls import CertCollector
from atlas.collect.urlscan import UrlscanCollector
from atlas.config import Settings
from atlas.db.enums import JobType
from atlas.errors import NotFoundError

__all__ = ["CollectorRegistry", "default_registry"]

CollectorFactory = Callable[[Settings], Collector]


def _as_job_types(value: JobType | tuple[JobType, ...]) -> tuple[JobType, ...]:
    if isinstance(value, JobType):
        return (value,)
    if not value:
        raise ValueError("a collector must serve at least one job type")
    return tuple(value)


@dataclass
class CollectorRegistry:
    """Name → factory mapping with job-type grouping."""

    _factories: dict[str, CollectorFactory] = field(default_factory=dict)
    _job_types: dict[str, tuple[JobType, ...]] = field(default_factory=dict)

    def register(
        self,
        name: str,
        factory: CollectorFactory,
        *,
        job_type: JobType | tuple[JobType, ...],
    ) -> None:
        if not name:
            raise ValueError("collector name must not be empty")
        self._factories[name] = factory
        self._job_types[name] = _as_job_types(job_type)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self._factories

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._factories))

    def job_types(self, name: str) -> tuple[JobType, ...]:
        return self._job_types.get(name, ())

    def create(self, name: str, settings: Settings) -> Collector:
        factory = self._factories.get(name)
        if factory is None:
            raise NotFoundError(
                f"unknown collector: {name} (available: {', '.join(self.names) or 'none'})",
                context={"collector": name},
            )
        return factory(settings)

    def for_job_type(self, job_type: JobType, settings: Settings) -> list[Collector]:
        return [
            factory(settings)
            for name, factory in sorted(self._factories.items())
            if job_type in self._job_types[name]
        ]

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": name,
                "job_types": [jt.value for jt in self._job_types[name]],
                "available": True,
            }
            for name in self.names
        ]


def default_registry(*, dns_follow_cnames: bool = True) -> CollectorRegistry:
    """The registry ATLAS ships with.

    Every collector registers here by name and job type; ``JobType.FULL`` runs all
    of them. A collector that reports itself unavailable (urlscan without an API
    key, for example) is skipped by a full job and surfaced as an error only when
    the operator names it explicitly.
    """

    registry = CollectorRegistry()
    registry.register(
        DnsCollector.name,
        lambda settings: DnsCollector(settings=settings, follow_cnames=dns_follow_cnames),
        job_type=(JobType.DISCOVER, JobType.DNS),
    )
    registry.register(
        CertCollector.name,
        lambda settings: CertCollector(settings=settings),
        job_type=JobType.CERTIFICATES,
    )
    registry.register(
        HttpCollector.name,
        lambda settings: HttpCollector(settings=settings),
        job_type=JobType.HTTP,
    )
    registry.register(
        UrlscanCollector.name,
        lambda settings: UrlscanCollector(settings=settings),
        job_type=JobType.URLSCAN,
    )
    return registry
