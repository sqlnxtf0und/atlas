"""Test doubles.

The suite never touches the network. DNS is exercised through a zone-backed fake
resolver that uses real ``dnspython`` rdata objects, so normalization runs against
the same types production sees while the answers stay deterministic.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from atlas.collect.base import CollectorContext
from atlas.core.time import utcnow
from atlas.scope.matcher import ScopeSet
from atlas.scope.policy import NetworkPolicy

__all__ = [
    "FakeAnswer",
    "FakeResolver",
    "RecordingLimiter",
    "make_context",
    "rr",
    "zone_of",
]


def rr(rdtype: str, text: str) -> dns.rdata.Rdata:
    """Build a real rdata object from zone-file text."""

    return dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.from_text(rdtype), text, origin=None, relativize=False
    )


@dataclass
class FakeAnswer:
    """The slice of ``dns.resolver.Answer`` the collector reads."""

    rdatas: list[dns.rdata.Rdata]
    ttl: int = 300

    def __post_init__(self) -> None:
        self.rrset = SimpleNamespace(ttl=self.ttl)

    def __iter__(self) -> Iterator[dns.rdata.Rdata]:
        return iter(self.rdatas)


@dataclass
class FakeResolver:
    """Zone-backed resolver.

    * a query for a name the zone knows nothing about raises ``NXDOMAIN``;
    * a query for a known name with no records of the asked type raises ``NoAnswer``;
    * ``failures`` forces a specific exception for a ``(name, rdtype)`` pair.
    """

    records: dict[tuple[str, str], FakeAnswer] = field(default_factory=dict)
    names: set[str] = field(default_factory=set)
    failures: dict[tuple[str, str], BaseException] = field(default_factory=dict)
    queries: list[tuple[str, str]] = field(default_factory=list)

    def add(self, name: str, rdtype: str, *values: str, ttl: int = 300) -> None:
        key = (_key(name), rdtype.upper())
        self.records[key] = FakeAnswer([rr(rdtype, value) for value in values], ttl=ttl)
        self.names.add(_key(name))

    def resolve(self, qname: str, rdtype: str, **kwargs: Any) -> FakeAnswer:
        del kwargs
        key = (_key(qname), rdtype.upper())
        self.queries.append(key)
        forced = self.failures.get(key)
        if forced is not None:
            raise forced
        answer = self.records.get(key)
        if answer is not None:
            return answer
        if _key(qname) not in self.names:
            raise dns.resolver.NXDOMAIN()
        raise dns.resolver.NoAnswer()


def _key(name: str) -> str:
    return name.rstrip(".").lower()


def zone_of(entries: Mapping[str, Mapping[str, Iterable[str]]]) -> FakeResolver:
    """Build a resolver from ``{name: {rdtype: [values]}}``."""

    resolver = FakeResolver()
    for name, record_types in entries.items():
        for rdtype, values in record_types.items():
            resolver.add(name, rdtype, *values)
    return resolver


@dataclass
class RecordingLimiter:
    """A rate limiter that records usage and never blocks."""

    acquire_calls: list[tuple[str, float]] = field(default_factory=list)

    def acquire(self, key: str, tokens: float = 1.0) -> float:
        self.acquire_calls.append((key, tokens))
        return 0.0

    def try_acquire(self, key: str, tokens: float = 1.0) -> bool:
        self.acquire_calls.append((key, tokens))
        return True

    @property
    def keys(self) -> list[str]:
        return [key for key, _ in self.acquire_calls]


def make_context(
    settings: Any,
    patterns: Iterable[str],
    *,
    deadline_seconds: float = 60.0,
    limiter: RecordingLimiter | None = None,
    allow_private: bool = False,
) -> CollectorContext:
    """Build a real :class:`CollectorContext` around a small scope set."""

    from datetime import timedelta

    return CollectorContext(
        settings=settings,
        scope=ScopeSet.from_patterns(patterns, policy=NetworkPolicy(allow_private=allow_private)),
        rate_limiter=limiter or RecordingLimiter(),
        deadline=utcnow() + timedelta(seconds=deadline_seconds),
    )
