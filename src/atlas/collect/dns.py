"""DNS collection.

The collector asks a recursive resolver the questions an analyst would ask, and
normalizes every answer into an immutable observation. It is deliberately
narrow:

* no zone transfers, no brute force, no dictionary walking — discovery of names
  beyond what DNS itself publishes is not a Phase 2 capability;
* no connection is ever made to a resolved address. A DNS answer is a fact about
  a name, not an authorization to touch a host;
* unreadable answers become :class:`~atlas.collect.base.CollectionError` rows.

The resolver is injected, so the whole collector runs against recorded data in
CI and against ``dns.resolver`` in the field.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Protocol

import dns.exception
import dns.resolver
import dns.reversename

from atlas.collect.base import (
    CollectionError,
    CollectionTarget,
    Collector,
    CollectorContext,
    CollectorResult,
    DnsAnswerObservation,
    NameStatusObservation,
    Observation,
)
from atlas.config import Settings
from atlas.core.time import utcnow
from atlas.db.enums import DnsRecordType, JobType, TargetKind

__all__ = [
    "DEFAULT_RECORD_TYPES",
    "DnsCollector",
    "DnsResolverProtocol",
    "build_resolver",
]

DEFAULT_RECORD_TYPES: tuple[DnsRecordType, ...] = (
    DnsRecordType.A,
    DnsRecordType.AAAA,
    DnsRecordType.CNAME,
    DnsRecordType.MX,
    DnsRecordType.NS,
    DnsRecordType.TXT,
    DnsRecordType.SOA,
    DnsRecordType.CAA,
)

#: Bound on how many CNAME targets are followed per run.
_MAX_CNAME_FOLLOWS = 32


class DnsResolverProtocol(Protocol):
    """The dnspython surface the collector depends on."""

    def resolve(self, qname: str, rdtype: str, **kwargs: Any) -> Any: ...


def build_resolver(settings: Settings) -> DnsResolverProtocol:
    """Construct a ``dns.resolver.Resolver`` with ATLAS timeouts."""

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = settings.collector.connect_timeout
    resolver.lifetime = min(
        settings.collector.total_timeout,
        max(settings.collector.connect_timeout * 4, settings.collector.read_timeout),
    )
    resolver.retry_servfail = False
    # dnspython's ``resolve`` is a superset of the protocol signature.
    return resolver  # type: ignore[return-value]


def _clean_name(value: object) -> str:
    return str(value).rstrip(".").lower()


def _txt_value(rdata: Any) -> str:
    parts = getattr(rdata, "strings", None)
    if parts:
        return "".join(
            part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
            for part in parts
        )
    return str(getattr(rdata, "to_text", lambda: rdata)()).strip('"')


def _normalize_rdata(
    record_type: DnsRecordType, rdata: Any
) -> tuple[str, int | None, dict[str, Any]]:
    """Return ``(value, priority, raw)`` for one resource record.

    Explicit handling covers the types ATLAS correlates on; anything else falls
    back to the zone-file text, which is still an exact, checkable value.
    """

    match record_type:
        case DnsRecordType.A | DnsRecordType.AAAA:
            address = ipaddress.ip_address(str(rdata.address))
            return str(address), None, {"version": address.version}
        case DnsRecordType.CNAME | DnsRecordType.NS | DnsRecordType.PTR:
            return _clean_name(rdata.target), None, {}
        case DnsRecordType.MX:
            return _clean_name(rdata.exchange), int(rdata.preference), {}
        case DnsRecordType.TXT:
            return _txt_value(rdata), None, {}
        case DnsRecordType.SOA:
            return (
                " ".join(
                    [
                        _clean_name(rdata.mname),
                        _clean_name(rdata.rname),
                        str(rdata.serial),
                        str(rdata.refresh),
                        str(rdata.retry),
                        str(rdata.expire),
                        str(rdata.minimum),
                    ]
                ),
                None,
                {"serial": int(rdata.serial)},
            )
        case DnsRecordType.SRV:
            target = _clean_name(getattr(rdata, "target", ""))
            port = int(getattr(rdata, "port", 0))
            return (
                f"{target}:{port}",
                int(getattr(rdata, "priority", 0)),
                {"weight": int(getattr(rdata, "weight", 0))},
            )
        case _:
            return str(rdata.to_text()), None, {}


def _rrset_ttl(answer: Any) -> int | None:
    rrset = getattr(answer, "rrset", None)
    ttl = getattr(rrset, "ttl", None)
    if ttl is None:
        return None
    try:
        return int(ttl)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return None


@dataclass(frozen=True, slots=True)
class DnsCollector(Collector):
    """Collect standard DNS records for a domain or a PTR name for an address."""

    name: ClassVar[str] = "dns"
    job_type: ClassVar[JobType] = JobType.DNS
    produces: ClassVar[tuple[str, ...]] = tuple(t.value for t in DEFAULT_RECORD_TYPES)

    settings: Settings
    resolver: DnsResolverProtocol | None = None
    record_types: tuple[DnsRecordType, ...] = DEFAULT_RECORD_TYPES
    follow_cnames: bool = True
    resolver_factory: Callable[[Settings], DnsResolverProtocol] = field(
        default=build_resolver, repr=False, compare=False
    )

    def _resolver(self) -> DnsResolverProtocol:
        if self.resolver is None:
            return self.resolver_factory(self.settings)
        return self.resolver

    # -- public API ------------------------------------------------------- #

    def collect(self, target: CollectionTarget, context: CollectorContext) -> CollectorResult:
        self._guard(target, context)
        started = utcnow()
        resolver = self._resolver()

        observations: list[Observation] = []
        errors: list[CollectionError] = []
        stats: dict[str, Any] = {"queries": 0, "records": 0, "nxdomain": 0, "checked_types": set()}

        if target.kind in {TargetKind.DOMAIN, TargetKind.URL}:
            self._collect_domain(target.value, resolver, context, observations, errors, stats)
        elif target.kind in {TargetKind.IP}:
            self._collect_ptr(target.value, resolver, context, observations, errors, stats)
        else:  # CIDR targets have no DNS surface of their own
            errors.append(
                CollectionError(
                    operation="dns",
                    error_type="unsupported_target",
                    message=f"DNS collection needs a name or address, not a {target.kind.value}",
                )
            )

        if self.follow_cnames and not context.expired():
            self._follow_cnames(resolver, context, observations, errors, stats)

        stats["records"] = sum(1 for obs in observations if isinstance(obs, DnsAnswerObservation))
        stats["checked_types"] = sorted(stats["checked_types"])
        return CollectorResult(
            collector=self.name,
            target=target,
            observations=tuple(observations),
            errors=tuple(errors),
            started_at=started,
            finished_at=utcnow(),
            stats=stats,
        )

    # -- internals -------------------------------------------------------- #

    def _collect_domain(
        self,
        fqdn: str,
        resolver: DnsResolverProtocol,
        context: CollectorContext,
        observations: list[Observation],
        errors: list[CollectionError],
        stats: dict[str, Any],
    ) -> None:
        checked: set[str] = stats["checked_types"]
        for record_type in self.record_types:
            if context.expired():
                errors.append(
                    CollectionError(
                        operation=record_type.value,
                        error_type="deadline",
                        message="job deadline reached",
                    )
                )
                return
            try:
                answers = self._query(resolver, fqdn, record_type, context, stats)
            except _NameDoesNotExist:
                stats["nxdomain"] += 1
                # NXDOMAIN is a statement about the name, not the type: every
                # configured type was effectively answered.
                checked.update(t.value for t in self.record_types)
                observations.append(
                    NameStatusObservation(
                        source=self.name,
                        observed_at=utcnow(),
                        query_name=fqdn,
                        status="NXDOMAIN",
                        exists=False,
                    )
                )
                return
            except _NoAnswer:
                checked.add(record_type.value)
                continue
            except Exception as exc:
                errors.append(self._translate(record_type.value, exc))
                continue

            checked.add(record_type.value)
            observed_at = utcnow()
            for value, priority, raw in answers:
                observations.append(
                    DnsAnswerObservation(
                        source=self.name,
                        observed_at=observed_at,
                        query_name=fqdn,
                        record_type=record_type,
                        value=value,
                        ttl=raw.pop("_ttl", None),
                        priority=priority,
                        raw=raw,
                    )
                )

    def _collect_ptr(
        self,
        address: str,
        resolver: DnsResolverProtocol,
        context: CollectorContext,
        observations: list[Observation],
        errors: list[CollectionError],
        stats: dict[str, Any],
    ) -> None:
        try:
            reverse_name = dns.reversename.from_address(address).to_text().rstrip(".")
        except ValueError as exc:
            errors.append(
                CollectionError(operation="PTR", error_type="invalid_address", message=str(exc))
            )
            return
        try:
            answers = self._query(resolver, reverse_name, DnsRecordType.PTR, context, stats)
        except (_NoAnswer, _NameDoesNotExist):
            observations.append(
                NameStatusObservation(
                    source=self.name,
                    observed_at=utcnow(),
                    query_name=address,
                    status="NO_PTR",
                    exists=False,
                )
            )
            return
        except Exception as exc:
            errors.append(self._translate("PTR", exc))
            return

        observed_at = utcnow()
        for value, priority, raw in answers:
            observations.append(
                DnsAnswerObservation(
                    source=self.name,
                    observed_at=observed_at,
                    query_name=address,
                    record_type=DnsRecordType.PTR,
                    value=value,
                    ttl=raw.pop("_ttl", None),
                    priority=priority,
                    raw=raw,
                )
            )

    def _query(
        self,
        resolver: DnsResolverProtocol,
        qname: str,
        record_type: DnsRecordType,
        context: CollectorContext,
        stats: dict[str, Any],
    ) -> list[tuple[str, int | None, dict[str, Any]]]:
        """One rate-limited lookup, translated into ``(value, priority, raw)``."""

        context.rate_limiter.acquire(f"dns:{qname}")
        stats["queries"] += 1
        try:
            answer = resolver.resolve(qname, record_type.value)
        except dns.resolver.NXDOMAIN as exc:
            raise _NameDoesNotExist(qname) from exc
        except dns.resolver.NoAnswer as exc:
            raise _NoAnswer(qname) from exc
        except dns.resolver.NoNameservers as exc:
            raise ConnectionError(f"no nameserver answered for {qname}: {exc}") from exc
        except dns.exception.Timeout as exc:
            raise TimeoutError(f"DNS timeout for {qname} {record_type.value}") from exc

        ttl = _rrset_ttl(answer)
        results: list[tuple[str, int | None, dict[str, Any]]] = []
        for rdata in answer:
            value, priority, raw = _normalize_rdata(record_type, rdata)
            raw["_ttl"] = ttl
            results.append((value, priority, raw))
        if not results:
            raise _NoAnswer(qname)
        return results

    def _follow_cnames(
        self,
        resolver: DnsResolverProtocol,
        context: CollectorContext,
        observations: list[Observation],
        errors: list[CollectionError],
        stats: dict[str, Any],
    ) -> None:
        """Check whether each observed CNAME target still exists.

        This is the evidence dangling-CNAME analysis needs. It is a resolver
        query about a *name* — no connection is opened, and the target is not
        promoted to an asset (see ``atlas.services.dns``).
        """

        targets = {
            obs.value
            for obs in observations
            if isinstance(obs, DnsAnswerObservation) and obs.record_type is DnsRecordType.CNAME
        }
        stats["cname_checks"] = 0
        for index, target in enumerate(sorted(targets)):
            if context.expired():
                errors.append(
                    CollectionError(
                        operation="cname_follow",
                        error_type="deadline",
                        message="job deadline reached while checking CNAME targets",
                    )
                )
                return
            if index >= _MAX_CNAME_FOLLOWS:
                stats["cname_checks_truncated"] = len(targets) - _MAX_CNAME_FOLLOWS
                return
            try:
                context.rate_limiter.acquire(f"dns:{target}")
                stats["queries"] += 1
                stats["cname_checks"] += 1
                resolver.resolve(target, DnsRecordType.A.value)
                exists = True
                status = "RESOLVED"
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                exists = False
                status = "NXDOMAIN"
            except Exception as exc:
                errors.append(self._translate("cname_follow", exc))
                continue
            observations.append(
                NameStatusObservation(
                    source=self.name,
                    observed_at=utcnow(),
                    query_name=target,
                    status=status,
                    exists=exists,
                )
            )


class _NameDoesNotExist(Exception):
    """Internal signal: the resolver answered NXDOMAIN for the query name."""


class _NoAnswer(Exception):
    """Internal signal: the name exists but has no records of the asked type."""


def iter_addresses(observations: Iterable[Observation]) -> Iterable[DnsAnswerObservation]:
    """Convenience filter used by the persistence layer and tests."""

    for observation in observations:
        if isinstance(observation, DnsAnswerObservation) and observation.record_type in {
            DnsRecordType.A,
            DnsRecordType.AAAA,
        }:
            yield observation


def observed_at_of(observation: Observation) -> datetime:
    return observation.observed_at
