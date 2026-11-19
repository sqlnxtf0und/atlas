"""Collection primitives.

A *collector* turns an authorized target into a list of immutable observations.
It never writes to the database, never decides what an observation means, and
never guesses: an answer it cannot read becomes an entry in ``errors``, not a
value in ``observations``.

Everything a collector needs at runtime lives in :class:`CollectorContext`, which
is also the only place a scope decision can be made — a collector calls
:meth:`CollectorContext.require_permitted` and lets the resulting
:class:`~atlas.errors.ScopeViolation` abort the run.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Protocol

from atlas.config import Settings
from atlas.core.time import isoformat, utcnow
from atlas.db.enums import DnsRecordType, JobType, TargetKind
from atlas.errors import AtlasError, ScopeViolation
from atlas.logging import get_logger
from atlas.scope.matcher import ScopeDecision, ScopeSet
from atlas.scope.policy import NetworkPolicy

__all__ = [
    "CertificateObservation",
    "CollectionError",
    "CollectionTarget",
    "Collector",
    "CollectorContext",
    "CollectorResult",
    "CookieObservation",
    "DnsAnswerObservation",
    "HttpObservation",
    "NameStatusObservation",
    "Observation",
    "RateLimiterProtocol",
    "TechnologyObservation",
    "UrlscanCertificateObservation",
    "UrlscanHostObservation",
    "UrlscanRequestObservation",
    "UrlscanScanObservation",
]

log = get_logger("collect")


class RateLimiterProtocol(Protocol):
    """The slice of the rate limiter a collector is allowed to depend on."""

    def acquire(self, key: str, tokens: float = 1.0) -> float:
        """Block until ``tokens`` may be spent on ``key``; return seconds waited."""

    def try_acquire(self, key: str, tokens: float = 1.0) -> bool:
        """Spend ``tokens`` without blocking. ``False`` means the bucket is empty."""


# --------------------------------------------------------------------------- #
# Target                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CollectionTarget:
    """A normalized target, already known to be inside the authorized scope."""

    kind: TargetKind
    value: str
    display: str = ""

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("collection target value must not be empty")

    @property
    def label(self) -> str:
        return self.display or self.value

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "value": self.value}


# --------------------------------------------------------------------------- #
# Observations                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Observation:
    """Base observation. Subclasses carry the collector-specific payload."""

    source: str
    observed_at: datetime

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": type(self).__name__,
            "source": self.source,
            "observed_at": isoformat(self.observed_at),
        }


@dataclass(frozen=True, slots=True)
class DnsAnswerObservation(Observation):
    """One normalized DNS answer for one query name."""

    query_name: str
    record_type: DnsRecordType
    value: str
    ttl: int | None = None
    priority: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        # Explicit base-class call: ``slots=True`` rebuilds the class, which breaks
        # the zero-argument ``super()`` closure inside the generated subclass.
        payload = Observation.as_dict(self)
        payload.update(
            {
                "query_name": self.query_name,
                "record_type": self.record_type.value,
                "value": self.value,
                "ttl": self.ttl,
                "priority": self.priority,
            }
        )
        return payload


@dataclass(frozen=True, slots=True)
class NameStatusObservation(Observation):
    """The authoritative answer status for a query name.

    Needed by dangling-CNAME detection: a CNAME whose target answers NXDOMAIN is
    a strong indicator of an unclaimed resource, and that fact is itself an
    observation rather than an inference.
    """

    query_name: str
    status: str
    exists: bool

    def as_dict(self) -> dict[str, Any]:
        payload = Observation.as_dict(self)
        payload.update(
            {"query_name": self.query_name, "status": self.status, "exists": self.exists}
        )
        return payload


# --------------------------------------------------------------------------- #
# Certificate and HTTP observations                                            #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CertificateObservation(Observation):
    """One X.509 leaf certificate as presented by a host.

    The fingerprint is the identity: the same certificate observed on two hosts is
    one certificate with two bindings, never two certificates. ``san`` is the SAN
    list as presented — a shared SAN list is *shared infrastructure*, not evidence
    that the names in it share an owner.
    """

    fingerprint_sha256: str
    host: str = ""
    port: int = 443
    fingerprint_sha1: str | None = None
    serial_number: str | None = None
    subject_cn: str | None = None
    subject: dict[str, str] = field(default_factory=dict)
    issuer_cn: str | None = None
    issuer: dict[str, str] = field(default_factory=dict)
    san: tuple[str, ...] = ()
    not_before: datetime | None = None
    not_after: datetime | None = None
    key_algorithm: str | None = None
    key_bits: int | None = None
    signature_algorithm: str | None = None
    is_ca: bool = False
    is_self_signed: bool = False
    tls_version: str | None = None

    @property
    def days_until_expiry(self) -> int | None:
        if self.not_after is None:
            return None
        return (self.not_after - self.observed_at).days

    def as_dict(self) -> dict[str, Any]:
        payload = Observation.as_dict(self)
        payload.update(
            {
                "fingerprint_sha256": self.fingerprint_sha256,
                "fingerprint_sha1": self.fingerprint_sha1,
                "host": self.host,
                "port": self.port,
                "serial_number": self.serial_number,
                "subject_cn": self.subject_cn,
                "subject": dict(self.subject),
                "issuer_cn": self.issuer_cn,
                "issuer": dict(self.issuer),
                "san": list(self.san),
                "not_before": isoformat(self.not_before) if self.not_before else None,
                "not_after": isoformat(self.not_after) if self.not_after else None,
                "days_until_expiry": self.days_until_expiry,
                "key_algorithm": self.key_algorithm,
                "key_bits": self.key_bits,
                "signature_algorithm": self.signature_algorithm,
                "is_ca": self.is_ca,
                "is_self_signed": self.is_self_signed,
                "tls_version": self.tls_version,
            }
        )
        return payload


@dataclass(frozen=True, slots=True)
class CookieObservation:
    """One ``Set-Cookie`` header, split into name and security attributes.

    Attribute presence is recorded exactly as sent. Whether a missing ``Secure``
    flag is a *finding* is a question for the analysis phase; this is the audit
    input, not a severity judgement.
    """

    name: str
    value: str = ""
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None
    domain: str | None = None
    path: str | None = None
    max_age: int | None = None
    expires: str | None = None
    raw: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
            "domain": self.domain,
            "path": self.path,
            "max_age": self.max_age,
            "expires": self.expires,
        }


@dataclass(frozen=True, slots=True)
class TechnologyObservation:
    """A technology fingerprint with the exact evidence that produced it.

    ``confidence`` reflects how *specific* the marker is (``Server: nginx/1.24``
    is stronger evidence than a body substring). It is never a severity, and a
    version string here never implies the version is vulnerable.
    """

    name: str
    category: str
    evidence: str
    version: str | None = None
    confidence: float = 0.6

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 3),
        }


@dataclass(frozen=True, slots=True)
class HttpObservation(Observation):
    """One HTTP exchange (redirect chain collapsed into the terminal response)."""

    url: str
    host: str
    scheme: str = "https"
    port: int = 443
    method: str = "GET"
    status: int | None = None
    reason: str | None = None
    final_url: str | None = None
    redirect_chain: tuple[str, ...] = ()
    mime_type: str | None = None
    content_length: int | None = None
    server: str | None = None
    powered_by: str | None = None
    tls_version: str | None = None
    remote_ip: str | None = None
    title: str | None = None
    body_sha256: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: tuple[CookieObservation, ...] = ()
    technologies: tuple[TechnologyObservation, ...] = ()

    @property
    def is_https(self) -> bool:
        return self.scheme.lower() == "https"

    def as_dict(self) -> dict[str, Any]:
        payload = Observation.as_dict(self)
        payload.update(
            {
                "url": self.url,
                "host": self.host,
                "scheme": self.scheme,
                "port": self.port,
                "method": self.method,
                "status": self.status,
                "reason": self.reason,
                "final_url": self.final_url,
                "redirect_chain": list(self.redirect_chain),
                "mime_type": self.mime_type,
                "content_length": self.content_length,
                "server": self.server,
                "powered_by": self.powered_by,
                "tls_version": self.tls_version,
                "remote_ip": self.remote_ip,
                "title": self.title,
                "body_sha256": self.body_sha256,
                "headers": dict(self.headers),
                "cookies": [cookie.as_dict() for cookie in self.cookies],
                "technologies": [tech.as_dict() for tech in self.technologies],
            }
        )
        return payload


# --------------------------------------------------------------------------- #
# Third-party source observations                                              #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class UrlscanScanObservation(Observation):
    """One urlscan.io scan, reduced to facts the scan itself carries.

    ``verdict_*`` values are **urlscan.io's opinion**, not an ATLAS finding: they
    are recorded so a later phase can compare them against our own analysis, and
    they are never promoted to ``findings`` as-is.
    """

    scan_id: str
    page_url: str
    page_domain: str
    page_ip: str | None = None
    page_in_scope: bool = True
    asn: int | None = None
    asn_name: str | None = None
    country: str | None = None
    server: str | None = None
    status: int | None = None
    title: str | None = None
    mime_type: str | None = None
    scanned_at: datetime | None = None
    verdict_score: int | None = None
    verdict_malicious: bool | None = None
    verdict_categories: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        payload = Observation.as_dict(self)
        payload.update(
            {
                "scan_id": self.scan_id,
                "page_url": self.page_url,
                "page_domain": self.page_domain,
                "page_in_scope": self.page_in_scope,
                "page_ip": self.page_ip,
                "asn": self.asn,
                "asn_name": self.asn_name,
                "country": self.country,
                "server": self.server,
                "status": self.status,
                "title": self.title,
                "mime_type": self.mime_type,
                "scanned_at": isoformat(self.scanned_at) if self.scanned_at else None,
                "verdict_score": self.verdict_score,
                "verdict_malicious": self.verdict_malicious,
                "verdict_categories": list(self.verdict_categories),
            }
        )
        return payload


@dataclass(frozen=True, slots=True)
class UrlscanHostObservation(Observation):
    """A host name or address that appeared in a scan, with its roles.

    ``in_scope`` is decided by the collector against the live scope set. An
    out-of-scope host is still recorded — it is real provenance for the scan —
    but persistence must never turn it into an asset.
    """

    host: str
    kind: str  # "domain" | "ip"
    scan_id: str = ""
    roles: tuple[str, ...] = ()
    in_scope: bool = True
    asn: int | None = None
    asn_name: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = Observation.as_dict(self)
        payload.update(
            {
                "host": self.host,
                "kind": self.kind,
                "scan_id": self.scan_id,
                "roles": list(self.roles),
                "in_scope": self.in_scope,
                "asn": self.asn,
                "asn_name": self.asn_name,
            }
        )
        return payload


@dataclass(frozen=True, slots=True)
class UrlscanRequestObservation(Observation):
    """One HTTP request/response pair recorded by a scan."""

    url: str
    host: str
    scan_id: str = ""
    method: str = "GET"
    status: int | None = None
    mime_type: str | None = None
    server: str | None = None
    remote_ip: str | None = None
    port: int | None = None
    scheme: str = "https"
    tls_protocol: str | None = None
    redirect_url: str | None = None
    in_scope: bool = True
    response_headers: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        payload = Observation.as_dict(self)
        payload.update(
            {
                "url": self.url,
                "host": self.host,
                "scan_id": self.scan_id,
                "method": self.method,
                "status": self.status,
                "mime_type": self.mime_type,
                "server": self.server,
                "remote_ip": self.remote_ip,
                "port": self.port,
                "scheme": self.scheme,
                "tls_protocol": self.tls_protocol,
                "redirect_url": self.redirect_url,
                "in_scope": self.in_scope,
                "response_headers": dict(self.response_headers),
            }
        )
        return payload


@dataclass(frozen=True, slots=True)
class UrlscanCertificateObservation(Observation):
    """A certificate *name* mentioned by a scan.

    urlscan.io reports subject/issuer/validity but not a leaf fingerprint, and a
    shared certificate's SAN list is not evidence of common ownership. This
    observation is therefore archived as provenance only: no ``Certificate`` row
    and no asset are derived from it. The TLS collector (Phase 3) is what can
    produce a fingerprint-bearing certificate.
    """

    scan_id: str
    subject_name: str | None = None
    issuer: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload = Observation.as_dict(self)
        payload.update(
            {
                "scan_id": self.scan_id,
                "subject_name": self.subject_name,
                "issuer": self.issuer,
                "valid_from": self.valid_from,
                "valid_to": self.valid_to,
            }
        )
        return payload


# --------------------------------------------------------------------------- #
# Errors and results                                                           #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CollectionError:
    """A non-fatal failure. Collection continues; the run is marked partial."""

    operation: str
    error_type: str
    message: str
    retryable: bool = False
    attempts: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "error_type": self.error_type,
            "message": self.message,
            "retryable": self.retryable,
            "attempts": self.attempts,
        }


@dataclass(frozen=True, slots=True)
class CollectorResult:
    """Everything one collector produced for one target."""

    collector: str
    target: CollectionTarget
    observations: tuple[Observation, ...] = ()
    errors: tuple[CollectionError, ...] = ()
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime = field(default_factory=utcnow)
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def failed(self) -> bool:
        return bool(self.errors) and not self.observations

    @property
    def partial(self) -> bool:
        return bool(self.errors) and bool(self.observations)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds())

    def observations_of(self, cls: type[Observation]) -> tuple[Observation, ...]:
        return tuple(item for item in self.observations if isinstance(item, cls))

    def summary(self) -> dict[str, Any]:
        return {
            "collector": self.collector,
            "target": self.target.as_dict(),
            "observations": len(self.observations),
            "errors": len(self.errors),
            "ok": self.ok,
            "partial": self.partial,
            "started_at": isoformat(self.started_at),
            "finished_at": isoformat(self.finished_at),
            "duration_seconds": round(self.duration_seconds, 3),
            "stats": dict(self.stats),
        }

    @classmethod
    def empty(
        cls, collector: str, target: CollectionTarget, *, started_at: datetime
    ) -> CollectorResult:
        return cls(collector=collector, target=target, started_at=started_at, finished_at=utcnow())


# --------------------------------------------------------------------------- #
# Context                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class CollectorContext:
    """The collector's whole world: settings, scope, rate limiting, deadline."""

    settings: Settings
    scope: ScopeSet
    rate_limiter: RateLimiterProtocol
    deadline: datetime
    job_id: uuid.UUID | None = None
    actor: str = "cli"

    @property
    def collector_settings(self) -> Any:
        return self.settings.collector

    def time_remaining(self) -> float:
        """Seconds until the deadline. Zero or less means the job must stop."""

        return (self.deadline - utcnow()).total_seconds()

    def expired(self) -> bool:
        return self.time_remaining() <= 0

    def require_permitted(self, value: str) -> ScopeDecision:
        """Scope gate. Raises :class:`ScopeViolation`; never returns a denial."""

        decision = self.scope.check(value)
        if not decision.permitted:
            raise ScopeViolation(
                f"{value} is outside the authorized scope: {decision.reason}",
                context={
                    "value": value,
                    "normalized": decision.normalized,
                    "reason": decision.reason,
                    "collector": "context",
                },
            )
        return decision

    def permits(self, value: str) -> bool:
        return self.scope.permits(value)

    @property
    def network_policy(self) -> NetworkPolicy:
        """Which address classes this job may connect to.

        The scope set's policy is derived from ``security`` when it is built, so it
        is the single source of truth: a context assembled with a permissive policy
        must not be second-guessed by re-reading the settings.
        """

        return self.scope.policy

    def permits_address(self, address: str, *, via_host: str | None = None) -> bool:
        """Whether a socket may be opened to ``address``.

        Two gates, both required:

        1. **Address class.** ``NetworkPolicy`` refuses loopback, private,
           link-local, reserved and multicast targets unless explicitly enabled.
           This is the gate that stops an authorized name whose DNS answers
           ``127.0.0.1`` or a cloud metadata address from becoming an SSRF
           primitive.
        2. **Scope.** The address is covered by a rule in its own right, or it is
           the resolution of a host that is covered. A domain rule that could
           never reach the addresses its own name resolves to would make the
           collector inert, so an authorized name authorizes its own answers —
           subject to gate 1.
        """

        try:
            if not self.network_policy.is_permitted(address):
                return False
        except ValueError:
            return False
        if self.scope.permits(address):
            return True
        return via_host is not None and self.scope.permits(via_host)


# --------------------------------------------------------------------------- #
# Collector                                                                    #
# --------------------------------------------------------------------------- #


class Collector(ABC):
    """Base class for every collection adapter.

    Contract:
      * ``collect`` is synchronous and bounded by ``context.deadline``.
      * It raises :class:`~atlas.errors.ScopeViolation` when a target is not
        permitted — that is the only exception allowed to escape.
      * Every other failure is converted into a :class:`CollectionError` so one
        dead record type never fails an entire job.
    """

    #: Stable identifier used in ``scan_results.source`` and ``Asset.source``.
    name: ClassVar[str] = "collector"
    #: Which job type this collector belongs to.
    job_type: ClassVar[JobType] = JobType.FULL
    #: Record types this collector produces, for CLI help and docs.
    produces: ClassVar[tuple[str, ...]] = ()

    def __init__(self, *, log_name: str | None = None) -> None:
        self.log = get_logger(f"collect.{log_name or self.name}")

    @abstractmethod
    def collect(self, target: CollectionTarget, context: CollectorContext) -> CollectorResult:
        """Collect observations for one target."""

    def available(self, settings: Settings) -> tuple[bool, str]:
        """Whether this collector can run at all.

        Returns ``(available, reason)``. A collector that is missing configuration
        reports itself unavailable so that a broad job simply skips it, while an
        explicit request for it fails with the same reason.
        """

        del settings
        return True, ""

    def _guard(self, target: CollectionTarget, context: CollectorContext) -> None:
        """Re-assert the scope decision at the collector boundary."""

        context.require_permitted(target.value)

    @staticmethod
    def _error(operation: str, exc: BaseException, *, attempts: int = 1) -> CollectionError:
        retryable = isinstance(exc, TimeoutError | ConnectionError | OSError)
        return CollectionError(
            operation=operation,
            error_type=type(exc).__name__,
            message=str(exc) or type(exc).__name__,
            retryable=retryable,
            attempts=attempts,
        )

    def _translate(self, operation: str, exc: BaseException) -> CollectionError:
        """Map an exception to a collection error, preserving ATLAS error slugs."""

        if isinstance(exc, AtlasError):
            return CollectionError(
                operation=operation,
                error_type=exc.slug,
                message=exc.message,
                retryable=False,
            )
        return self._error(operation, exc)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "job_type": self.job_type.value,
            "produces": list(self.produces),
        }
