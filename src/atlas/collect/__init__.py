"""Collection engine.

Public surface:

``Collector``
    Abstract adapter. Implementations turn an authorized target into immutable
    observations and never touch the database.
``CollectorContext``
    Settings, scope set, rate limiter and deadline handed to a collector.
``CollectorRegistry`` / ``default_registry``
    Name → collector lookup used by the CLI.
``build_context``
    Assembles a context (scope set, limiter, deadline) for one job.
"""

from atlas.collect.base import (
    CertificateObservation,
    CollectionError,
    CollectionTarget,
    Collector,
    CollectorContext,
    CollectorResult,
    CookieObservation,
    DnsAnswerObservation,
    HttpObservation,
    NameStatusObservation,
    Observation,
    RateLimiterProtocol,
    TechnologyObservation,
    UrlscanCertificateObservation,
    UrlscanHostObservation,
    UrlscanRequestObservation,
    UrlscanScanObservation,
)
from atlas.collect.dns import DEFAULT_RECORD_TYPES, DnsCollector, build_resolver
from atlas.collect.http import HttpCollector, build_http_client, parse_set_cookie
from atlas.collect.ratelimit import RateLimiter, TokenBucket
from atlas.collect.registry import CollectorRegistry, default_registry
from atlas.collect.retry import RetryPolicy
from atlas.collect.runtime import build_context, build_rate_limiter
from atlas.collect.tls import CertCollector, handshake_over_tls, parse_certificate
from atlas.collect.urlscan import UrlscanCollector, build_urlscan_client, normalize_scan_id

__all__ = [
    "DEFAULT_RECORD_TYPES",
    "CertCollector",
    "CertificateObservation",
    "CollectionError",
    "CollectionTarget",
    "Collector",
    "CollectorContext",
    "CollectorRegistry",
    "CollectorResult",
    "CookieObservation",
    "DnsAnswerObservation",
    "DnsCollector",
    "HttpCollector",
    "HttpObservation",
    "NameStatusObservation",
    "Observation",
    "RateLimiter",
    "RateLimiterProtocol",
    "RetryPolicy",
    "TechnologyObservation",
    "TokenBucket",
    "UrlscanCertificateObservation",
    "UrlscanCollector",
    "UrlscanHostObservation",
    "UrlscanRequestObservation",
    "UrlscanScanObservation",
    "build_context",
    "build_http_client",
    "build_rate_limiter",
    "build_resolver",
    "build_urlscan_client",
    "default_registry",
    "handshake_over_tls",
    "normalize_scan_id",
    "parse_certificate",
    "parse_set_cookie",
]
