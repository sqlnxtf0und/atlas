"""urlscan.io source collection.

urlscan.io is a third-party *observer*: it already visited a page, and ATLAS reads
what it recorded. That changes what "authorized" means here, so the rules are
explicit:

* **ATLAS never asks urlscan.io to scan anything.** Only the read endpoints are
  called (``/api/v1/result/<id>/`` and ``/api/v1/search/?q=...``). There is no
  submission code path at all — not gated, absent.
* **Scope is applied to what comes back, not to what is asked.** A scan result is
  full of hosts ATLAS has no authority over (CDNs, trackers, third-party APIs).
  Each host is checked against the live scope set and recorded with
  ``in_scope=False`` when denied. Persistence must never promote those to assets,
  which is why the flag travels on the observation.
* **A scan id is not an authorization.** Following one requires the page domain to
  be inside the scope; an out-of-scope scan raises ``ScopeViolation`` and is never
  silently skipped.
* **urlscan's verdicts are urlscan's.** ``verdict_*`` values are archived as
  provenance and explicitly labelled as a third-party opinion. They are not ATLAS
  findings and never become one.
* **No credential, no collection.** Without an API key the collector reports
  itself unavailable instead of failing a job that merely included it.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx

from atlas.collect.base import (
    CollectionError,
    CollectionTarget,
    Collector,
    CollectorContext,
    CollectorResult,
    Observation,
    UrlscanCertificateObservation,
    UrlscanHostObservation,
    UrlscanRequestObservation,
    UrlscanScanObservation,
)
from atlas.config import Settings
from atlas.core.time import parse_datetime, utcnow
from atlas.db.enums import JobType, TargetKind
from atlas.errors import ConfigurationError, ScopeViolation, ValidationError
from atlas.scope.normalize import normalize_domain

__all__ = [
    "UrlscanCollector",
    "build_urlscan_client",
    "looks_like_scan_id",
    "normalize_scan_id",
    "scan_target_from",
]

#: A urlscan UUID: 8-4-4-4-12 lowercase hex.
_SCAN_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

#: ``https://urlscan.io/<kind>/<uuid>/`` — the public result URL shapes.
_RESULT_URL = re.compile(
    r"^https?://urlscan\.io/(?:result|api/v1/result|responses)/([0-9a-f-]{36})/?$",
    re.IGNORECASE,
)

#: Headers worth keeping from each response; everything else is dropped so a scan
#: result cannot balloon a database row.
_KEPT_HEADERS = frozenset(
    {
        "server",
        "x-powered-by",
        "content-type",
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "set-cookie",
        "access-control-allow-origin",
        "location",
        "cache-control",
        "x-aspnet-version",
        "x-generator",
    }
)


def normalize_scan_id(value: str) -> str:
    """Extract the scan UUID from a bare id or a public urlscan.io URL.

    Raises :class:`~atlas.errors.ValidationError` for anything that is not a scan
    identifier — guessing at one would mean reading data nobody named.
    """

    candidate = value.strip()
    match = _RESULT_URL.match(candidate)
    if match is not None:
        candidate = match.group(1)
    candidate = candidate.lower()
    if not _SCAN_ID.match(candidate):
        raise ValidationError(
            f"not a urlscan.io scan id: {value!r} (expected a UUID or a urlscan.io result URL)"
        )
    return candidate


def looks_like_scan_id(value: str) -> bool:
    """Cheap, non-raising probe used when a target string might be a scan id."""

    try:
        normalize_scan_id(value)
    except ValidationError:
        return False
    return True


def build_urlscan_client(settings: Settings) -> httpx.Client:
    """Client for the urlscan.io API with the configured key attached."""

    sources = settings.sources
    if not sources.urlscan_enabled:
        raise ConfigurationError(
            "urlscan.io collection requires sources.urlscan_api_key "
            "(set it in atlas.yaml or ATLAS_SOURCES__URLSCAN_API_KEY)"
        )
    return httpx.Client(
        base_url=sources.urlscan_base_url.rstrip("/"),
        timeout=httpx.Timeout(sources.urlscan_timeout),
        headers={
            "User-Agent": settings.collector.user_agent,
            "API-Key": sources.urlscan_api_key,
            "Accept": "application/json",
        },
        follow_redirects=False,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
    )


def scan_target_from(target: CollectionTarget) -> str | None:
    """The requested value may itself be a scan id or result URL."""

    for candidate in (target.display, target.value):
        if candidate and looks_like_scan_id(candidate):
            return normalize_scan_id(candidate)
    return None


def _host_kind(value: str) -> str:
    head = value.split(".", 1)[0]
    return "ip" if head.isdigit() or ":" in value else "domain"


@dataclass(slots=True)
class UrlscanCollector(Collector):
    """Read urlscan.io scan results and search hits into observations."""

    name: ClassVar[str] = "urlscan"
    job_type: ClassVar[JobType] = JobType.URLSCAN
    produces: ClassVar[tuple[str, ...]] = (
        "urlscan.scan",
        "urlscan.host",
        "urlscan.request",
        "urlscan.certificate",
    )

    settings: Settings
    client_factory: Callable[[Settings], httpx.Client] = field(
        default=build_urlscan_client, repr=False, compare=False
    )
    #: A direct scan id from the command line or the target string.
    scan_id: str | None = None

    #: Per-scan host budget, reset at the start of every ingest.
    _host_budget: int = field(default=0, init=False, repr=False)
    _seen_hosts: set[tuple[str, str]] = field(default_factory=set, init=False, repr=False)

    def available(self, settings: Settings) -> tuple[bool, str]:
        if settings.sources.urlscan_enabled:
            return True, ""
        return False, (
            "urlscan.io collection needs sources.urlscan_api_key "
            "(atlas.yaml: sources.urlscan_api_key)"
        )

    # -- public API ------------------------------------------------------- #

    def collect(self, target: CollectionTarget, context: CollectorContext) -> CollectorResult:
        # A scan id is not a host: running it through the scope matcher is
        # meaningless. When the operator named a host alongside the id that host
        # is the gate; when they named only an id, the captured page domain is the
        # only authorization available and it is enforced inside ``_ingest``.
        if looks_like_scan_id(target.value):
            authorized_host = None
            if target.display and not looks_like_scan_id(target.display):
                authorized_host = target.display
        else:
            authorized_host = target.value
        if authorized_host is not None and not context.permits(authorized_host):
            raise ScopeViolation(
                f"{authorized_host} is outside the authorized scope",
                context={"value": authorized_host, "collector": self.name},
            )
        started = utcnow()
        observations: list[Observation] = []
        errors: list[CollectionError] = []
        stats: dict[str, Any] = {"scans": 0, "requests": 0, "hosts": 0, "http_calls": 0}

        available, reason = self.available(self.settings)
        if not available:
            errors.append(
                CollectionError(operation="urlscan", error_type="not_configured", message=reason)
            )
            return self._result(target, started, observations, errors, stats)

        client = self.client_factory(self.settings)
        try:
            self._host_budget = self.settings.sources.urlscan_max_hosts
            self._seen_hosts = set()
            scan_ids = [self.scan_id] if self.scan_id else self._search(client, target, context)
            for scan_id in scan_ids[: self.settings.sources.urlscan_result_limit]:
                if context.expired():
                    errors.append(
                        CollectionError(
                            operation="urlscan",
                            error_type="deadline",
                            message="job deadline reached before every scan was read",
                        )
                    )
                    break
                stats["http_calls"] += 1
                payload = self._get_json(client, f"/api/v1/result/{scan_id}/", context, errors)
                if payload is None:
                    continue
                try:
                    self._ingest(scan_id, payload, context, observations, stats)
                except _MalformedScan as exc:
                    errors.append(
                        CollectionError(
                            operation="urlscan.parse",
                            error_type="malformed_scan",
                            message=str(exc),
                        )
                    )
        finally:
            client.close()

        stats["requests"] = sum(1 for o in observations if isinstance(o, UrlscanRequestObservation))
        stats["hosts"] = sum(1 for o in observations if isinstance(o, UrlscanHostObservation))
        return self._result(target, started, observations, errors, stats)

    # -- internals ------------------------------------------------------- #

    def _result(
        self,
        target: CollectionTarget,
        started: Any,
        observations: list[Observation],
        errors: list[CollectionError],
        stats: dict[str, Any],
    ) -> CollectorResult:
        return CollectorResult(
            collector=self.name,
            target=target,
            observations=tuple(observations),
            errors=tuple(errors),
            started_at=started,
            finished_at=utcnow(),
            stats=stats,
        )

    def _search(
        self, client: httpx.Client, target: CollectionTarget, context: CollectorContext
    ) -> list[str]:
        if target.kind not in {TargetKind.DOMAIN, TargetKind.URL}:
            return []
        domain = normalize_domain(target.value)
        context.rate_limiter.acquire("urlscan:search")
        try:
            response = client.get("/api/v1/search/", params={"q": f"page.domain:{domain}"})
        except httpx.HTTPError as exc:
            raise ConnectionError(f"urlscan.io search failed: {exc}") from exc
        if response.status_code != 200:
            raise ConnectionError(
                f"urlscan.io search returned HTTP {response.status_code} for {domain}"
            )
        results = response.json().get("results") or []
        scans: list[str] = []
        for entry in results:
            scan_id = str(entry.get("_id") or "")
            try:
                scans.append(normalize_scan_id(scan_id))
            except Exception:
                continue
        return scans[: self.settings.sources.urlscan_result_limit]

    def _get_json(
        self,
        client: httpx.Client,
        path: str,
        context: CollectorContext,
        errors: list[CollectionError],
    ) -> dict[str, Any] | None:
        context.rate_limiter.acquire("urlscan:result")
        try:
            response = client.get(path)
        except httpx.HTTPError as exc:
            errors.append(self._translate("urlscan.fetch", exc))
            return None
        if response.status_code == 404:
            errors.append(
                CollectionError(
                    operation="urlscan.fetch",
                    error_type="scan_not_found",
                    message=f"urlscan.io has no result at {path}",
                )
            )
            return None
        if response.status_code == 403:
            errors.append(
                CollectionError(
                    operation="urlscan.fetch",
                    error_type="source_denied",
                    message=(
                        "urlscan.io refused the request (403); the scan may require an "
                        "API key you do not have access to"
                    ),
                )
            )
            return None
        if response.status_code != 200:
            errors.append(
                CollectionError(
                    operation="urlscan.fetch",
                    error_type="http_status",
                    message=f"urlscan.io returned HTTP {response.status_code} for {path}",
                    retryable=response.status_code >= 500,
                )
            )
            return None
        try:
            payload = response.json()
        except ValueError as exc:
            errors.append(self._translate("urlscan.json", exc))
            return None
        if not isinstance(payload, dict):
            errors.append(
                CollectionError(
                    operation="urlscan.json",
                    error_type="unexpected_payload",
                    message="urlscan.io returned a non-object JSON document",
                )
            )
            return None
        return payload

    def _ingest(
        self,
        scan_id: str,
        payload: dict[str, Any],
        context: CollectorContext,
        observations: list[Observation],
        stats: dict[str, Any],
    ) -> None:
        page = payload.get("page") or {}
        task = payload.get("task") or {}
        lists = payload.get("lists") or {}
        verdicts = (payload.get("verdicts") or {}).get("overall") or {}

        page_domain = str(page.get("domain") or "").lower()
        page_url = str(page.get("url") or "")
        if not page_domain:
            page_domain = str(task.get("domain") or "").lower()

        if not page_domain:
            raise _MalformedScan(scan_id, "page.domain")

        # A scan id is not an authorization: the page it captured must be ours.
        if not context.permits(page_domain):
            raise ScopeViolation(
                f"urlscan.io scan {scan_id} captured {page_domain}, which is outside "
                f"the authorized scope",
                context={"scan_id": scan_id, "domain": page_domain, "collector": self.name},
            )

        stats["scans"] += 1
        observations.append(
            UrlscanScanObservation(
                source=self.name,
                observed_at=self._scanned_at(task),
                scan_id=scan_id,
                page_url=page_url,
                page_domain=page_domain,
                page_ip=_first_str(page.get("ip")),
                page_in_scope=True,
                asn=_first_int(page.get("asn")),
                asn_name=_first_str(page.get("asnname")),
                country=_first_str(page.get("country")),
                server=_first_str(page.get("server")),
                status=_first_int(page.get("status")),
                title=_first_str(page.get("title")),
                mime_type=_first_str(page.get("mimeType")),
                scanned_at=self._scanned_at(task),
                verdict_score=_first_int(verdicts.get("score")),
                verdict_malicious=_first_bool(verdicts.get("malicious")),
                verdict_categories=tuple(str(item) for item in verdicts.get("categories") or []),
            )
        )

        self._seen_hosts = set()
        self._host_budget = self.settings.sources.urlscan_max_hosts
        self._ingest_hosts(lists.get("domains") or [], scan_id, context, observations)
        self._ingest_hosts(lists.get("ips") or [], scan_id, context, observations)
        self._ingest_requests(payload.get("data") or {}, scan_id, context, observations)
        self._ingest_certificates(lists, scan_id, observations)

    def _ingest_hosts(
        self,
        entries: Iterable[Any],
        scan_id: str,
        context: CollectorContext,
        observations: list[Observation],
    ) -> None:
        # ``urlscan_max_hosts`` is a ceiling on the whole scan, not per list: a
        # result with a thousand domains and a thousand addresses must not double it.
        for entry in entries:
            if self._host_budget <= 0:
                return
            if not isinstance(entry, str) or not entry:
                continue
            host = entry.strip().lower().rstrip(".")
            kind = _host_kind(host)
            key = (kind, host)
            if key in self._seen_hosts:
                continue
            self._seen_hosts.add(key)
            self._host_budget -= 1
            observations.append(
                UrlscanHostObservation(
                    source=self.name,
                    observed_at=utcnow(),
                    host=host,
                    kind=kind,
                    scan_id=scan_id,
                    roles=("listed",),
                    in_scope=context.permits(host),
                )
            )

    def _ingest_requests(
        self,
        data: dict[str, Any],
        scan_id: str,
        context: CollectorContext,
        observations: list[Observation],
    ) -> None:
        entries = data.get("requests") or []
        ceiling = self.settings.sources.urlscan_max_requests
        header_ceiling = self.settings.sources.urlscan_max_headers_per_response
        for entry in list(entries)[:ceiling]:
            # urlscan nests the exchange one level deep: the outer ``request``
            # holds ``request`` (what was sent) and ``response`` (what came back).
            outer = entry.get("request") or {}
            sent = outer.get("request") or {}
            received = outer.get("response") or entry.get("response") or {}
            url = str(sent.get("url") or outer.get("documentURL") or "")
            if not url:
                continue
            try:
                host = str(urlsplit(url).hostname or "").lower()
            except ValueError:
                continue
            if not host:
                continue
            raw_headers = (received.get("response") or {}).get("headers") or {}
            headers: dict[str, str] = {}
            for name, value in list(raw_headers.items())[:header_ceiling]:
                if str(name).lower() in _KEPT_HEADERS:
                    headers[str(name).lower()] = (
                        "; ".join(str(item) for item in value)
                        if isinstance(value, list)
                        else str(value)
                    )
            observations.append(
                UrlscanRequestObservation(
                    source=self.name,
                    observed_at=utcnow(),
                    url=url,
                    host=host,
                    method=str(sent.get("method") or "GET"),
                    status=_first_int(received.get("status")),
                    mime_type=_first_str(received.get("mimeType")),
                    server=headers.get("server"),
                    remote_ip=_first_str(received.get("remoteIPAddress")),
                    port=_first_int(received.get("remotePort")),
                    scheme=str(urlsplit(url).scheme or "https"),
                    tls_protocol=_first_str((received.get("tls") or {}).get("protocol")),
                    redirect_url=_first_str(received.get("redirectURL")),
                    in_scope=context.permits(host),
                    response_headers=headers,
                )
            )

    def _ingest_certificates(
        self,
        lists: dict[str, Any],
        scan_id: str,
        observations: list[Observation],
    ) -> None:
        for entry in lists.get("certificates") or []:
            if not isinstance(entry, dict):
                continue
            observations.append(
                UrlscanCertificateObservation(
                    source=self.name,
                    observed_at=utcnow(),
                    scan_id=scan_id,
                    subject_name=_first_str(entry.get("subjectName")),
                    issuer=_first_str(entry.get("issuer")),
                    valid_from=_first_str(entry.get("validFrom")),
                    valid_to=_first_str(entry.get("validTo")),
                )
            )

    @staticmethod
    def _scanned_at(task: dict[str, Any]) -> datetime:
        raw = task.get("time")
        if not isinstance(raw, str) or not raw:
            return utcnow()
        try:
            return parse_datetime(raw)
        except ValueError:
            return utcnow()


class _MalformedScan(Exception):
    """The scan result is missing a field ATLAS requires."""

    def __init__(self, scan_id: str, field_name: str) -> None:
        super().__init__(f"urlscan.io scan {scan_id} has no {field_name}; nothing was ingested")
        self.scan_id = scan_id
        self.field_name = field_name


def _first_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _first_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1"}
    return bool(value)
