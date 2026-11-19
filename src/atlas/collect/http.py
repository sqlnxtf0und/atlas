"""HTTP collection.

A bounded, read-only GET with the redirect chain followed and the *terminal*
response recorded. The point is observable facts: status, headers, cookies, the
document title, and technology markers with the exact evidence that produced them.

What it will not do:

* **No exploit probing.** One GET per candidate URL, nothing appended, no method
  override, no parameter injection. Collection is observation, not testing.
* **No unbounded reads.** The body is streamed and truncated at
  ``collector.max_body_bytes``; a hostile peer cannot exhaust memory.
* **No trust in the chain.** TLS verification is disabled on purpose. A site with
  an invalid certificate is a valid observation; refusing to connect would hide
  the very fact an operator needs.
* **No invented findings.** A technology marker carries the evidence string and a
  confidence that reflects how specific that evidence is. A version string is
  never upgraded into an "exploitable" claim here.

The client is injectable so the whole collector runs against ``respx`` / a
``MockTransport`` in CI with no network access.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx

from atlas.collect.base import (
    CollectionError,
    CollectionTarget,
    Collector,
    CollectorContext,
    CollectorResult,
    CookieObservation,
    HttpObservation,
    Observation,
    TechnologyObservation,
)
from atlas.collect.resolve import AddressResolver, resolve_addresses
from atlas.config import Settings
from atlas.core.time import utcnow
from atlas.db.enums import JobType, TargetKind

__all__ = [
    "HttpCollector",
    "build_http_client",
    "fingerprint_technologies",
    "parse_set_cookie",
]

#: Hard ceiling on captured response headers per response.
_MAX_HEADERS = 100

#: Below this many bytes the body is not scanned for markers (nothing useful in it).
_MIN_BODY_SCAN = 24

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

#: Header → technology table. ``(header, pattern, name, category, confidence)``.
#: Confidence reflects marker specificity, not exploitability.
_HEADER_TECH: tuple[tuple[str, re.Pattern[str], str, str, float], ...] = (
    ("server", re.compile(r"nginx(?:/([\w.]+))?", re.I), "nginx", "server", 0.9),
    ("server", re.compile(r"openresty(?:/([\w.]+))?", re.I), "OpenResty", "server", 0.8),
    ("server", re.compile(r"apache(?:/([\w.]+))?", re.I), "Apache HTTP Server", "server", 0.9),
    ("server", re.compile(r"microsoft-iis(?:/([\w.]+))?", re.I), "Microsoft IIS", "server", 0.9),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare", "cdn", 0.9),
    ("server", re.compile(r"gunicorn(?:/([\w.]+))?", re.I), "Gunicorn", "server", 0.8),
    ("server", re.compile(r"caddy(?:/([\w.]+))?", re.I), "Caddy", "server", 0.85),
    ("x-powered-by", re.compile(r"php(?:/([\w.]+))?", re.I), "PHP", "language", 0.9),
    ("x-powered-by", re.compile(r"express", re.I), "Express", "framework", 0.9),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET", "framework", 0.9),
    ("x-powered-by", re.compile(r"servlet(?:/([\w.]+))?", re.I), "Java Servlet", "language", 0.8),
    ("x-generator", re.compile(r"drupal(?:[ /]([\w.]+))?", re.I), "Drupal", "cms", 0.9),
    ("x-drupal-cache", re.compile(r"."), "Drupal", "cms", 0.8),
    ("x-aspnet-version", re.compile(r"([\w.]+)"), "ASP.NET", "framework", 0.9),
    ("x-aspnetmvc-version", re.compile(r"([\w.]+)"), "ASP.NET MVC", "framework", 0.9),
    ("cf-ray", re.compile(r"."), "Cloudflare", "cdn", 0.9),
    ("x-shopify-stage", re.compile(r"."), "Shopify", "cms", 0.9),
    ("x-vercel-id", re.compile(r"."), "Vercel", "cdn", 0.9),
    ("x-amz-cf-id", re.compile(r"."), "Amazon CloudFront", "cdn", 0.9),
    ("x-github-request-id", re.compile(r"."), "GitHub Pages", "other", 0.7),
)

#: Body → technology table. ``(pattern, name, category, confidence)``. Most specific
#: marker first: a CMS generator string carries the version, a bare asset path does
#: not, so generator patterns must win the deduplication race.
_BODY_TECH: tuple[tuple[re.Pattern[bytes], str, str, float], ...] = (
    (
        re.compile(rb'name=["\']generator["\'][^>]{0,80}content=["\']WordPress ?([\w.]*)', re.I),
        "WordPress",
        "cms",
        0.9,
    ),
    (re.compile(rb"wp-content/|wp-includes/", re.I), "WordPress", "cms", 0.9),
    (re.compile(rb"/sites/default/files/", re.I), "Drupal", "cms", 0.8),
    (
        re.compile(rb'name=["\']generator["\'][^>]{0,80}content=["\']Drupal ?([\w.]*)', re.I),
        "Drupal",
        "cms",
        0.9,
    ),
    (re.compile(rb"__NEXT_DATA__", re.I), "Next.js", "framework", 0.9),
    (re.compile(rb'ng-version=["\']([\w.]+)', re.I), "Angular", "framework", 0.9),
    (re.compile(rb'data-reactroot|__REACT_DEVTOOLS|"react-dom"', re.I), "React", "framework", 0.6),
    (re.compile(rb'name=["\']csrf-token["\']', re.I), "Ruby on Rails", "framework", 0.6),
    (
        re.compile(rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Hugo', re.I),
        "Hugo",
        "cms",
        0.9,
    ),
    (re.compile(rb'generator["\'][^>]+content=["\']Jekyll', re.I), "Jekyll", "cms", 0.9),
)


def build_http_client(settings: Settings) -> httpx.Client:
    """A client with ATLAS timeouts, redirect policy and a bounded pool."""

    collector = settings.collector
    return httpx.Client(
        timeout=httpx.Timeout(
            collector.read_timeout,
            connect=collector.connect_timeout,
            write=collector.connect_timeout,
            pool=collector.read_timeout,
        ),
        limits=httpx.Limits(
            max_connections=collector.global_concurrency,
            max_keepalive_connections=collector.per_host_concurrency,
        ),
        follow_redirects=True,
        max_redirects=collector.max_redirects,
        # Observation, not trust: an invalid certificate is a fact to record.
        verify=False,
        headers={"User-Agent": collector.user_agent, "Accept": "*/*"},
    )


def parse_set_cookie(raw: str) -> CookieObservation | None:
    """Parse one ``Set-Cookie`` header. Returns ``None`` when it is not a cookie."""

    segments = [segment.strip() for segment in raw.split(";") if segment.strip()]
    if not segments or "=" not in segments[0]:
        return None
    name, _, value = segments[0].partition("=")
    name = name.strip()
    if not name:
        return None

    attributes: dict[str, str] = {}
    for segment in segments[1:]:
        key, _, attr_value = segment.partition("=")
        attributes[key.strip().lower()] = attr_value.strip()

    max_age: int | None = None
    if "max-age" in attributes:
        try:
            max_age = int(attributes["max-age"])
        except ValueError:
            max_age = None

    same_site = attributes.get("samesite") or None
    return CookieObservation(
        name=name,
        value=value.strip(),
        secure="secure" in attributes,
        http_only="httponly" in attributes,
        same_site=same_site,
        domain=attributes.get("domain") or None,
        path=attributes.get("path") or None,
        max_age=max_age,
        expires=attributes.get("expires") or None,
        raw=raw,
    )


def fingerprint_technologies(
    headers: dict[str, str], body: bytes
) -> tuple[TechnologyObservation, ...]:
    """Match the documented marker tables against the response. Evidence included."""

    found: dict[str, TechnologyObservation] = {}

    # Keep the header name exactly as sent for the evidence string: "Server: nginx/1.24"
    # is what an operator compares against a raw capture, and header casing is
    # meaningful in that comparison.
    by_lower: dict[str, tuple[str, str]] = {
        key.lower(): (key, value) for key, value in headers.items()
    }
    for header, header_pattern, name, category, confidence in _HEADER_TECH:
        entry = by_lower.get(header)
        if entry is None:
            continue
        original_name, value = entry
        if not value:
            continue
        match = header_pattern.search(value)
        if match is None:
            continue
        header_version = match.group(1) if match.groups() else None
        found.setdefault(
            f"header:{header}:{name.lower()}",
            TechnologyObservation(
                name=name,
                category=category,
                version=header_version or None,
                evidence=f"{original_name}: {value}",
                confidence=confidence,
            ),
        )

    if len(body) >= _MIN_BODY_SCAN:
        for body_pattern, name, category, confidence in _BODY_TECH:
            body_match = body_pattern.search(body)
            if body_match is None:
                continue
            version: str | None = None
            if body_match.groups():
                try:
                    version = body_match.group(1).decode("ascii", "ignore") or None
                except (IndexError, AttributeError):  # pragma: no cover - defensive
                    version = None
            found.setdefault(
                f"body:{name.lower()}",
                TechnologyObservation(
                    name=name,
                    category=category,
                    version=version,
                    evidence=f"body marker: {body_match.group(0)[:80]!r}",
                    confidence=confidence,
                ),
            )

    return tuple(found.values())


def _extract_title(body: bytes) -> str | None:
    match = _TITLE.search(body.decode("utf-8", "replace"))
    if match is None:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:300] or None


def _candidate_urls(target: CollectionTarget) -> list[str]:
    """Candidate URLs in preference order. ``display`` carries a URL target's path."""

    if target.kind is TargetKind.URL:
        return [target.display or f"https://{target.value}/"]

    host = target.value
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        parsed = None
    if parsed is not None and parsed.version == 6:
        host_part = f"[{host}]"
    else:
        host_part = host
    return [f"https://{host_part}/", f"http://{host_part}/"]


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


class _FetchRefused(Exception):
    """A response arrived from somewhere the scope and policy do not permit.

    Internal to the module: ``collect`` turns it into a ``scope_denied`` error so a
    single refused hop never aborts the job.
    """


def _port_for(url: str) -> int:
    parsed = urlsplit(url)
    if parsed.port is not None:
        return int(parsed.port)
    return 443 if parsed.scheme.lower() == "https" else 80


@dataclass(slots=True)
class HttpCollector(Collector):
    """Fetch one bounded HTTP response per host and record what was observed."""

    name: ClassVar[str] = "http"
    job_type: ClassVar[JobType] = JobType.HTTP
    produces: ClassVar[tuple[str, ...]] = ("http.response",)

    settings: Settings
    client_factory: Callable[[Settings], httpx.Client] = field(
        default=build_http_client, repr=False, compare=False
    )
    address_resolver: AddressResolver | None = field(default=None, repr=False, compare=False)

    # -- address gate ----------------------------------------------------- #

    def _addresses_allowed(
        self, host: str, context: CollectorContext, errors: list[CollectionError]
    ) -> bool:
        """Pre-flight gate: every address the host resolves to must be connectable.

        httpx resolves the name itself, so this cannot pin the socket; it is a
        refusal to *start* a request that the scope and network policy forbid. The
        response's actual remote address is checked again in ``_verify_remote``,
        which catches a redirect or a resolver answer that moved between gates.
        """

        if _is_literal(host):
            return True
        try:
            addresses = resolve_addresses(host, self.address_resolver)
        except (OSError, ValueError) as exc:
            errors.append(self._translate(f"resolve:{host}", exc))
            return False
        denied = [ip for ip in addresses if not context.permits_address(ip, via_host=host)]
        if denied:
            errors.append(
                CollectionError(
                    operation="http",
                    error_type="address_out_of_scope",
                    message=(
                        f"{host} resolved to address(es) that are not connectable under the "
                        f"authorized scope and network policy: {', '.join(denied[:5])}"
                    ),
                )
            )
            return False
        return True

    def _verify_remote(
        self,
        host: str,
        remote_ip: str | None,
        context: CollectorContext,
        chain: list[str],
    ) -> None:
        """Refuse to record a response that came from outside the authorized set.

        The transport reports its peer address; when it does not (a mock transport),
        the scope check on the final URL is the only evidence available, so the hop
        that left the authorized scope is the one that trips the refusal.
        """

        if remote_ip is not None:
            if context.permits_address(remote_ip, via_host=host):
                return
            raise _FetchRefused(f"{host} answered from {remote_ip}, which is not connectable")
        for hop in chain:
            hop_host = urlsplit(hop).hostname or ""
            if hop_host and not context.permits(hop_host):
                raise _FetchRefused(
                    f"redirected to {hop_host}, which is outside the authorized scope"
                )

    # -- public API ------------------------------------------------------- #

    def collect(self, target: CollectionTarget, context: CollectorContext) -> CollectorResult:
        self._guard(target, context)
        started = utcnow()
        observations: list[Observation] = []
        errors: list[CollectionError] = []
        stats: dict[str, Any] = {"requests": 0, "redirects": 0, "status": None}

        if target.kind is TargetKind.CIDR:
            errors.append(
                CollectionError(
                    operation="http",
                    error_type="unsupported_target",
                    message="HTTP collection needs a name, address or URL, not a CIDR block",
                )
            )
            return CollectorResult(
                collector=self.name,
                target=target,
                observations=(),
                errors=tuple(errors),
                started_at=started,
                finished_at=utcnow(),
                stats=stats,
            )

        client = self.client_factory(self.settings)
        try:
            for url in _candidate_urls(target):
                if context.expired():
                    errors.append(
                        CollectionError(
                            operation="http",
                            error_type="deadline",
                            message="job deadline reached before the request was made",
                        )
                    )
                    break
                host = urlsplit(url).hostname or target.value
                if not context.permits(host):
                    errors.append(
                        CollectionError(
                            operation="http",
                            error_type="scope_denied",
                            message=f"{host} is outside the authorized scope; request not sent",
                        )
                    )
                    continue
                if not self._addresses_allowed(host, context, errors):
                    continue
                context.rate_limiter.acquire(f"http:{host}")
                stats["requests"] += 1
                try:
                    observation = self._fetch(client, url, context)
                except _FetchRefused as exc:
                    errors.append(
                        CollectionError(
                            operation="http",
                            error_type="scope_denied",
                            message=f"{url}: {exc}",
                        )
                    )
                    continue
                except (httpx.HTTPError, OSError) as exc:
                    errors.append(_http_error(url, exc))
                    continue
                observations.append(observation)
                stats["redirects"] = max(0, len(observation.redirect_chain) - 1)
                stats["status"] = observation.status
                break
        finally:
            client.close()

        return CollectorResult(
            collector=self.name,
            target=target,
            observations=tuple(observations),
            errors=tuple(errors),
            started_at=started,
            finished_at=utcnow(),
            stats=stats,
        )

    # -- internals ------------------------------------------------------- #

    def _fetch(self, client: httpx.Client, url: str, context: CollectorContext) -> HttpObservation:
        max_body = context.settings.collector.max_body_bytes
        with client.stream("GET", url) as response:
            body = bytearray()
            for chunk in response.iter_bytes():
                if not chunk:
                    continue
                remaining = max_body - len(body)
                if remaining <= 0:
                    break
                body.extend(chunk[:remaining])
            parsed_url = urlsplit(str(response.url))
            host = parsed_url.hostname or urlsplit(url).hostname or ""
            chain = [str(item.url) for item in response.history] + [str(response.url)]
            headers = dict(list(response.headers.items())[:_MAX_HEADERS])
            raw_cookies = response.headers.get_list("set-cookie")
            cookies = tuple(
                cookie
                for cookie in (parse_set_cookie(raw) for raw in raw_cookies)
                if cookie is not None
            )
            body_bytes = bytes(body)
            remote_ip, tls_version = _connection_facts(response)

            self._verify_remote(host, remote_ip, context, chain)
            observation = HttpObservation(
                source=self.name,
                observed_at=utcnow(),
                url=url,
                host=host,
                scheme=parsed_url.scheme or urlsplit(url).scheme,
                port=_port_for(str(response.url)),
                method="GET",
                status=response.status_code,
                reason=response.reason_phrase or None,
                final_url=str(response.url),
                redirect_chain=tuple(chain),
                mime_type=response.headers.get("content-type"),
                content_length=len(body_bytes),
                server=response.headers.get("server"),
                powered_by=response.headers.get("x-powered-by"),
                tls_version=tls_version,
                remote_ip=remote_ip,
                title=_extract_title(body_bytes),
                body_sha256=hashlib.sha256(body_bytes).hexdigest() if body_bytes else None,
                headers=headers,
                cookies=cookies,
                technologies=fingerprint_technologies(headers, body_bytes),
            )
        return observation


def _connection_facts(response: httpx.Response) -> tuple[str | None, str | None]:
    """Best-effort remote address and negotiated TLS version.

    httpx exposes the underlying stream as an extension; when a transport does not
    provide it (a ``MockTransport`` in tests, for example) both values are simply
    absent rather than guessed.
    """

    stream = response.extensions.get("network_stream")
    if stream is None:
        return None, None
    remote: str | None = None
    tls_version: str | None = None
    try:
        server_addr = stream.get_extra_info("server_addr")
        if server_addr:
            remote = str(server_addr[0])
    except (AttributeError, TypeError, IndexError):  # pragma: no cover - transport-dependent
        remote = None
    try:
        ssl_object = stream.get_extra_info("ssl_object")
        if ssl_object is not None:
            tls_version = ssl_object.version()
    except (AttributeError, TypeError):  # pragma: no cover - transport-dependent
        tls_version = None
    return remote, tls_version


def _http_error(url: str, exc: BaseException) -> CollectionError:
    """Classify a transport failure. ``httpx`` hierarchy, then plain OS errors."""

    if isinstance(exc, httpx.TimeoutException):
        error_type, retryable = "timeout", True
    elif isinstance(exc, httpx.ConnectError):
        error_type, retryable = "connection_error", True
    elif isinstance(exc, httpx.TooManyRedirects):
        error_type, retryable = "too_many_redirects", False
    elif isinstance(exc, httpx.HTTPStatusError):
        error_type, retryable = "http_status", exc.response.status_code >= 500
    elif isinstance(exc, httpx.HTTPError):
        error_type, retryable = "http_error", False
    elif isinstance(exc, OSError):
        error_type, retryable = "connection_error", True
    else:  # pragma: no cover - defensive: nothing else is caught at the call site
        error_type, retryable = type(exc).__name__, False
    return CollectionError(
        operation="http",
        error_type=error_type,
        message=f"{url}: {exc}" if str(exc) else f"{url}: {type(exc).__name__}",
        retryable=retryable,
    )


def iter_technologies(observations: Iterable[Observation]) -> Iterable[TechnologyObservation]:
    """Convenience filter for callers that only want fingerprints."""

    for observation in observations:
        if isinstance(observation, HttpObservation):
            yield from observation.technologies
