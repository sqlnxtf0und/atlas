"""HTTP collection: cookie parsing, fingerprints, and bounded fetching.

Every request is served by ``httpx.MockTransport``; the suite never opens a socket.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest

from atlas.collect.base import CollectionTarget, HttpObservation
from atlas.collect.http import (
    HttpCollector,
    fingerprint_technologies,
    parse_set_cookie,
)
from atlas.config import Settings
from atlas.db.enums import TargetKind
from atlas.errors import ScopeViolation
from support import RecordingLimiter, make_context


def client_for(handler: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=handler, follow_redirects=True, verify=False)


def collector_with(
    handler: httpx.MockTransport,
    settings: Settings,
    *,
    addresses: tuple[str, ...] = ("203.0.113.10",),
) -> HttpCollector:
    """A collector whose client is faked and whose resolver is fixed.

    The pre-flight address gate runs against ``addresses``, so no test ever performs
    a live lookup.
    """

    class Resolver:
        def resolve(self, host: str) -> list[str]:
            del host
            return list(addresses)

    return HttpCollector(
        settings=settings,
        client_factory=lambda _settings: httpx.Client(
            transport=handler, follow_redirects=True, verify=False, max_redirects=5
        ),
        address_resolver=Resolver(),
    )


# --------------------------------------------------------------------------- #
# Cookie parsing                                                               #
# --------------------------------------------------------------------------- #


def test_parse_set_cookie_records_every_attribute_as_sent() -> None:
    cookie = parse_set_cookie(
        "session=a1b2c3; Path=/app; Domain=.example.com; Secure; HttpOnly; "
        "SameSite=Lax; Max-Age=1800; Expires=Wed, 21 Oct 2026 07:28:00 GMT"
    )

    assert cookie is not None
    assert cookie.name == "session"
    assert cookie.value == "a1b2c3"
    assert cookie.secure is True
    assert cookie.http_only is True
    assert cookie.same_site == "Lax"
    assert cookie.domain == ".example.com"
    assert cookie.path == "/app"
    assert cookie.max_age == 1800
    assert cookie.expires == "Wed, 21 Oct 2026 07:28:00 GMT"


def test_parse_set_cookie_reports_absent_flags_as_false() -> None:
    cookie = parse_set_cookie("tracker=xyz; Path=/")

    assert cookie is not None
    assert cookie.secure is False
    assert cookie.http_only is False
    assert cookie.same_site is None


def test_parse_set_cookie_rejects_non_cookie_headers() -> None:
    assert parse_set_cookie("not-a-cookie") is None
    assert parse_set_cookie("=onlyvalue") is None
    assert parse_set_cookie("") is None


def test_parse_set_cookie_tolerates_a_broken_max_age() -> None:
    cookie = parse_set_cookie("a=b; Max-Age=soon")

    assert cookie is not None
    assert cookie.max_age is None


# --------------------------------------------------------------------------- #
# Technology fingerprints                                                      #
# --------------------------------------------------------------------------- #


def test_fingerprints_from_headers_carry_evidence_and_version() -> None:
    found = fingerprint_technologies({"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.11"}, b"")
    by_name = {tech.name: tech for tech in found}

    assert by_name["nginx"].version == "1.24.0"
    assert by_name["nginx"].category == "server"
    assert by_name["nginx"].evidence == "Server: nginx/1.24.0"
    assert by_name["PHP"].version == "8.2.11"


def test_fingerprints_from_body_are_deduplicated_against_headers() -> None:
    body = b"<html><head><meta name='generator' content='WordPress 6.5'></head>wp-content/x</html>"
    found = fingerprint_technologies({"Server": "nginx/1.24.0"}, body)

    assert [tech.name for tech in found].count("WordPress") == 1
    wordpress = next(tech for tech in found if tech.name == "WordPress")
    assert wordpress.version == "6.5"
    assert wordpress.evidence.startswith("body marker:")


def test_fingerprints_ignore_a_tiny_body() -> None:
    assert fingerprint_technologies({}, b"tiny") == ()


def test_fingerprints_return_nothing_for_an_unknown_server() -> None:
    assert fingerprint_technologies({"Server": "custom-daemon"}, b"") == ()


# --------------------------------------------------------------------------- #
# Collector                                                                    #
# --------------------------------------------------------------------------- #


def test_collector_fetches_and_describes_a_response(settings: Settings) -> None:
    body = b"<html><head><title>  Acme  Corp </title></head>wp-content/</html>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Server": "nginx/1.24.0",
                "Content-Type": "text/html; charset=utf-8",
                "X-Powered-By": "PHP/8.2.11",
                "Set-Cookie": "sid=1; Secure; HttpOnly; SameSite=Strict",
            },
            content=body,
        )

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["example.com"])
    limiter = context.rate_limiter

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert result.errors == ()
    assert len(result.observations) == 1
    observation = result.observations[0]
    assert isinstance(observation, HttpObservation)
    assert observation.url == "https://example.com/"
    assert observation.host == "example.com"
    assert observation.status == 200
    assert observation.scheme == "https"
    assert observation.port == 443
    assert observation.is_https is True
    assert observation.title == "Acme Corp"
    assert observation.server == "nginx/1.24.0"
    assert observation.body_sha256 == hashlib.sha256(body).hexdigest()
    assert observation.content_length == len(body)
    assert [cookie.name for cookie in observation.cookies] == ["sid"]
    assert {tech.name for tech in observation.technologies} == {"nginx", "PHP", "WordPress"}
    assert "http:example.com" in limiter.keys
    assert result.stats["requests"] == 1


def test_collector_records_the_redirect_chain(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(301, headers={"Location": "https://www.example.com/home"})
        return httpx.Response(200, headers={"Server": "nginx"}, content=b"ok " * 10)

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["example.com", "www.example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    observation = result.observations[0]
    assert observation.status == 200
    assert observation.redirect_chain == (
        "https://example.com/",
        "https://www.example.com/home",
    )
    assert observation.final_url == "https://www.example.com/home"
    assert observation.host == "www.example.com"
    assert result.stats["redirects"] == 1


def test_collector_falls_back_to_plain_http(settings: Settings) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.scheme == "https":
            raise httpx.ConnectError("no TLS here", request=request)
        return httpx.Response(200, headers={"Server": "nginx"}, content=b"x" * 32)

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert seen == ["https://example.com/", "http://example.com/"]
    assert result.observations[0].scheme == "http"
    assert result.observations[0].port == 80
    assert result.observations[0].is_https is False


def test_collector_refuses_an_out_of_scope_target(settings: Settings) -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=b"nope")

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["other.test"])

    with pytest.raises(ScopeViolation):
        collector.collect(CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context)
    assert called is False


def test_collector_truncates_the_body_at_the_configured_ceiling(settings: Settings) -> None:
    oversized = b"a" * (settings.collector.max_body_bytes + 4096)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Server": "nginx"}, content=oversized)

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    observation = result.observations[0]
    assert observation.content_length == settings.collector.max_body_bytes
    assert observation.body_sha256 != hashlib.sha256(oversized).hexdigest()


def test_collector_records_transport_failures_as_errors(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert result.observations == ()
    assert result.failed is True
    assert {error.error_type for error in result.errors} == {"connection_error"}


def test_collector_rejects_a_cidr_target(settings: Settings) -> None:
    collector = HttpCollector(settings=settings)
    context = make_context(settings, ["203.0.113.0/24"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.CIDR, value="203.0.113.0/24"), context
    )

    assert [error.error_type for error in result.errors] == ["unsupported_target"]


def test_collector_uses_the_url_path_when_one_is_given(settings: Settings) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, headers={"Server": "nginx"}, content=b"y" * 32)

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["example.com"])

    result = collector.collect(
        CollectionTarget(
            kind=TargetKind.URL, value="example.com", display="https://example.com/login"
        ),
        context,
    )

    assert seen == ["https://example.com/login"]
    assert result.observations[0].url == "https://example.com/login"


def test_collector_respects_the_deadline(settings: Settings) -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, content=b"z" * 32)

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["example.com"], deadline_seconds=-1.0)

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert called is False
    assert [error.error_type for error in result.errors] == ["deadline"]


def test_collector_never_reuses_a_limiter_key_for_another_host(settings: Settings) -> None:
    limiter = RecordingLimiter()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Server": "nginx"}, content=b"q" * 32)

    collector = collector_with(httpx.MockTransport(handler), settings)
    context = make_context(settings, ["example.com", "other.example.com"], limiter=limiter)

    collector.collect(CollectionTarget(kind=TargetKind.DOMAIN, value="other.example.com"), context)

    assert limiter.keys == ["http:other.example.com"]
