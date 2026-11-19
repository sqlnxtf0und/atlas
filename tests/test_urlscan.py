"""urlscan.io source collection.

All HTTP goes through ``httpx.MockTransport``. The payload shapes mirror the
documented ``/api/v1/result/<id>/`` response so the parser is exercised against the
nesting a real scan uses.
"""

from __future__ import annotations

import uuid

import httpx
import pytest

from atlas.collect.base import (
    CollectionTarget,
    UrlscanCertificateObservation,
    UrlscanHostObservation,
    UrlscanRequestObservation,
    UrlscanScanObservation,
)
from atlas.collect.urlscan import (
    UrlscanCollector,
    looks_like_scan_id,
    normalize_scan_id,
)
from atlas.config import Settings, load_settings
from atlas.db.enums import TargetKind
from atlas.errors import ScopeViolation, ValidationError
from support import make_context

SCAN_ID = "0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"


def settings_with_key(tmp_path, key: str = "test-key") -> Settings:
    return load_settings(
        database={"url": f"sqlite+pysqlite:///{tmp_path / 'atlas-test.db'}", "echo": False},
        logging={"level": "warning", "json": False},
        sources={"urlscan_api_key": key, "urlscan_result_limit": 3},
        environment="test",
    )


def scan_payload(
    *,
    domain: str = "example.com",
    page_ip: str = "203.0.113.10",
    extra_domains: tuple[str, ...] = ("cdn.thirdparty.test",),
    extra_ips: tuple[str, ...] = (),
) -> dict:
    return {
        "task": {"time": "2026-03-04T05:06:07.000Z", "domain": domain},
        "page": {
            "url": f"https://{domain}/",
            "domain": domain,
            "ip": page_ip,
            "asn": 64500,
            "asnname": "TEST-AS",
            "country": "US",
            "server": "nginx",
            "status": 200,
            "title": "Example",
            "mimeType": "text/html",
        },
        "lists": {
            "domains": [domain, *extra_domains],
            "ips": [page_ip, *extra_ips],
            "certificates": [
                {
                    "subjectName": f"*.{domain}",
                    "issuer": "Let's Encrypt",
                    "validFrom": "2026-01-01T00:00:00Z",
                    "validTo": "2026-04-01T00:00:00Z",
                }
            ],
        },
        "data": {
            "requests": [
                {
                    "request": {
                        "request": {
                            "url": f"https://{domain}/",
                            "method": "GET",
                        },
                        "documentURL": f"https://{domain}/",
                        "response": {
                            "status": 200,
                            "mimeType": "text/html",
                            "remoteIPAddress": page_ip,
                            "remotePort": 443,
                            "tls": {"protocol": "TLS 1.3"},
                            "response": {
                                "headers": {
                                    "Server": ["nginx"],
                                    "Content-Type": ["text/html"],
                                    "X-Not-Kept": ["drop me"],
                                }
                            },
                        },
                    }
                },
                {
                    "request": {
                        "request": {
                            "url": "https://cdn.thirdparty.test/app.js",
                            "method": "GET",
                        },
                        "response": {
                            "status": 304,
                            "response": {"headers": {"Server": ["cloudflare"]}},
                        },
                    }
                },
            ]
        },
        "verdicts": {"overall": {"score": 12, "malicious": False, "categories": ["cdn"]}},
    }


def collector_with(handler: httpx.MockTransport, settings: Settings) -> UrlscanCollector:
    return UrlscanCollector(
        settings=settings,
        client_factory=lambda _settings: httpx.Client(
            base_url="https://urlscan.io", transport=handler
        ),
    )


def result_transport(payload: dict, *, status: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/api/v1/result/"):
            return httpx.Response(status, json=payload)
        if request.url.path == "/api/v1/search/":
            return httpx.Response(200, json={"results": [{"_id": SCAN_ID}]})
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


# --------------------------------------------------------------------------- #
# Identifier handling                                                          #
# --------------------------------------------------------------------------- #


def test_normalize_scan_id_accepts_a_uuid_and_result_urls() -> None:
    assert normalize_scan_id(SCAN_ID.upper()) == SCAN_ID
    assert normalize_scan_id(f"https://urlscan.io/result/{SCAN_ID}/") == SCAN_ID
    assert normalize_scan_id(f"https://urlscan.io/api/v1/result/{SCAN_ID}/") == SCAN_ID


def test_normalize_scan_id_rejects_anything_else() -> None:
    for value in ("", "example.com", str(uuid.uuid5(uuid.NAMESPACE_DNS, "x")) + "x"):
        with pytest.raises(ValidationError):
            normalize_scan_id(value)


def test_looks_like_scan_id_never_raises() -> None:
    assert looks_like_scan_id(SCAN_ID) is True
    assert looks_like_scan_id("example.com") is False


# --------------------------------------------------------------------------- #
# Availability                                                                 #
# --------------------------------------------------------------------------- #


def test_collector_reports_unavailable_without_an_api_key(settings: Settings) -> None:
    available, reason = UrlscanCollector(settings=settings).available(settings)

    assert available is False
    assert "urlscan_api_key" in reason


def test_collector_reports_available_with_an_api_key(tmp_path) -> None:
    keyed = settings_with_key(tmp_path)
    assert UrlscanCollector(settings=keyed).available(keyed) == (True, "")


def test_unconfigured_collector_records_not_configured_instead_of_crashing(
    settings: Settings,
) -> None:
    collector = UrlscanCollector(settings=settings)
    context = make_context(settings, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert result.observations == ()
    assert [error.error_type for error in result.errors] == ["not_configured"]


# --------------------------------------------------------------------------- #
# Collection                                                                   #
# --------------------------------------------------------------------------- #


def test_collector_ingests_a_scan_by_explicit_id(tmp_path) -> None:
    keyed = settings_with_key(tmp_path)
    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io", transport=result_transport(scan_payload())
        ),
        scan_id=SCAN_ID,
    )
    context = make_context(keyed, ["example.com", "203.0.113.0/24"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value=SCAN_ID, display="example.com"), context
    )

    assert result.errors == ()
    scans = [o for o in result.observations if isinstance(o, UrlscanScanObservation)]
    hosts = [o for o in result.observations if isinstance(o, UrlscanHostObservation)]
    requests = [o for o in result.observations if isinstance(o, UrlscanRequestObservation)]
    certificates = [o for o in result.observations if isinstance(o, UrlscanCertificateObservation)]

    assert len(scans) == 1
    scan = scans[0]
    assert scan.scan_id == SCAN_ID
    assert scan.page_domain == "example.com"
    assert scan.page_ip == "203.0.113.10"
    assert scan.asn == 64500
    assert scan.title == "Example"
    assert scan.verdict_score == 12
    assert scan.verdict_categories == ("cdn",)
    assert scan.scanned_at.year == 2026 and scan.scanned_at.month == 3

    by_host = {host.host: host for host in hosts}
    assert by_host["example.com"].in_scope is True
    assert by_host["cdn.thirdparty.test"].in_scope is False
    assert by_host["203.0.113.10"].kind == "ip"
    assert all(host.scan_id == SCAN_ID for host in hosts)

    assert len(requests) == 2
    assert requests[0].status == 200
    assert requests[0].port == 443
    assert requests[0].tls_protocol == "TLS 1.3"
    assert requests[0].response_headers == {"server": "nginx", "content-type": "text/html"}
    assert requests[1].in_scope is False

    assert len(certificates) == 1
    assert certificates[0].subject_name == "*.example.com"


def test_collector_searches_by_page_domain_when_no_id_is_given(tmp_path) -> None:
    keyed = settings_with_key(tmp_path)
    seen: list[str] = []
    base = result_transport(scan_payload())

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.url.path}?{request.url.query.decode()}")
        return base.handle_request(request)

    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io", transport=httpx.MockTransport(handler)
        ),
    )
    context = make_context(keyed, ["example.com", "203.0.113.0/24"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert result.errors == ()
    assert seen[0] == "/api/v1/search/?q=page.domain%3Aexample.com"
    assert any(entry.startswith("/api/v1/result/") for entry in seen)


def test_collector_refuses_a_scan_of_an_out_of_scope_page(tmp_path) -> None:
    keyed = settings_with_key(tmp_path)
    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io",
            transport=result_transport(scan_payload(domain="someone-else.test")),
        ),
        scan_id=SCAN_ID,
    )
    context = make_context(keyed, ["example.com", "203.0.113.0/24"])

    with pytest.raises(ScopeViolation) as excinfo:
        collector.collect(
            CollectionTarget(kind=TargetKind.DOMAIN, value=SCAN_ID, display="example.com"),
            context,
        )
    assert "someone-else.test" in excinfo.value.message


def test_collector_records_a_missing_scan_as_an_error(tmp_path) -> None:
    keyed = settings_with_key(tmp_path)
    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io",
            transport=httpx.MockTransport(lambda _r: httpx.Response(404, json={})),
        ),
        scan_id=SCAN_ID,
    )
    context = make_context(keyed, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value=SCAN_ID, display="example.com"), context
    )

    assert result.observations == ()
    assert [error.error_type for error in result.errors] == ["scan_not_found"]


def test_collector_records_a_403_as_source_denied(tmp_path) -> None:
    keyed = settings_with_key(tmp_path)
    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io",
            transport=httpx.MockTransport(
                lambda _r: httpx.Response(403, json={"warning": "You're not logged in!"})
            ),
        ),
        scan_id=SCAN_ID,
    )
    context = make_context(keyed, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value=SCAN_ID, display="example.com"), context
    )

    assert [error.error_type for error in result.errors] == ["source_denied"]


def test_collector_records_a_malformed_scan_without_ingesting_it(tmp_path) -> None:
    keyed = settings_with_key(tmp_path)
    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io",
            transport=result_transport({"page": {}, "task": {}}),
        ),
        scan_id=SCAN_ID,
    )
    context = make_context(keyed, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value=SCAN_ID, display="example.com"), context
    )

    assert result.observations == ()
    assert [error.error_type for error in result.errors] == ["malformed_scan"]


def test_collector_ignores_an_unparseable_search_hit(tmp_path) -> None:
    keyed = settings_with_key(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/search/":
            return httpx.Response(200, json={"results": [{"_id": "not-a-uuid"}]})
        return httpx.Response(404, json={})

    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io", transport=httpx.MockTransport(handler)
        ),
    )
    context = make_context(keyed, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert result.observations == ()
    assert result.errors == ()


def test_collector_never_sends_a_submission(tmp_path) -> None:
    """There is no submission path. Every request must be a read."""

    keyed = settings_with_key(tmp_path)
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(200, json=scan_payload())

    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io", transport=httpx.MockTransport(handler)
        ),
        scan_id=SCAN_ID,
    )
    context = make_context(keyed, ["example.com"])

    collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value=SCAN_ID, display="example.com"), context
    )

    assert methods == ["GET"]


def test_collector_respects_the_host_and_request_ceilings(tmp_path) -> None:
    keyed = load_settings(
        database={"url": f"sqlite+pysqlite:///{tmp_path / 'atlas-test.db'}", "echo": False},
        logging={"level": "warning", "json": False},
        sources={
            "urlscan_api_key": "k",
            "urlscan_max_hosts": 2,
            "urlscan_max_requests": 1,
        },
        environment="test",
    )
    payload = scan_payload(extra_domains=("a.test", "b.test", "c.test"))
    collector = UrlscanCollector(
        settings=keyed,
        client_factory=lambda _s: httpx.Client(
            base_url="https://urlscan.io", transport=result_transport(payload)
        ),
        scan_id=SCAN_ID,
    )
    context = make_context(keyed, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value=SCAN_ID, display="example.com"),
        context,
    )

    hosts = [o for o in result.observations if isinstance(o, UrlscanHostObservation)]
    requests = [o for o in result.observations if isinstance(o, UrlscanRequestObservation)]
    assert len(hosts) == 2
    assert len(requests) == 1
