"""Certificate, HTTP and urlscan persistence, plus the discovery wiring.

The collectors are exercised with injected fakes so persistence is tested against
the exact observations production produces, with no network involved.
"""

from __future__ import annotations

import datetime as dt

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.collect.base import (
    CollectionTarget,
    CollectorResult,
    CookieObservation,
    HttpObservation,
    TechnologyObservation,
    UrlscanHostObservation,
    UrlscanRequestObservation,
    UrlscanScanObservation,
)
from atlas.collect.registry import CollectorRegistry
from atlas.collect.tls import CertCollector
from atlas.collect.urlscan import UrlscanCollector
from atlas.config import Settings, load_settings
from atlas.core.time import ensure_utc
from atlas.db.enums import JobStatus, JobType, RelationshipType, TargetKind
from atlas.db.models import (
    Asset,
    Certificate,
    CertificateBinding,
    Relationship,
    ScanJob,
    ScanResult,
    Service,
)
from atlas.services.certificates import (
    certificate_detail,
    certificates_list,
    expiring_certificates,
    persist_certificate_result,
)
from atlas.services.discovery import discover
from atlas.services.http import http_snapshot, persist_http_result
from atlas.services.scopes import add_rule
from atlas.services.urlscan import ingest_urlscan_scan, persist_urlscan_result
from test_tls import build_certificate, handshake_for

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

#: Test settings that permit the documentation addresses the fakes resolve to.
OPEN_SETTINGS = load_settings(
    logging={"level": "warning", "json": False},
    security={"allow_private_addresses": True},
    environment="test",
)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def certificate_result(
    certificate,
    *,
    host: str = "example.com",
    tls_version: str = "TLSv1.3",
    collector: str = "tls",
) -> CollectorResult:
    from atlas.collect.tls import parse_certificate

    parsed = parse_certificate(certificate)
    from atlas.collect.base import CertificateObservation

    observation = CertificateObservation(
        source=collector,
        observed_at=NOW,
        fingerprint_sha256=parsed.fingerprint_sha256,
        fingerprint_sha1=parsed.fingerprint_sha1,
        host=host,
        port=443,
        serial_number=parsed.serial_number,
        subject_cn=parsed.subject_cn,
        subject=parsed.subject,
        issuer_cn=parsed.issuer_cn,
        issuer=parsed.issuer,
        san=parsed.san,
        not_before=parsed.not_before,
        not_after=parsed.not_after,
        key_algorithm=parsed.key_algorithm,
        key_bits=parsed.key_bits,
        signature_algorithm=parsed.signature_algorithm,
        is_ca=parsed.is_ca,
        is_self_signed=parsed.is_self_signed,
        tls_version=tls_version,
    )
    return CollectorResult(
        collector=collector,
        target=CollectionTarget(kind=TargetKind.DOMAIN, value=host),
        observations=(observation,),
        errors=(),
        started_at=NOW,
        finished_at=NOW,
        stats={},
    )


def http_result(host: str = "example.com", **overrides) -> CollectorResult:
    payload = {
        "source": "http",
        "observed_at": NOW,
        "url": f"https://{host}/",
        "host": host,
        "scheme": "https",
        "port": 443,
        "status": 200,
        "server": "nginx/1.24.0",
        "tls_version": "TLSv1.3",
        "cookies": (CookieObservation(name="sid", value="1", secure=True, http_only=True),),
        "technologies": (
            TechnologyObservation(
                name="nginx",
                category="server",
                evidence="Server: nginx/1.24.0",
                version="1.24.0",
            ),
        ),
        "headers": {"server": "nginx/1.24.0"},
    }
    payload.update(overrides)
    observation = HttpObservation(**payload)
    return CollectorResult(
        collector="http",
        target=CollectionTarget(kind=TargetKind.DOMAIN, value=host),
        observations=(observation,),
        errors=(),
        started_at=NOW,
        finished_at=NOW,
        stats={},
    )


def urlscan_result(
    *, domain: str = "example.com", hosts: tuple[tuple[str, bool], ...] | None = None
) -> CollectorResult:
    observations: list[object] = [
        UrlscanScanObservation(
            source="urlscan",
            observed_at=NOW,
            scan_id="0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d",
            page_url=f"https://{domain}/",
            page_domain=domain,
            page_ip="203.0.113.10",
            page_in_scope=True,
            asn=64500,
            title="Example",
            scanned_at=NOW,
            verdict_score=5,
            verdict_malicious=False,
        )
    ]
    for host, in_scope in hosts or ((domain, True), ("cdn.thirdparty.test", False)):
        observations.append(
            UrlscanHostObservation(
                source="urlscan",
                observed_at=NOW,
                host=host,
                kind="domain",
                scan_id="0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d",
                in_scope=in_scope,
            )
        )
    observations.append(
        UrlscanRequestObservation(
            source="urlscan",
            observed_at=NOW,
            url=f"https://{domain}/",
            host=domain,
            scan_id="0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d",
            status=200,
            port=443,
            scheme="https",
            tls_protocol="TLS 1.3",
            server="nginx",
            in_scope=True,
        )
    )
    return CollectorResult(
        collector="urlscan",
        target=CollectionTarget(kind=TargetKind.DOMAIN, value=domain),
        observations=tuple(observations),  # type: ignore[arg-type]
        errors=(),
        started_at=NOW,
        finished_at=NOW,
        stats={},
    )


# --------------------------------------------------------------------------- #
# Certificate persistence                                                      #
# --------------------------------------------------------------------------- #


def test_persist_certificate_creates_asset_binding_and_edge(
    session: Session, project, **__: object
) -> None:
    result = certificate_result(build_certificate())

    outcome = persist_certificate_result(session, project, result)
    session.commit()

    assert outcome is not None
    assert outcome.certificate_created is True
    assert outcome.bindings == 1
    assert outcome.relationships == 1
    assert outcome.subject_cn == "example.com"
    assert outcome.issuer_cn == "Test Intermediate CA"

    certificate = session.scalar(select(Certificate))
    assert certificate is not None
    # SQLite returns naive datetimes for timezone-aware columns.
    assert ensure_utc(certificate.not_after) == NOW + dt.timedelta(days=60)
    assert certificate.key_bits == 2048

    asset = session.scalar(select(Asset).where(Asset.key == "example.com"))
    assert asset is not None
    binding = session.scalar(select(CertificateBinding))
    assert binding is not None
    assert binding.asset_id == asset.id
    assert binding.certificate_id == certificate.id

    edge = session.scalar(
        select(Relationship).where(Relationship.rel_type == RelationshipType.PRESENTS_CERTIFICATE)
    )
    assert edge is not None
    assert edge.source_asset_id == asset.id
    assert edge.confidence > 0


def test_second_host_presenting_the_same_certificate_adds_a_binding(
    session: Session, project
) -> None:
    certificate = build_certificate()
    persist_certificate_result(
        session, project, certificate_result(certificate, host="example.com")
    )
    outcome = persist_certificate_result(
        session, project, certificate_result(certificate, host="www.example.com")
    )
    session.commit()

    assert outcome is not None
    assert outcome.certificate_created is False
    assert len(session.scalars(select(Certificate)).all()) == 1
    assert len(session.scalars(select(CertificateBinding)).all()) == 2
    # The shared-certificate candidate list is explicit about who else presents it.
    assert outcome.shared_with == ["example.com"]


def test_certificate_detail_lists_every_presenting_host(session: Session, project) -> None:
    certificate = build_certificate()
    persist_certificate_result(session, project, certificate_result(certificate))
    persist_certificate_result(
        session, project, certificate_result(certificate, host="www.example.com")
    )
    session.commit()

    payload = certificate_detail(
        session,
        project,
        certificate.fingerprint(
            __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()
        ).hex(),
    )

    assert {entry["host"] for entry in payload["presented_by"]} == {
        "example.com",
        "www.example.com",
    }
    assert payload["shared_note"] is not None
    assert "not shared ownership" in payload["shared_note"]


def test_certificate_rows_name_the_presenting_host_not_the_fingerprint(
    session: Session, project
) -> None:
    """The certificate's own asset is keyed by fingerprint; the row must not show it."""

    certificate = build_certificate()
    persist_certificate_result(session, project, certificate_result(certificate))
    persist_certificate_result(
        session, project, certificate_result(certificate, host="www.example.com")
    )
    session.commit()

    row = certificates_list(session, project)[0]
    assert row["presenting_host"] == "example.com"
    assert row["presented_by"] == ["example.com", "www.example.com"]
    assert row["asset_key"] != row["presenting_host"]


def test_certificate_list_and_expiry_window(
    session: Session, project, monkeypatch: pytest.MonkeyPatch
) -> None:
    import atlas.services.certificates as certificates_module

    monkeypatch.setattr(certificates_module, "utcnow", lambda: NOW)
    soon = build_certificate(
        common_name="soon.test",
        san=("soon.test",),
        not_after=NOW + dt.timedelta(days=5),
    )
    later = build_certificate(
        common_name="later.test",
        san=("later.test",),
        not_after=NOW + dt.timedelta(days=200),
    )
    persist_certificate_result(session, project, certificate_result(soon, host="soon.test"))
    persist_certificate_result(session, project, certificate_result(later, host="later.test"))
    session.commit()

    everything = certificates_list(session, project)
    assert {row["subject_cn"] for row in everything} == {"soon.test", "later.test"}

    windowed = expiring_certificates(session, project, days=30)
    assert [row["subject_cn"] for row in windowed] == ["soon.test"]


def test_persist_certificate_returns_none_without_an_observation(session: Session, project) -> None:
    empty = CollectorResult.empty(
        "tls", CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), started_at=NOW
    )
    assert persist_certificate_result(session, project, empty) is None


# --------------------------------------------------------------------------- #
# HTTP persistence                                                             #
# --------------------------------------------------------------------------- #


def test_persist_http_creates_a_service_and_keeps_cookie_attributes(
    session: Session, project
) -> None:
    outcome = persist_http_result(session, project, http_result())
    session.commit()

    assert outcome is not None
    assert outcome.service_created is True
    assert outcome.status == 200
    assert outcome.port == 443
    assert outcome.tls_enabled is True
    assert outcome.cookies == [
        {
            "name": "sid",
            "secure": True,
            "http_only": True,
            "same_site": None,
            "domain": None,
            "path": None,
            "max_age": None,
            "expires": None,
        }
    ]
    service = session.scalar(select(Service))
    assert service is not None
    assert service.port == 443
    assert service.protocol == "https"
    assert service.tls_version == "TLSv1.3"
    assert service.banner == "nginx/1.24.0"


def test_persist_http_is_idempotent_for_the_same_endpoint(session: Session, project) -> None:
    persist_http_result(session, project, http_result())
    outcome = persist_http_result(session, project, http_result())
    session.commit()

    assert outcome is not None
    assert outcome.service_created is False
    assert len(session.scalars(select(Service)).all()) == 1


def test_persist_http_links_a_redirect_only_to_a_known_asset(session: Session, project) -> None:
    from atlas.services.observations import ensure_domain

    ensure_domain(session, project, "www.example.com", source="dns", observed_at=NOW)
    session.commit()

    outcome = persist_http_result(
        session,
        project,
        http_result(redirect_chain=("https://example.com/", "https://www.example.com/")),
    )
    session.commit()

    assert outcome is not None
    assert outcome.redirects == 1
    assert outcome.relationships == 1
    edge = session.scalar(
        select(Relationship).where(Relationship.rel_type == RelationshipType.REDIRECTS_TO)
    )
    assert edge is not None


def test_persist_http_does_not_promote_an_unknown_redirect_target(
    session: Session, project
) -> None:
    outcome = persist_http_result(
        session,
        project,
        http_result(redirect_chain=("https://example.com/", "https://elsewhere.test/")),
    )
    session.commit()

    assert outcome is not None
    assert outcome.relationships == 0
    assert session.scalar(select(Asset).where(Asset.key == "elsewhere.test")) is None


def test_http_snapshot_raises_for_a_host_without_observations(session: Session, project) -> None:
    from atlas.errors import ValidationError

    with pytest.raises(ValidationError):
        http_snapshot(session, project, "example.com")


# --------------------------------------------------------------------------- #
# urlscan persistence                                                          #
# --------------------------------------------------------------------------- #


def test_persist_urlscan_only_creates_assets_for_in_scope_hosts(session: Session, project) -> None:
    outcome = persist_urlscan_result(session, project, urlscan_result())
    session.commit()

    assert outcome is not None
    assert outcome.hosts_in_scope == 1
    assert outcome.hosts_out_of_scope == 1
    assert outcome.services == 1
    assert outcome.verdict_score == 5

    keys = {asset.key for asset in session.scalars(select(Asset)).all()}
    assert "example.com" in keys
    assert "cdn.thirdparty.test" not in keys
    # The scan's own address is recorded as an asset the page resolves to.
    assert "203.0.113.10" in keys


def test_persist_urlscan_never_creates_a_certificate_row(session: Session, project) -> None:
    from atlas.collect.base import UrlscanCertificateObservation

    result = urlscan_result()
    observation = UrlscanCertificateObservation(
        source="urlscan",
        observed_at=NOW,
        scan_id="0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d",
        subject_name="*.example.com",
        issuer="Let's Encrypt",
    )
    combined = CollectorResult(
        collector=result.collector,
        target=result.target,
        observations=(*result.observations, observation),
        errors=(),
        started_at=NOW,
        finished_at=NOW,
        stats={},
    )

    persist_urlscan_result(session, project, combined)
    session.commit()

    assert session.scalar(select(Certificate)) is None


def test_persist_urlscan_records_a_resolution_edge(session: Session, project) -> None:
    persist_urlscan_result(session, project, urlscan_result())
    session.commit()

    edge = session.scalar(
        select(Relationship).where(Relationship.rel_type == RelationshipType.RESOLVES_TO)
    )
    assert edge is not None
    # Third-party provenance is explicit in the edge, and confidence is lower.
    assert edge.evidence_source == "urlscan"
    assert edge.confidence < 0.9


# --------------------------------------------------------------------------- #
# Discovery wiring                                                             #
# --------------------------------------------------------------------------- #


def keyed_settings(tmp_path) -> Settings:
    return load_settings(
        database={"url": f"sqlite+pysqlite:///{tmp_path / 'atlas-3.db'}", "echo": False},
        logging={"level": "warning", "json": False},
        sources={"urlscan_api_key": "test-key"},
        environment="test",
    )


def install_urlscan_fake(
    monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport, scan_id: str
) -> None:
    """Make the collector the ingestion service builds answer from ``transport``.

    The service references ``UrlscanCollector`` as both a class (for ``.name``) and
    a constructor, so the double is a class whose ``__init__`` delegates to the real
    one with a mock transport bound.
    """

    import atlas.collect.urlscan as urlscan_module

    real = urlscan_module.UrlscanCollector

    class Fake:
        name = real.name

        def __init__(self, **kwargs: object) -> None:
            self._inner = real(
                **kwargs,  # type: ignore[arg-type]
                client_factory=lambda _settings: httpx.Client(
                    base_url="https://urlscan.io", transport=transport
                ),
            )

        def __getattr__(self, item: str) -> object:
            return getattr(self._inner, item)

    monkeypatch.setattr(urlscan_module, "UrlscanCollector", Fake)


def tls_registry(certificate) -> CollectorRegistry:
    registry = CollectorRegistry()
    registry.register(
        CertCollector.name,
        lambda settings: CertCollector(
            settings=settings,
            address_resolver=lambda_resolver(["203.0.113.10"]),
            handshake=lambda host, port, address, timeout: handshake_for(certificate),
        ),
        job_type=JobType.CERTIFICATES,
    )
    return registry


def lambda_resolver(addresses: list[str]):
    class _Resolver:
        def resolve(self, host: str) -> list[str]:
            del host
            return list(addresses)

    return _Resolver()


def http_registry(body: bytes = b"ok " * 20):
    registry = CollectorRegistry()
    from atlas.collect.http import HttpCollector

    def factory(_settings):
        return httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, headers={"Server": "nginx/1.24.0"}, content=body
                )
            ),
            follow_redirects=True,
        )

    registry.register(
        HttpCollector.name,
        lambda settings: HttpCollector(settings=settings, client_factory=factory),
        job_type=JobType.HTTP,
    )
    return registry


def test_discovery_persists_certificates_and_archives_the_observation(
    session: Session, project, monkeypatch
) -> None:
    certificate = build_certificate()
    add_rule(session, project, pattern="example.com")
    # The fakes resolve to documentation addresses; the network must allow them.
    add_rule(session, project, pattern="203.0.113.0/24")
    session.commit()

    monkeypatch.setattr("atlas.collect.tls.utcnow", lambda: NOW)
    outcome = discover(
        session,
        project,
        OPEN_SETTINGS,
        "example.com",
        job_type=JobType.CERTIFICATES,
        registry=tls_registry(certificate),
    )

    assert outcome.errors == []
    assert outcome.status == JobStatus.SUCCEEDED.value
    assert outcome.certs is not None
    assert outcome.certs.certificate_created is True
    assert outcome.scan_results == 1

    archived = session.scalar(select(ScanResult))
    assert archived is not None
    assert archived.result_type == "tls.certificate"
    job = session.scalar(select(ScanJob))
    assert job is not None
    assert job.status is JobStatus.SUCCEEDED


def test_discovery_persists_http_and_records_the_service(session: Session, project) -> None:
    add_rule(session, project, pattern="example.com")
    # The fakes resolve to documentation addresses; the network must allow them.
    add_rule(session, project, pattern="203.0.113.0/24")
    session.commit()

    outcome = discover(
        session,
        project,
        OPEN_SETTINGS,
        "example.com",
        job_type=JobType.HTTP,
        registry=http_registry(),
    )

    assert outcome.status == JobStatus.SUCCEEDED.value
    assert outcome.http is not None
    assert outcome.http.status == 200
    assert outcome.http.technologies[0]["name"] == "nginx"
    assert session.scalar(select(ScanResult)).result_type == "http.response"
    assert session.scalar(select(Service)) is not None


def test_full_job_skips_an_unconfigured_source_without_failing(
    session: Session, project, monkeypatch
) -> None:
    add_rule(session, project, pattern="example.com")
    # The fakes resolve to documentation addresses; the network must allow them.
    add_rule(session, project, pattern="203.0.113.0/24")
    session.commit()

    registry = tls_registry(build_certificate())
    registry.register(
        UrlscanCollector.name,
        lambda settings: UrlscanCollector(settings=settings),
        job_type=JobType.URLSCAN,
    )

    outcome = discover(
        session,
        project,
        OPEN_SETTINGS,
        "example.com",
        job_type=JobType.FULL,
        registry=registry,
    )

    assert outcome.status == JobStatus.SUCCEEDED.value
    assert [entry["collector"] for entry in outcome.skipped_collectors] == ["urlscan"]
    assert "urlscan_api_key" in outcome.skipped_collectors[0]["reason"]


def test_explicit_urlscan_job_reports_not_configured(session: Session, project) -> None:
    add_rule(session, project, pattern="example.com")
    # The fakes resolve to documentation addresses; the network must allow them.
    add_rule(session, project, pattern="203.0.113.0/24")
    session.commit()

    registry = CollectorRegistry()
    registry.register(
        UrlscanCollector.name,
        lambda settings: UrlscanCollector(settings=settings),
        job_type=JobType.URLSCAN,
    )

    outcome = discover(
        session,
        project,
        OPEN_SETTINGS,
        "example.com",
        job_type=JobType.URLSCAN,
        registry=registry,
    )

    assert outcome.status == JobStatus.PARTIAL.value
    assert [error["error_type"] for error in outcome.errors] == ["not_configured"]


def test_discovery_rejects_a_scan_id_for_a_non_urlscan_job(session: Session, project) -> None:
    from atlas.errors import ValidationError

    add_rule(session, project, pattern="example.com")
    # The fakes resolve to documentation addresses; the network must allow them.
    add_rule(session, project, pattern="203.0.113.0/24")
    session.commit()

    with pytest.raises(ValidationError):
        discover(
            session,
            project,
            OPEN_SETTINGS,
            "example.com",
            job_type=JobType.HTTP,
            scan_id="0a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d",
        )


def test_ingest_urlscan_scan_persists_and_audits(
    session: Session, project, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from atlas.db.models import AuditEvent
    from test_urlscan import SCAN_ID, result_transport, scan_payload

    add_rule(session, project, pattern="example.com")
    # The fakes resolve to documentation addresses; the network must allow them.
    add_rule(session, project, pattern="203.0.113.0/24")
    session.commit()

    settings = keyed_settings(tmp_path)

    # The ingestion service builds its own collector from the registry, so the
    # capture is installed at the factory boundary rather than the constructor.
    install_urlscan_fake(monkeypatch, result_transport(scan_payload()), SCAN_ID)
    ingestion = ingest_urlscan_scan(session, project, settings, SCAN_ID)

    assert ingestion.status == JobStatus.SUCCEEDED.value
    assert ingestion.outcome.scans == 1
    # ``example.com`` and the scan's captured address are both in scope.
    assert ingestion.outcome.hosts_in_scope == 2
    job = session.scalar(select(ScanJob).where(ScanJob.job_type == JobType.URLSCAN))
    assert job is not None
    assert job.params == {"scan_id": SCAN_ID}
    event = session.scalar(select(AuditEvent).where(AuditEvent.action == "urlscan.ingest"))
    assert event is not None
