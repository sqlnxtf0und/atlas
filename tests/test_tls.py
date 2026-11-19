"""TLS certificate collection: parsing, scope gating, and failure handling.

Certificates are generated in-test with ``cryptography`` so every assertion runs
against a real DER encoding. No socket is opened: the handshake is injected.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import ssl
from collections.abc import Iterator

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from atlas.collect.base import CertificateObservation, CollectionTarget
from atlas.collect.tls import (
    CertCollector,
    Handshake,
    build_pinning_context,
    covers_host,
    parse_certificate,
)
from atlas.config import Settings
from atlas.db.enums import TargetKind
from atlas.errors import ScopeViolation
from support import RecordingLimiter, make_context

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def build_certificate(
    *,
    common_name: str = "example.com",
    san: tuple[str, ...] = ("example.com", "www.example.com"),
    issuer_cn: str = "Test Intermediate CA",
    self_signed: bool = False,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
    is_ca: bool = False,
    include_ips: tuple[str, ...] = (),
) -> x509.Certificate:
    """Mint a certificate with real extensions and a real signature."""

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ATLAS Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    issuer = (
        subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    )
    entries: list[x509.GeneralName] = [x509.DNSName(name) for name in san]
    entries.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in include_ips)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - dt.timedelta(days=30))
        .not_valid_after(not_after or NOW + dt.timedelta(days=60))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(entries), critical=False)
    return builder.sign(key, hashes.SHA256())


def handshake_for(certificate: x509.Certificate, *, tls_version: str = "TLSv1.3") -> Handshake:
    return Handshake(
        der=certificate.public_bytes(serialization.Encoding.DER),
        tls_version=tls_version,
        cipher="TLS_AES_256_GCM_SHA384",
    )


def collector_for(
    settings: Settings,
    certificate: x509.Certificate,
    *,
    addresses: tuple[str, ...] = ("203.0.113.10",),
    tls_version: str = "TLSv1.3",
) -> tuple[CertCollector, list[tuple[str, int, str, float]]]:
    calls: list[tuple[str, int, str, float]] = []

    def handshake(host: str, port: int, address: str, timeout: float) -> Handshake:
        calls.append((host, port, address, timeout))
        return handshake_for(certificate, tls_version=tls_version)

    class Resolver:
        def resolve(self, host: str) -> list[str]:
            del host
            return list(addresses)

    collector = CertCollector(settings=settings, address_resolver=Resolver(), handshake=handshake)
    return collector, calls


@pytest.fixture
def certificate() -> x509.Certificate:
    return build_certificate()


# --------------------------------------------------------------------------- #
# Parsing                                                                      #
# --------------------------------------------------------------------------- #


def test_parse_certificate_extracts_every_field_atlas_stores(
    certificate: x509.Certificate,
) -> None:
    parsed = parse_certificate(certificate)

    assert parsed.subject_cn == "example.com"
    assert parsed.subject["organizationName"] == "ATLAS Test"
    assert parsed.issuer_cn == "Test Intermediate CA"
    assert parsed.san == ("example.com", "www.example.com")
    assert parsed.fingerprint_sha256 == certificate.fingerprint(hashes.SHA256()).hex()
    assert parsed.fingerprint_sha1 == certificate.fingerprint(hashes.SHA1()).hex()
    assert parsed.key_algorithm == "RSA"
    assert parsed.key_bits == 2048
    assert parsed.signature_algorithm == "RSA-SHA256"
    assert parsed.is_ca is False
    assert parsed.is_self_signed is False
    assert parsed.not_before == NOW - dt.timedelta(days=30)
    assert parsed.not_after == NOW + dt.timedelta(days=60)


def test_parse_certificate_detects_self_signed_ca() -> None:
    parsed = parse_certificate(
        build_certificate(common_name="internal.lab", self_signed=True, is_ca=True)
    )

    assert parsed.is_self_signed is True
    assert parsed.is_ca is True
    assert parsed.issuer_cn == "internal.lab"


def test_parse_certificate_records_ip_sans() -> None:
    parsed = parse_certificate(
        build_certificate(san=("example.com",), include_ips=("198.51.100.7",))
    )

    assert ("198.51.100.7" in parsed.san) is True
    assert parsed.san[0] == "example.com"


def test_parse_certificate_without_san_returns_empty_tuple() -> None:
    parsed = parse_certificate(build_certificate(san=()))

    assert parsed.san == ()


def test_parse_certificate_handles_ec_keys_and_sha384_signatures() -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ec.example.com")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=1))
        .sign(key, hashes.SHA384())
    )

    parsed = parse_certificate(certificate)

    assert parsed.key_algorithm == "EC"
    assert parsed.key_bits == 384
    assert parsed.signature_algorithm == "ECDSA-SHA384"


# --------------------------------------------------------------------------- #
# Coverage helper                                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("example.com", True),
        ("www.example.com", True),
        ("a.example.com", True),
        ("example.com.evil.test", False),
        ("deep.a.example.com", False),
    ],
)
def test_covers_host_treats_wildcards_as_one_label(host: str, expected: bool) -> None:
    assert covers_host(host, ("example.com", "*.example.com")) is expected


def test_covers_host_wildcard_does_not_cover_the_apex_or_two_labels() -> None:
    assert covers_host("example.com", ("*.example.com",)) is False
    assert covers_host("a.b.example.com", ("*.example.com",)) is False
    assert covers_host("a.example.com", ("*.example.com",)) is True


def test_pinning_context_disables_verification() -> None:
    context = build_pinning_context()

    assert context.verify_mode is ssl.CERT_NONE
    assert context.check_hostname is False


# --------------------------------------------------------------------------- #
# Collector                                                                    #
# --------------------------------------------------------------------------- #


def test_collector_records_a_certificate_observation(
    settings: Settings, certificate: x509.Certificate
) -> None:
    collector, calls = collector_for(settings, certificate)
    context = make_context(settings, ["example.com", "203.0.113.0/24"])
    target = CollectionTarget(kind=TargetKind.DOMAIN, value="example.com")

    result = collector.collect(target, context)

    assert result.errors == ()
    assert len(result.observations) == 1
    observation = result.observations[0]
    assert isinstance(observation, CertificateObservation)
    assert observation.host == "example.com"
    assert observation.port == 443
    assert observation.tls_version == "TLSv1.3"
    assert observation.subject_cn == "example.com"
    assert observation.fingerprint_sha256 == parse_certificate(certificate).fingerprint_sha256
    # SNI carries the host name; the socket opens to the approved address.
    assert calls == [("example.com", 443, "203.0.113.10", pytest.approx(calls[0][3]))]
    assert result.stats["handshakes"] == 1
    assert result.stats["certificates"] == 1


def test_collector_is_rate_limited_per_address_and_port(
    settings: Settings, certificate: x509.Certificate
) -> None:
    collector, _calls = collector_for(settings, certificate)
    limiter = RecordingLimiter()
    context = make_context(settings, ["example.com", "203.0.113.0/24"], limiter=limiter)

    collector.collect(CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context)

    assert "tls:203.0.113.10:443" in limiter.keys


def test_collector_refuses_an_out_of_scope_target(
    settings: Settings, certificate: x509.Certificate
) -> None:
    collector, calls = collector_for(settings, certificate)
    context = make_context(settings, ["other.test", "203.0.113.0/24"])

    with pytest.raises(ScopeViolation):
        collector.collect(CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context)
    assert calls == []


def test_collector_dials_an_address_its_authorized_name_resolves_to(
    settings: Settings, certificate: x509.Certificate
) -> None:
    """A domain rule authorizes its own answers; the address need not be listed."""

    collector, calls = collector_for(settings, certificate, addresses=("192.0.2.99",))
    context = make_context(settings, ["example.com"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert [error.error_type for error in result.errors] == []
    assert [call[2] for call in calls] == ["192.0.2.99"]


def test_collector_never_dials_a_private_address_even_when_the_name_is_authorized(
    settings: Settings, certificate: x509.Certificate
) -> None:
    """Network policy outranks the scope rule — this is the SSRF gate."""

    for address in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.10"):
        collector, calls = collector_for(settings, certificate, addresses=(address,))
        context = make_context(settings, ["example.com"])

        result = collector.collect(
            CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
        )

        assert calls == [], address
        assert [error.error_type for error in result.errors] == ["address_out_of_scope"], address


def test_collector_permits_a_private_address_only_when_the_policy_allows_it(
    settings: Settings, certificate: x509.Certificate
) -> None:
    collector, calls = collector_for(settings, certificate, addresses=("10.0.0.5",))
    context = make_context(settings, ["example.com"], allow_private=True)

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert [error.error_type for error in result.errors] == []
    assert [call[2] for call in calls] == ["10.0.0.5"]


def test_collector_never_dials_an_address_for_an_unauthorized_host(
    settings: Settings, certificate: x509.Certificate
) -> None:
    collector, calls = collector_for(settings, certificate, addresses=("192.0.2.99",))
    context = make_context(settings, ["other.test"])

    with pytest.raises(ScopeViolation):
        collector.collect(CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context)
    assert calls == []


def test_collector_records_handshake_failures_without_inventing_a_certificate(
    settings: Settings,
) -> None:
    def failing(host: str, port: int, address: str, timeout: float) -> Handshake:
        del host, port, address, timeout
        raise ssl.SSLError("handshake failure")

    class Resolver:
        def resolve(self, host: str) -> list[str]:
            del host
            return ["203.0.113.10"]

    collector = CertCollector(settings=settings, address_resolver=Resolver(), handshake=failing)
    context = make_context(settings, ["example.com", "203.0.113.0/24"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert result.observations == ()
    assert {error.error_type for error in result.errors} == {"tls_error"}
    # Both TLS ports are attempted before the host is given up on.
    assert len(result.errors) == 2


def test_collector_rejects_a_cidr_target(settings: Settings, certificate: x509.Certificate) -> None:
    collector, calls = collector_for(settings, certificate)
    context = make_context(settings, ["203.0.113.0/24"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.CIDR, value="203.0.113.0/24"), context
    )

    assert calls == []
    assert [error.error_type for error in result.errors] == ["unsupported_target"]


def test_collector_handles_a_bare_ip_target(
    settings: Settings, certificate: x509.Certificate
) -> None:
    collector, calls = collector_for(settings, certificate, addresses=())
    context = make_context(settings, ["198.51.100.7"])

    result = collector.collect(CollectionTarget(kind=TargetKind.IP, value="198.51.100.7"), context)

    assert result.errors == ()
    assert calls[0][0] == "198.51.100.7"
    assert calls[0][2] == "198.51.100.7"


def test_collector_stops_after_the_first_presented_certificate(
    settings: Settings, certificate: x509.Certificate
) -> None:
    collector, calls = collector_for(
        settings, certificate, addresses=("203.0.113.10", "203.0.113.11")
    )
    context = make_context(settings, ["example.com", "203.0.113.0/24"])

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert len(result.observations) == 1
    assert len(calls) == 1


def test_collector_honours_the_deadline(settings: Settings, certificate: x509.Certificate) -> None:
    collector, calls = collector_for(settings, certificate)
    context = make_context(settings, ["example.com", "203.0.113.0/24"], deadline_seconds=-1.0)

    result = collector.collect(
        CollectionTarget(kind=TargetKind.DOMAIN, value="example.com"), context
    )

    assert calls == []
    assert [error.error_type for error in result.errors] == ["deadline"]


@pytest.fixture(autouse=True)
def _freeze_time(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep certificate validity and observation timestamps comparable."""

    import atlas.collect.tls as tls_module

    real_utcnow = tls_module.utcnow
    monkeypatch.setattr(tls_module, "utcnow", lambda: NOW)
    yield
    monkeypatch.setattr(tls_module, "utcnow", real_utcnow)
