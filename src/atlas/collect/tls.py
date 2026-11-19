"""TLS certificate collection.

One job: complete a TLS handshake against an authorized host and record the leaf
certificate exactly as it was presented. Nothing else.

Why a raw handshake instead of an HTTP request: the certificate a host presents at
the connection layer is the fact under test. Wrapping it in an ``httpx`` client
would add redirect handling and body parsing to a question that only needs bytes
and a chain.

Deliberate limits:

* **Certificate validation is off.** We inspect the certificate, we do not trust
  it. A pinned ``SSLContext`` with ``CERT_NONE`` and no hostname check lets an
  expired, self-signed or mis-issued certificate be *observed* instead of aborting
  the handshake — that is exactly the case an operator needs evidence for. No
  application data is sent after the handshake.
* **SNI carries the host name.** The host is sent as SNI because that is what a
  browser does and it is what selects a virtual host.
* **Address pinning.** The socket opens to an address the scope gate already
  approved, so a resolver swap between the gate and the connection cannot redirect
  the handshake (``security.dns_rebinding_protection``).
* **The scope gate runs first.** A host outside the authorized set raises
  :class:`~atlas.errors.ScopeViolation` and aborts the run; it is never softened
  into a collection error.

The handshake is injectable so tests exercise parsing and persistence against a
synthetic certificate without opening a socket.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID

from atlas.collect.base import (
    CertificateObservation,
    CollectionError,
    CollectionTarget,
    Collector,
    CollectorContext,
    CollectorResult,
    Observation,
)
from atlas.collect.resolve import AddressResolver as HostAddressResolver
from atlas.collect.resolve import resolve_addresses
from atlas.config import Settings
from atlas.core.time import ensure_utc, utcnow
from atlas.db.enums import JobType, TargetKind
from atlas.scope.normalize import normalize_domain

__all__ = [
    "TLS_PORTS",
    "CertCollector",
    "Handshake",
    "HostAddressResolver",
    "build_pinning_context",
    "parse_certificate",
]

#: Ports a certificate pass tries, in order. 443 first; 8443 is the common
#: alternate HTTPS port operators still authorize on the same host.
TLS_PORTS: tuple[int, ...] = (443, 8443)

#: Ceiling on a single DER-encoded peer certificate (a leaf is normally ~1-2 KiB).
_MAX_CERTIFICATE_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class Handshake:
    """The facts a completed handshake produced, as raw bytes plus metadata."""

    der: bytes
    tls_version: str
    cipher: str


HandshakeFn = Callable[[str, int, str, float], Handshake]


@dataclass(frozen=True, slots=True)
class ParsedCertificate:
    """The certificate fields ATLAS persists. Pure data; no DB knowledge."""

    subject_cn: str | None
    subject: dict[str, str]
    issuer_cn: str | None
    issuer: dict[str, str]
    san: tuple[str, ...]
    serial_number: str | None
    fingerprint_sha256: str
    fingerprint_sha1: str
    not_before: datetime | None
    not_after: datetime | None
    key_algorithm: str | None
    key_bits: int | None
    signature_algorithm: str | None
    is_ca: bool
    is_self_signed: bool


def _name_to_dict(name: x509.Name) -> dict[str, str]:
    """Flatten a distinguished name to ``{short attribute name: value}``."""

    return {(attr.oid._name or attr.oid.dotted_string): str(attr.value) for attr in name}


def _first_value(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else None


def _san_entries(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return ()
    entries: list[str] = []
    for value in extension.get_values_for_type(x509.DNSName):
        text = str(value).lower().rstrip(".")
        if text and text not in entries:
            entries.append(text)
    for ip_value in extension.get_values_for_type(x509.IPAddress):
        ip_text = str(ip_value)
        if ip_text not in entries:
            entries.append(ip_text)
    return tuple(entries)


def _key_detail(certificate: x509.Certificate) -> tuple[str | None, int | None]:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 456
    return type(public_key).__name__, None


def _is_ca(certificate: x509.Certificate) -> bool:
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return False
    return bool(constraints.ca)


def _signature_algorithm(certificate: x509.Certificate) -> str | None:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        family = "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        family = "ECDSA"
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        family = "Ed25519"
    elif isinstance(public_key, ed448.Ed448PublicKey):
        family = "Ed448"
    else:
        return type(public_key).__name__
    hash_algorithm = certificate.signature_hash_algorithm
    if hash_algorithm is None:  # pragma: no cover - Ed25519/Ed448 style signatures
        return family
    return f"{family}-{hash_algorithm.name.upper()}"


def parse_certificate(certificate: x509.Certificate) -> ParsedCertificate:
    """Reduce a parsed X.509 certificate to the fields ATLAS stores."""

    key_algorithm, key_bits = _key_detail(certificate)
    return ParsedCertificate(
        subject_cn=_first_value(certificate.subject, NameOID.COMMON_NAME),
        subject=_name_to_dict(certificate.subject),
        issuer_cn=_first_value(certificate.issuer, NameOID.COMMON_NAME),
        issuer=_name_to_dict(certificate.issuer),
        san=_san_entries(certificate),
        serial_number=format(certificate.serial_number, "X"),
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
        fingerprint_sha1=certificate.fingerprint(hashes.SHA1()).hex(),
        not_before=ensure_utc(certificate.not_valid_before_utc),
        not_after=ensure_utc(certificate.not_valid_after_utc),
        key_algorithm=key_algorithm,
        key_bits=key_bits,
        signature_algorithm=_signature_algorithm(certificate),
        is_ca=_is_ca(certificate),
        is_self_signed=certificate.subject == certificate.issuer,
    )


def build_pinning_context() -> ssl.SSLContext:
    """A context that accepts any certificate and verifies no hostname.

    Used to *read* a certificate, not to establish a trusted channel: nothing
    beyond the certificate exchange is transmitted over the resulting socket.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def handshake_over_tls(host: str, port: int, address: str, timeout: float) -> Handshake:
    """Connect to ``address:port`` and handshake with SNI ``host``."""

    context = build_pinning_context()
    raw = socket.create_connection((address, port), timeout=timeout)
    tls: ssl.SSLSocket | None = None
    try:
        raw.settimeout(timeout)
        tls = context.wrap_socket(raw, server_hostname=host)
        der = tls.getpeercert(binary_form=True)
        if not der:
            raise ssl.SSLError("peer completed a handshake without presenting a certificate")
        if len(der) > _MAX_CERTIFICATE_BYTES:
            raise ssl.SSLError(
                f"peer certificate is larger than the {_MAX_CERTIFICATE_BYTES}-byte ceiling"
            )
        cipher = tls.cipher()
        return Handshake(
            der=bytes(der),
            tls_version=tls.version() or "",
            cipher=cipher[0] if cipher else "",
        )
    finally:
        if tls is not None:
            tls.close()
        else:
            raw.close()


def _failure_kind(exc: BaseException) -> str:
    """Classify a handshake failure without inventing a result."""

    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(exc, ssl.SSLError):
        return "tls_error"
    if isinstance(exc, OSError):
        return "connection_error"
    return type(exc).__name__


def covers_host(host: str, names: Iterable[str]) -> bool:
    """Whether ``host`` is covered by a SAN list. ``*.`` matches exactly one label."""

    target = host.lower().rstrip(".")
    for name in names:
        candidate = str(name).lower().rstrip(".")
        if candidate == target:
            return True
        if (
            candidate.startswith("*.")
            and target.count(".") == candidate.count(".")
            and target.split(".", 1)[1] == candidate.split(".", 1)[1]
        ):
            return True
    return False


@dataclass(slots=True)
class CertCollector(Collector):
    """Collect the leaf certificate of a host over TLS."""

    name: ClassVar[str] = "tls"
    job_type: ClassVar[JobType] = JobType.CERTIFICATES
    produces: ClassVar[tuple[str, ...]] = ("certificate",)

    settings: Settings
    ports: tuple[int, ...] = TLS_PORTS
    #: Returns candidate addresses for a name. ``None`` falls back to ``getaddrinfo``.
    address_resolver: HostAddressResolver | None = None
    #: Injectable handshake so tests never open a socket.
    handshake: HandshakeFn = field(default=handshake_over_tls, repr=False, compare=False)

    # -- public API ------------------------------------------------------- #

    def collect(self, target: CollectionTarget, context: CollectorContext) -> CollectorResult:
        self._guard(target, context)
        started = utcnow()
        observations: list[Observation] = []
        errors: list[CollectionError] = []
        stats: dict[str, Any] = {"handshakes": 0, "certificates": 0, "hosts": 0}

        hosts = self._hosts_for(target, errors)
        for host in hosts:
            if context.expired():
                errors.append(
                    CollectionError(
                        operation="tls",
                        error_type="deadline",
                        message="job deadline reached before the host was reached",
                    )
                )
                break
            stats["hosts"] += 1
            addresses = self._addresses_for(host, context, errors)
            if not addresses:
                continue
            self._collect_host(host, addresses, context, observations, errors, stats)

        stats["certificates"] = sum(
            1 for o in observations if isinstance(o, CertificateObservation)
        )
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

    def _hosts_for(self, target: CollectionTarget, errors: list[CollectionError]) -> list[str]:
        if target.kind in {TargetKind.DOMAIN, TargetKind.URL}:
            return [normalize_domain(target.value)]
        if target.kind is TargetKind.IP:
            return [str(ipaddress.ip_address(target.value))]
        errors.append(
            CollectionError(
                operation="tls",
                error_type="unsupported_target",
                message=(
                    f"certificate collection needs a name or address, not a {target.kind.value}"
                ),
            )
        )
        return []

    def _addresses_for(
        self, host: str, context: CollectorContext, errors: list[CollectionError]
    ) -> list[str]:
        try:
            parsed = ipaddress.ip_address(host)
        except ValueError:
            parsed = None

        if parsed is not None:
            candidates = [str(parsed)]
        else:
            try:
                candidates = resolve_addresses(host, self.address_resolver)
            except (OSError, ValueError) as exc:
                errors.append(self._translate("resolve", exc))
                return []

        permitted: list[str] = []
        blocked: list[str] = []
        for candidate in dict.fromkeys(candidates):
            try:
                normalized = str(ipaddress.ip_address(candidate))
            except ValueError:
                blocked.append(candidate)
                continue
            # ``permits_address`` applies both gates: the address class policy
            # (which is what forbids loopback/private/metadata ranges) and scope,
            # where an authorized name authorizes its own answers.
            if context.permits_address(normalized, via_host=host):
                permitted.append(normalized)
            else:
                blocked.append(normalized)

        if blocked:
            errors.append(
                CollectionError(
                    operation="resolve",
                    error_type="address_out_of_scope",
                    message=(
                        f"{host} resolved to address(es) that are not connectable under the "
                        f"authorized scope and network policy: {', '.join(blocked[:5])}"
                    ),
                )
            )

        ceiling = context.settings.security.max_resolved_addresses
        return permitted[:ceiling]

    def _collect_host(
        self,
        host: str,
        addresses: list[str],
        context: CollectorContext,
        observations: list[Observation],
        errors: list[CollectionError],
        stats: dict[str, Any],
    ) -> None:
        timeout = min(
            context.settings.collector.connect_timeout,
            max(0.5, context.time_remaining()),
        )
        for port in self.ports:
            for address in addresses:
                if context.expired():
                    errors.append(
                        CollectionError(
                            operation=f"tls:{port}",
                            error_type="deadline",
                            message="job deadline reached during the handshake",
                        )
                    )
                    return
                context.rate_limiter.acquire(f"tls:{address}:{port}")
                stats["handshakes"] += 1
                try:
                    result = self.handshake(host, port, address, timeout)
                except (OSError, ssl.SSLError, ValueError) as exc:
                    errors.append(
                        CollectionError(
                            operation=f"tls:{port}",
                            error_type=_failure_kind(exc),
                            message=str(exc) or type(exc).__name__,
                            retryable=isinstance(exc, TimeoutError | ssl.SSLError),
                        )
                    )
                    continue
                try:
                    certificate = x509.load_der_x509_certificate(result.der)
                except ValueError as exc:
                    errors.append(self._translate(f"tls:{port}", exc))
                    continue
                observations.append(self._observation(host, port, certificate, result))
                return  # one certificate per host is the contract

    def _observation(
        self,
        host: str,
        port: int,
        certificate: x509.Certificate,
        handshake: Handshake,
    ) -> CertificateObservation:
        parsed = parse_certificate(certificate)
        return CertificateObservation(
            source=self.name,
            observed_at=utcnow(),
            fingerprint_sha256=parsed.fingerprint_sha256,
            fingerprint_sha1=parsed.fingerprint_sha1,
            host=host,
            port=port,
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
            tls_version=handshake.tls_version or None,
        )
