"""Certificate intelligence: persistence, bindings, and expiry reporting.

The certificate a host presents is one fact. Two hosts presenting the same
certificate is a *second* fact — a shared-infrastructure observation, not evidence
of a shared owner. The schema models both: a ``Certificate`` row keyed by SHA-256
fingerprint, and a ``CertificateBinding`` per (certificate, host) pair.

What this module refuses to do:

* derive a certificate from anything but a stored ``CertificateObservation`` that
  carries a real fingerprint;
* report a certificate as "shared" without listing the exact hosts that present it;
* turn a version or issuer name into a severity. Expiry is reported as a date and a
  day count; whether that is acceptable is an operator decision, recorded in Phase 6.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.collect.base import CertificateObservation, CollectorResult
from atlas.core.time import ensure_utc, isoformat, parse_datetime, utcnow
from atlas.db.enums import AssetKind, RelationshipType, TargetKind
from atlas.db.models import (
    Asset,
    Certificate,
    CertificateBinding,
    Project,
    ScanResult,
)
from atlas.errors import NotFoundError
from atlas.scope.normalize import normalize_domain
from atlas.services.observations import (
    ensure_domain,
    ensure_ip_address,
    merge_observation_window,
    upsert_asset,
)
from atlas.services.relationships import upsert_relationship

__all__ = [
    "CertOutcome",
    "bind_certificate",
    "certificate_detail",
    "certificate_for_host",
    "certificates_list",
    "ensure_certificate",
    "expiring_certificates",
    "persist_certificate_result",
]

#: Directly observed host↔certificate presentation.
_BINDING_CONFIDENCE = 0.9
#: A shared certificate is shared infrastructure; the note says so on every row.
_SHARED_CERT_NOTE = (
    "Shared certificate SAN list indicates shared infrastructure (CDN, host, or "
    "certificate authority reuse), not shared ownership."
)
_MAX_SHARED_PEERS = 200


@dataclass(slots=True)
class CertOutcome:
    """What one certificate persistence pass did."""

    host: str
    certificate_created: bool = False
    fingerprint_sha256: str | None = None
    subject_cn: str | None = None
    issuer_cn: str | None = None
    not_after: str | None = None
    days_until_expiry: int | None = None
    expired: bool = False
    tls_version: str | None = None
    bindings: int = 0
    relationships: int = 0
    shared_with: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "certificate_created": self.certificate_created,
            "fingerprint_sha256": self.fingerprint_sha256,
            "subject_cn": self.subject_cn,
            "issuer_cn": self.issuer_cn,
            "not_after": self.not_after,
            "days_until_expiry": self.days_until_expiry,
            "expired": self.expired,
            "tls_version": self.tls_version,
            "bindings": self.bindings,
            "relationships": self.relationships,
            "shared_with": list(self.shared_with),
        }


def ensure_certificate(
    session: Session,
    project: Project,
    observation: CertificateObservation,
    *,
    source: str,
    scan_job_id: uuid.UUID | None = None,
) -> tuple[Certificate, bool]:
    """Upsert the certificate asset and its detail row. Returns ``(cert, created)``."""

    upsert = upsert_asset(
        session,
        project,
        kind=AssetKind.CERTIFICATE,
        key=observation.fingerprint_sha256,
        source=source,
        observed_at=observation.observed_at,
        label=observation.subject_cn or observation.fingerprint_sha256[:16],
        confidence=1.0,
        attributes={
            "subject_cn": observation.subject_cn,
            "issuer_cn": observation.issuer_cn,
            "not_after": isoformat(observation.not_after) if observation.not_after else None,
        },
        scan_job_id=scan_job_id,
    )
    asset = upsert.asset

    certificate = session.scalar(
        select(Certificate).where(
            Certificate.project_id == project.id,
            Certificate.fingerprint_sha256 == observation.fingerprint_sha256,
        )
    )
    created = certificate is None
    if certificate is None:
        certificate = Certificate(
            asset_id=asset.id,
            project_id=project.id,
            fingerprint_sha256=observation.fingerprint_sha256,
        )
        session.add(certificate)

    certificate.fingerprint_sha1 = observation.fingerprint_sha1 or certificate.fingerprint_sha1
    certificate.serial_number = observation.serial_number or certificate.serial_number
    certificate.subject_cn = observation.subject_cn or certificate.subject_cn
    certificate.subject = dict(observation.subject) or certificate.subject or {}
    certificate.issuer_cn = observation.issuer_cn or certificate.issuer_cn
    certificate.issuer = dict(observation.issuer) or certificate.issuer or {}
    certificate.san = list(observation.san) or certificate.san or []
    certificate.not_before = observation.not_before or certificate.not_before
    certificate.not_after = observation.not_after or certificate.not_after
    certificate.key_algorithm = observation.key_algorithm or certificate.key_algorithm
    certificate.key_bits = observation.key_bits or certificate.key_bits
    certificate.signature_algorithm = (
        observation.signature_algorithm or certificate.signature_algorithm
    )
    certificate.is_ca = observation.is_ca
    certificate.is_self_signed = observation.is_self_signed
    session.flush()
    return certificate, created


def bind_certificate(
    session: Session,
    project: Project,
    certificate: Certificate,
    asset: Asset,
    *,
    source: str,
    observed_at: Any = None,
) -> tuple[CertificateBinding, bool]:
    """Record that ``asset`` presented ``certificate``, widening the window."""

    moment = ensure_utc(observed_at or utcnow())
    binding = session.scalar(
        select(CertificateBinding).where(
            CertificateBinding.certificate_id == certificate.id,
            CertificateBinding.asset_id == asset.id,
        )
    )
    if binding is None:
        binding = CertificateBinding(
            certificate_id=certificate.id,
            asset_id=asset.id,
            project_id=project.id,
            source=source,
            first_seen=moment,
            last_seen=moment,
        )
        session.add(binding)
        session.flush()
        return binding, True

    binding.first_seen, binding.last_seen = merge_observation_window(
        binding.first_seen, binding.last_seen, moment
    )
    if source and source not in (binding.source or ""):
        binding.source = binding.source or source
    session.flush()
    return binding, False


def _presenting_asset(
    session: Session,
    project: Project,
    host: str,
    *,
    source: str,
    observed_at: Any,
    scan_job_id: uuid.UUID | None,
) -> Asset:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        domain = ensure_domain(
            session,
            project,
            normalize_domain(host),
            source=source,
            observed_at=observed_at,
            scan_job_id=scan_job_id,
        )
        return session.get(Asset, domain.asset_id)  # type: ignore[return-value]

    address = ensure_ip_address(
        session,
        project,
        host,
        source=source,
        observed_at=observed_at,
        scan_job_id=scan_job_id,
    )
    return session.get(Asset, address.asset_id)  # type: ignore[return-value]


def persist_certificate_result(
    session: Session,
    project: Project,
    result: CollectorResult,
    *,
    scan_job_id: uuid.UUID | None = None,
    link_relationships: bool = True,
) -> CertOutcome | None:
    """Write a TLS collector result: certificate, binding, and the edge between them."""

    certificates = tuple(
        observation
        for observation in result.observations
        if isinstance(observation, CertificateObservation)
    )
    if not certificates:
        return None

    observation = certificates[0]
    host = observation.host or result.target.value
    if result.target.kind not in {TargetKind.DOMAIN, TargetKind.IP, TargetKind.URL}:
        return None

    certificate, created = ensure_certificate(
        session,
        project,
        observation,
        source=result.collector,
        scan_job_id=scan_job_id,
    )
    asset = _presenting_asset(
        session,
        project,
        host,
        source=result.collector,
        observed_at=observation.observed_at,
        scan_job_id=scan_job_id,
    )
    _binding, binding_created = bind_certificate(
        session,
        project,
        certificate,
        asset,
        source=result.collector,
        observed_at=observation.observed_at,
    )

    outcome = CertOutcome(
        host=host,
        certificate_created=created,
        fingerprint_sha256=certificate.fingerprint_sha256,
        subject_cn=certificate.subject_cn,
        issuer_cn=certificate.issuer_cn,
        not_after=isoformat(certificate.not_after) if certificate.not_after else None,
        days_until_expiry=_days_until(certificate.not_after),
        expired=_is_expired(certificate.not_after),
        tls_version=observation.tls_version,
        bindings=1 if binding_created else 0,
    )

    if link_relationships:
        cert_asset = session.get(Asset, certificate.asset_id)
        if cert_asset is not None and cert_asset.id != asset.id:
            upsert_relationship(
                session,
                project,
                source=asset,
                target=cert_asset,
                rel_type=RelationshipType.PRESENTS_CERTIFICATE,
                evidence_source=result.collector,
                confidence=_BINDING_CONFIDENCE,
                observed_at=observation.observed_at,
                attributes={
                    "subject_cn": certificate.subject_cn,
                    "issuer_cn": certificate.issuer_cn,
                    "tls_version": observation.tls_version,
                },
            )
            outcome.relationships += 1
        outcome.shared_with = _shared_hosts(session, project, certificate, exclude=asset.id)

    return outcome


def _shared_hosts(
    session: Session, project: Project, certificate: Certificate, *, exclude: uuid.UUID
) -> list[str]:
    rows = session.execute(
        select(Asset.key)
        .join(CertificateBinding, CertificateBinding.asset_id == Asset.id)
        .where(
            CertificateBinding.certificate_id == certificate.id,
            CertificateBinding.asset_id != exclude,
        )
        .limit(_MAX_SHARED_PEERS)
    ).all()
    return sorted({str(row[0]) for row in rows})


def _days_until(moment: Any) -> int | None:
    if moment is None:
        return None
    return (ensure_utc(moment) - utcnow()).days


def _is_expired(moment: Any) -> bool:
    if moment is None:
        return False
    return ensure_utc(moment) < utcnow()


# --------------------------------------------------------------------------- #
# Queries used by the CLI and API                                              #
# --------------------------------------------------------------------------- #


def _certificate_row(certificate: Certificate, asset: Asset | None) -> dict[str, Any]:
    days = _days_until(certificate.not_after)
    return {
        "id": str(certificate.id),
        "fingerprint_sha256": certificate.fingerprint_sha256,
        "subject_cn": certificate.subject_cn,
        "issuer_cn": certificate.issuer_cn,
        "san": list(certificate.san or []),
        "serial_number": certificate.serial_number,
        "not_before": isoformat(certificate.not_before) if certificate.not_before else None,
        "not_after": isoformat(certificate.not_after) if certificate.not_after else None,
        "days_until_expiry": days,
        "expired": _is_expired(certificate.not_after),
        "key_algorithm": certificate.key_algorithm,
        "key_bits": certificate.key_bits,
        "signature_algorithm": certificate.signature_algorithm,
        "is_ca": certificate.is_ca,
        "is_self_signed": certificate.is_self_signed,
        "asset_key": asset.key if asset is not None else None,
    }


def certificates_list(
    session: Session,
    project: Project,
    *,
    days: int | None = None,
    include_expired: bool = True,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Certificates ordered by expiry, optionally windowed to the next ``days``."""

    statement = (
        select(Certificate, Asset)
        .join(Asset, Asset.id == Certificate.asset_id)
        .where(Certificate.project_id == project.id)
        .order_by(Certificate.not_after.is_(None), Certificate.not_after)
        .limit(max(1, limit))
    )
    fetched = [(cert, asset) for cert, asset in session.execute(statement).all()]
    rows = [_certificate_row(cert, asset) for cert, asset in fetched]
    # ``Certificate.asset_id`` is the certificate's own asset, keyed by fingerprint.
    # The hosts that presented it are the bindings, and that is what a reader means
    # by "whose certificate is this".
    presenting = _presenting_hosts(session, project, [cert.id for cert, _asset in fetched])
    for row, (cert, _asset) in zip(rows, fetched, strict=True):
        hosts = presenting.get(cert.id, [])
        row["presented_by"] = hosts
        row["presenting_host"] = hosts[0] if hosts else None
    if days is None:
        return rows
    horizon = (utcnow() + timedelta(days=max(0, days))).date()
    result: list[dict[str, Any]] = []
    for row in rows:
        if row["not_after"] is None:
            continue
        if not include_expired and row["expired"]:
            continue
        if parse_datetime(str(row["not_after"])).date() <= horizon:
            result.append(row)
    return result


def expiring_certificates(
    session: Session,
    project: Project,
    *,
    days: int = 30,
    include_expired: bool = True,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """The expiry monitor feed: certificates inside the window, soonest first."""

    return certificates_list(
        session, project, days=days, include_expired=include_expired, limit=limit
    )


def _presenting_hosts(
    session: Session, project: Project, certificate_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[str]]:
    """Presenting asset keys per certificate, first seen first."""

    if not certificate_ids:
        return {}
    statement = (
        select(CertificateBinding.certificate_id, Asset.key)
        .join(Asset, Asset.id == CertificateBinding.asset_id)
        .where(
            CertificateBinding.project_id == project.id,
            CertificateBinding.certificate_id.in_(certificate_ids),
        )
        # ``first_seen`` ties when a certificate is observed on several hosts in the
        # same pass; the key breaks the tie so the order is reproducible.
        .order_by(CertificateBinding.first_seen, Asset.key)
    )
    hosts: dict[uuid.UUID, list[str]] = {}
    for certificate_id, key in session.execute(statement).all():
        hosts.setdefault(certificate_id, []).append(key)
    return hosts


def certificate_detail(session: Session, project: Project, fingerprint: str) -> dict[str, Any]:
    """One certificate plus every host that has presented it."""

    certificate = session.scalar(
        select(Certificate).where(
            Certificate.project_id == project.id,
            Certificate.fingerprint_sha256 == fingerprint.lower(),
        )
    )
    if certificate is None:
        raise NotFoundError(
            f"no certificate with fingerprint {fingerprint}",
            context={"fingerprint": fingerprint},
        )
    asset = session.get(Asset, certificate.asset_id)
    payload = _certificate_row(certificate, asset)

    bindings = session.execute(
        select(Asset.key, Asset.kind, CertificateBinding.first_seen, CertificateBinding.last_seen)
        .join(CertificateBinding, CertificateBinding.asset_id == Asset.id)
        .where(CertificateBinding.certificate_id == certificate.id)
        # ``first_seen`` ties when a certificate is observed on several hosts in the
        # same pass; the key breaks the tie so the order is reproducible.
        .order_by(CertificateBinding.first_seen, Asset.key)
    ).all()
    payload["presented_by"] = [
        {
            "host": str(row[0]),
            "kind": row[1].value if hasattr(row[1], "value") else str(row[1]),
            "first_seen": isoformat(row[2]),
            "last_seen": isoformat(row[3]),
        }
        for row in bindings
    ]
    payload["shared_note"] = _SHARED_CERT_NOTE if len(payload["presented_by"]) > 1 else None
    return payload


def certificate_observations(
    session: Session, project: Project, *, limit: int = 200
) -> list[ScanResult]:
    """Raw archived certificate observations, newest first (provenance view)."""

    return list(
        session.scalars(
            select(ScanResult)
            .where(
                ScanResult.project_id == project.id,
                ScanResult.result_type == "tls.certificate",
            )
            .order_by(ScanResult.observed_at.desc())
            .limit(max(1, limit))
        )
    )


def certificate_for_host(session: Session, project: Project, host: str) -> Certificate | None:
    """The certificate currently bound to ``host``, if one was collected."""

    statement = (
        select(Certificate)
        .join(CertificateBinding, CertificateBinding.certificate_id == Certificate.id)
        .join(Asset, Asset.id == CertificateBinding.asset_id)
        .where(Certificate.project_id == project.id, Asset.key == host)
        .order_by(CertificateBinding.last_seen.desc())
        .limit(1)
    )
    return session.scalar(statement)
