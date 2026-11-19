"""SQLAlchemy ORM models — the canonical ATLAS schema.

Design notes
------------
* ``Asset`` is the graph node. ``Domain``, ``IpAddress``, ``Asn``, ``Certificate``
  and ``Service`` are detail tables hanging off an asset (1:1 for the first four,
  1:N for services), so the graph engine only ever walks ``assets`` and
  ``relationships``.
* Observation columns (``first_seen`` / ``last_seen``) are never overwritten with
  "now" unless a collector actually observed the thing again.
* Nothing is deleted to express disappearance: ``Asset.is_active`` flips to false
  and an ``AssetChange`` row records the event.
* All timestamps are aware UTC (see ``atlas.core.time``).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from atlas.core.time import utcnow
from atlas.db.base import Base, TimestampMixin, uuid_pk
from atlas.db.enums import (
    AssetChangeType,
    AssetKind,
    DnsRecordType,
    EvidenceKind,
    ExposureLevel,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    JobStatus,
    JobType,
    RelationshipType,
    ScopeKind,
    ScopeMode,
    ServiceState,
    TargetKind,
    TechnologyCategory,
)

__all__ = [
    "Asn",
    "Asset",
    "AssetChange",
    "AuditEvent",
    "Certificate",
    "CertificateBinding",
    "DnsRecord",
    "Domain",
    "Evidence",
    "Finding",
    "IpAddress",
    "Project",
    "Relationship",
    "ScanJob",
    "ScanResult",
    "ScopeRule",
    "Service",
    "ServiceTechnology",
    "Snapshot",
    "SnapshotAsset",
    "Target",
    "Technology",
]


def _enum(enum_cls: type, length: int = 48) -> SAEnum:
    """Portable enum column: stored as VARCHAR, validated in Python."""

    return SAEnum(
        enum_cls,
        native_enum=False,
        length=length,
        values_callable=lambda members: [str(member.value) for member in members],
        validate_strings=True,
    )


def _observed_now() -> datetime:
    return utcnow()


# --------------------------------------------------------------------------- #
# Tenancy                                                                      #
# --------------------------------------------------------------------------- #


class Project(Base, TimestampMixin):
    """Top-level tenant boundary. Everything else is scoped to a project."""

    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=180)
    is_archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    scope_rules: Mapped[list[ScopeRule]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    targets: Mapped[list[Target]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    assets: Mapped[list[Asset]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    snapshots: Mapped[list[Snapshot]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )


class ScopeRule(Base, TimestampMixin):
    """One authorization statement. Default-deny: no include rule, no collection."""

    __tablename__ = "scope_rules"
    __table_args__ = (
        UniqueConstraint("project_id", "kind", "pattern", "mode", name="uq_scope_rules_identity"),
        Index("ix_scope_rules_project_active", "project_id", "is_active"),
        CheckConstraint("length(pattern) > 0", name="pattern_not_empty"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[ScopeKind] = mapped_column(_enum(ScopeKind, 16), nullable=False)
    pattern: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_pattern: Mapped[str] = mapped_column(String(512), nullable=False)
    mode: Mapped[ScopeMode] = mapped_column(_enum(ScopeMode, 16), nullable=False)
    include_subdomains: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    note: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(120), nullable=False, default="cli")

    project: Mapped[Project] = relationship(back_populates="scope_rules")


class Target(Base, TimestampMixin):
    """A named root submitted for collection. Must be scope-permitted at write time."""

    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("project_id", "kind", "normalized", name="uq_targets_identity"),
        Index("ix_targets_project_active", "project_id", "is_active"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    scope_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scope_rules.id", ondelete="SET NULL")
    )
    kind: Mapped[TargetKind] = mapped_column(_enum(TargetKind, 16), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    normalized: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)

    project: Mapped[Project] = relationship(back_populates="targets")
    jobs: Mapped[list[ScanJob]] = relationship(back_populates="target")


# --------------------------------------------------------------------------- #
# Assets                                                                       #
# --------------------------------------------------------------------------- #


class Asset(Base, TimestampMixin):
    """Canonical graph node. ``(project_id, kind, key)`` is the identity."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("project_id", "kind", "key", name="uq_assets_identity"),
        Index("ix_assets_project_kind", "project_id", "kind"),
        Index("ix_assets_project_active", "project_id", "is_active"),
        Index("ix_assets_project_last_seen", "project_id", "last_seen"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[AssetKind] = mapped_column(_enum(AssetKind, 24), nullable=False)
    key: Mapped[str] = mapped_column(String(512), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    first_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )

    project: Mapped[Project] = relationship(back_populates="assets")
    domain: Mapped[Domain | None] = relationship(
        back_populates="asset", uselist=False, cascade="all, delete-orphan"
    )
    ip_address: Mapped[IpAddress | None] = relationship(
        back_populates="asset", uselist=False, cascade="all, delete-orphan"
    )
    asn: Mapped[Asn | None] = relationship(
        back_populates="asset", uselist=False, cascade="all, delete-orphan"
    )
    certificate: Mapped[Certificate | None] = relationship(
        back_populates="asset", uselist=False, cascade="all, delete-orphan"
    )
    services: Mapped[list[Service]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    outgoing: Mapped[list[Relationship]] = relationship(
        back_populates="source_asset",
        foreign_keys="Relationship.source_asset_id",
        passive_deletes=True,
    )
    incoming: Mapped[list[Relationship]] = relationship(
        back_populates="target_asset",
        foreign_keys="Relationship.target_asset_id",
        passive_deletes=True,
    )


class Domain(Base, TimestampMixin):
    """Domain detail. ``parent_id`` expresses the subdomain tree."""

    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("asset_id", name="uq_domains_asset"),
        UniqueConstraint("project_id", "fqdn", name="uq_domains_fqdn"),
        Index("ix_domains_registrable", "project_id", "registrable_domain"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("domains.id", ondelete="SET NULL")
    )
    fqdn: Mapped[str] = mapped_column(String(253), nullable=False)
    registrable_domain: Mapped[str] = mapped_column(String(253), nullable=False)
    tld: Mapped[str | None] = mapped_column(String(63))
    is_apex: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    asset: Mapped[Asset] = relationship(back_populates="domain")
    parent: Mapped[Domain | None] = relationship(remote_side="Domain.id", back_populates="children")
    children: Mapped[list[Domain]] = relationship(back_populates="parent")
    dns_records: Mapped[list[DnsRecord]] = relationship(
        back_populates="domain", cascade="all, delete-orphan"
    )


class Asn(Base, TimestampMixin):
    """Autonomous system detail. Enrichment only — never expands scope."""

    __tablename__ = "asns"
    __table_args__ = (
        UniqueConstraint("asset_id", name="uq_asns_asset"),
        UniqueConstraint("project_id", "number", name="uq_asns_number"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    organisation: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(2))
    # ``registry`` shadows ``DeclarativeBase.registry``; SQLAlchemy maps it fine,
    # but mypy cannot reconcile the declared class attribute with the metaclass one.
    registry: Mapped[str | None] = mapped_column(String(32))  # type: ignore[assignment,misc]

    asset: Mapped[Asset] = relationship(back_populates="asn")
    addresses: Mapped[list[IpAddress]] = relationship(back_populates="asn")


class IpAddress(Base, TimestampMixin):
    """IPv4/IPv6 address detail."""

    __tablename__ = "ip_addresses"
    __table_args__ = (
        UniqueConstraint("asset_id", name="uq_ip_addresses_asset"),
        UniqueConstraint("project_id", "address", name="uq_ip_addresses_address"),
        Index("ix_ip_addresses_asn", "asn_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    asn_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("asns.id", ondelete="SET NULL")
    )
    address: Mapped[str] = mapped_column(String(45), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    is_private: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_reserved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_global: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    asset: Mapped[Asset] = relationship(back_populates="ip_address")
    asn: Mapped[Asn | None] = relationship(back_populates="addresses")


class Certificate(Base, TimestampMixin):
    """X.509 certificate detail, keyed by SHA-256 fingerprint."""

    __tablename__ = "certificates"
    __table_args__ = (
        UniqueConstraint("asset_id", name="uq_certificates_asset"),
        UniqueConstraint("project_id", "fingerprint_sha256", name="uq_certificates_fingerprint"),
        Index("ix_certificates_expiry", "project_id", "not_after"),
        Index("ix_certificates_issuer", "project_id", "issuer_cn"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    fingerprint_sha1: Mapped[str | None] = mapped_column(String(40))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    subject_cn: Mapped[str | None] = mapped_column(String(255))
    subject: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    issuer_cn: Mapped[str | None] = mapped_column(String(255))
    issuer: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    san: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    not_before: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    key_algorithm: Mapped[str | None] = mapped_column(String(32))
    key_bits: Mapped[int | None] = mapped_column(Integer)
    signature_algorithm: Mapped[str | None] = mapped_column(String(64))
    is_ca: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    asset: Mapped[Asset] = relationship(back_populates="certificate")
    bindings: Mapped[list[CertificateBinding]] = relationship(
        back_populates="certificate", cascade="all, delete-orphan"
    )


class CertificateBinding(Base, TimestampMixin):
    """Which asset presented which certificate, and when it was observed."""

    __tablename__ = "certificate_bindings"
    __table_args__ = (
        UniqueConstraint("certificate_id", "asset_id", name="uq_certificate_bindings_pair"),
        Index("ix_certificate_bindings_asset", "asset_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    certificate_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="tls")
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )

    certificate: Mapped[Certificate] = relationship(back_populates="bindings")


class Service(Base, TimestampMixin):
    """A network service observed on a host asset."""

    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "transport", name="uq_services_endpoint"),
        Index("ix_services_project_port", "project_id", "port"),
        CheckConstraint("port > 0 AND port <= 65535", name="port_range"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    transport: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    protocol: Mapped[str | None] = mapped_column(String(32))
    state: Mapped[ServiceState] = mapped_column(
        _enum(ServiceState, 16), nullable=False, default=ServiceState.UNKNOWN
    )
    banner: Mapped[str | None] = mapped_column(Text)
    tls_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tls_version: Mapped[str | None] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )

    asset: Mapped[Asset] = relationship(back_populates="services")
    technologies: Mapped[list[ServiceTechnology]] = relationship(
        back_populates="service", cascade="all, delete-orphan"
    )


class Technology(Base, TimestampMixin):
    """Fingerprint catalogue entry (server, framework, CMS, library)."""

    __tablename__ = "technologies"
    __table_args__ = (
        UniqueConstraint("name", "version", "category", name="uq_technologies_identity"),
        Index("ix_technologies_name", "name"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    category: Mapped[TechnologyCategory] = mapped_column(
        _enum(TechnologyCategory, 24), nullable=False, default=TechnologyCategory.OTHER
    )
    vendor: Mapped[str | None] = mapped_column(String(120))
    cpe: Mapped[str | None] = mapped_column(String(255))
    is_vulnerable_version: Mapped[bool | None] = mapped_column(Boolean)


class ServiceTechnology(Base, TimestampMixin):
    """Association: a service serves a technology, with confidence and evidence."""

    __tablename__ = "service_technologies"
    __table_args__ = (
        UniqueConstraint("service_id", "technology_id", name="uq_service_technologies_pair"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    service_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("services.id", ondelete="CASCADE"), nullable=False
    )
    technology_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("technologies.id", ondelete="CASCADE"), nullable=False
    )
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    evidence: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )

    service: Mapped[Service] = relationship(back_populates="technologies")
    technology: Mapped[Technology] = relationship()


class DnsRecord(Base, TimestampMixin):
    """A DNS record observation for a domain, with a live observation window."""

    __tablename__ = "dns_records"
    __table_args__ = (
        UniqueConstraint("domain_id", "record_type", "value", name="uq_dns_records_value"),
        Index("ix_dns_records_domain_type", "domain_id", "record_type"),
        Index("ix_dns_records_project", "project_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    domain_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    record_type: Mapped[DnsRecordType] = mapped_column(_enum(DnsRecordType, 12), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    ttl: Mapped[int | None] = mapped_column(Integer)
    priority: Mapped[int | None] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="dns")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )

    domain: Mapped[Domain] = relationship(back_populates="dns_records")


# --------------------------------------------------------------------------- #
# Relationships and findings                                                   #
# --------------------------------------------------------------------------- #


class Relationship(Base, TimestampMixin):
    """A typed, evidence-bearing edge between two assets."""

    __tablename__ = "relationships"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "source_asset_id",
            "target_asset_id",
            "rel_type",
            name="uq_relationships_edge",
        ),
        Index("ix_relationships_project_type", "project_id", "rel_type"),
        Index("ix_relationships_source", "source_asset_id"),
        Index("ix_relationships_target", "target_asset_id"),
        CheckConstraint("source_asset_id <> target_asset_id", name="no_self_edge"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    rel_type: Mapped[RelationshipType] = mapped_column(_enum(RelationshipType, 32), nullable=False)
    evidence_source: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    first_observed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    last_observed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    source_asset: Mapped[Asset] = relationship(
        back_populates="outgoing", foreign_keys=[source_asset_id]
    )
    target_asset: Mapped[Asset] = relationship(
        back_populates="incoming", foreign_keys=[target_asset_id]
    )


class Finding(Base, TimestampMixin):
    """A scored security observation. Severity and confidence are independent."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_id", "dedup_key", name="uq_findings_dedup"),
        Index("ix_findings_project_severity", "project_id", "severity"),
        Index("ix_findings_project_status", "project_id", "status"),
        Index("ix_findings_asset", "asset_id"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE")
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    dedup_key: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[FindingCategory] = mapped_column(_enum(FindingCategory, 32), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(_enum(FindingSeverity, 16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    exposure: Mapped[ExposureLevel] = mapped_column(
        _enum(ExposureLevel, 16), nullable=False, default=ExposureLevel.UNKNOWN
    )
    business_relevance: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    detection_method: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reasoning: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, 24), nullable=False, default=FindingStatus.OPEN
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="findings")
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base, TimestampMixin):
    """Raw proof supporting a finding or a job. Content-addressed by SHA-256."""

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_finding", "finding_id"),
        Index("ix_evidence_project_collected", "project_id", "collected_at"),
        Index("ix_evidence_hash", "content_hash"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE")
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    kind: Mapped[EvidenceKind] = mapped_column(_enum(EvidenceKind, 32), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_uri: Mapped[str | None] = mapped_column(String(1024))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[str | None] = mapped_column(Text)
    content_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )
    meta: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    finding: Mapped[Finding | None] = relationship(back_populates="evidence")


# --------------------------------------------------------------------------- #
# Execution and history                                                        #
# --------------------------------------------------------------------------- #


class ScanJob(Base, TimestampMixin):
    """One collection execution. Immutable once finished except for status fields."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_project_status", "project_id", "status"),
        Index("ix_scan_jobs_project_created", "project_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL")
    )
    job_type: Mapped[JobType] = mapped_column(_enum(JobType, 24), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        _enum(JobStatus, 16), nullable=False, default=JobStatus.PENDING
    )
    params: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    stats: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False, default="cli")
    celery_task_id: Mapped[str | None] = mapped_column(String(64))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    target: Mapped[Target | None] = relationship(back_populates="jobs")
    results: Mapped[list[ScanResult]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )


class ScanResult(Base, TimestampMixin):
    """Immutable raw observation produced by a collector."""

    __tablename__ = "scan_results"
    __table_args__ = (
        Index("ix_scan_results_job_type", "scan_job_id", "result_type"),
        Index("ix_scan_results_asset", "asset_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    result_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )

    job: Mapped[ScanJob] = relationship(back_populates="results")


class Snapshot(Base, TimestampMixin):
    """Point-in-time capture of a project's asset and relationship set."""

    __tablename__ = "snapshots"
    __table_args__ = (Index("ix_snapshots_project_created", "project_id", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    label: Mapped[str | None] = mapped_column(String(120))
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    relationship_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    note: Mapped[str | None] = mapped_column(Text)

    project: Mapped[Project] = relationship(back_populates="snapshots")
    members: Mapped[list[SnapshotAsset]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )


class SnapshotAsset(Base):
    """Snapshot membership plus a per-asset digest for cheap change detection."""

    __tablename__ = "snapshot_assets"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "asset_id", name="uq_snapshot_assets_pair"),
        Index("ix_snapshot_assets_asset", "asset_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    asset_kind: Mapped[AssetKind] = mapped_column(_enum(AssetKind, 24), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)

    snapshot: Mapped[Snapshot] = relationship(back_populates="members")


class AssetChange(Base):
    """Append-only change event derived from snapshot comparison."""

    __tablename__ = "asset_changes"
    __table_args__ = (Index("ix_asset_changes_project_detected", "project_id", "detected_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("snapshots.id", ondelete="SET NULL")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL")
    )
    asset_key: Mapped[str] = mapped_column(String(512), nullable=False)
    asset_kind: Mapped[AssetKind] = mapped_column(_enum(AssetKind, 24), nullable=False)
    change_type: Mapped[AssetChangeType] = mapped_column(_enum(AssetChangeType, 16), nullable=False)
    previous_digest: Mapped[str | None] = mapped_column(String(64))
    current_digest: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )


class AuditEvent(Base):
    """Append-only record of every mutating operator or API action."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_project_created", "project_id", "created_at"),
        Index("ix_audit_events_action", "action"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE")
    )
    actor: Mapped[str] = mapped_column(String(120), nullable=False, default="cli")
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    object_type: Mapped[str | None] = mapped_column(String(64))
    object_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    ip_address: Mapped[str | None] = mapped_column(String(45))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_observed_now
    )

    project: Mapped[Project | None] = relationship(back_populates="audit_events")
