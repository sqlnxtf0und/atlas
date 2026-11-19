"""Database layer: models, engine, sessions.

Import order matters: ``models`` must be imported so every mapper is registered
before ``Base.metadata`` is used for schema creation or migrations.
"""

from __future__ import annotations

from atlas.db.base import Base, TimestampMixin
from atlas.db.models import (
    Asn,
    Asset,
    AssetChange,
    AuditEvent,
    Certificate,
    CertificateBinding,
    DnsRecord,
    Domain,
    Evidence,
    Finding,
    IpAddress,
    Project,
    Relationship,
    ScanJob,
    ScanResult,
    ScopeRule,
    Service,
    ServiceTechnology,
    Snapshot,
    SnapshotAsset,
    Target,
    Technology,
)
from atlas.db.session import (
    build_engine,
    build_session_factory,
    create_all,
    get_engine,
    get_session_factory,
    ping,
    reset_engine_cache,
    session_scope,
)

__all__ = [
    "Asn",
    "Asset",
    "AssetChange",
    "AuditEvent",
    "Base",
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
    "TimestampMixin",
    "build_engine",
    "build_session_factory",
    "create_all",
    "get_engine",
    "get_session_factory",
    "ping",
    "reset_engine_cache",
    "session_scope",
]
