"""Asset queries for the CLI and (later) the API."""

from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from atlas.core.time import isoformat
from atlas.db.enums import AssetKind
from atlas.db.models import (
    Asset,
    Certificate,
    DnsRecord,
    Domain,
    Finding,
    IpAddress,
    Project,
    Relationship,
    Service,
)
from atlas.errors import NotFoundError

__all__ = ["asset_detail", "asset_summary", "get_asset", "list_assets"]


def list_assets(
    session: Session,
    project: Project,
    *,
    kind: AssetKind | None = None,
    active: bool | None = None,
    search: str | None = None,
    limit: int = 100,
) -> list[Asset]:
    statement = select(Asset).where(Asset.project_id == project.id)
    if kind is not None:
        statement = statement.where(Asset.kind == kind)
    if active is not None:
        statement = statement.where(Asset.is_active.is_(active))
    if search:
        statement = statement.where(Asset.key.ilike(f"%{search}%"))
    statement = statement.order_by(Asset.kind, Asset.key).limit(max(1, limit))
    return list(session.scalars(statement))


def get_asset(session: Session, project: Project, key: str) -> Asset:
    asset = session.scalar(select(Asset).where(Asset.project_id == project.id, Asset.key == key))
    if asset is None:
        raise NotFoundError(f"asset not found: {key}", context={"key": key})
    return asset


def asset_summary(asset: Asset) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "kind": asset.kind.value,
        "key": asset.key,
        "label": asset.label,
        "source": asset.source,
        "confidence": round(asset.confidence, 3),
        "is_active": asset.is_active,
        "first_seen": isoformat(asset.first_seen),
        "last_seen": isoformat(asset.last_seen),
    }


def asset_detail(session: Session, asset: Asset) -> dict[str, Any]:
    """Summary plus kind-specific detail, relationship counts and finding counts."""

    payload = asset_summary(asset)
    payload["attributes"] = dict(asset.attributes or {})

    match asset.kind:
        case AssetKind.DOMAIN:
            domain = session.scalar(select(Domain).where(Domain.asset_id == asset.id))
            if domain is not None:
                record_count = int(
                    session.scalar(
                        select(func.count(DnsRecord.id)).where(DnsRecord.domain_id == domain.id)
                    )
                    or 0
                )
                payload["domain"] = {
                    "fqdn": domain.fqdn,
                    "registrable_domain": domain.registrable_domain,
                    "tld": domain.tld,
                    "is_apex": domain.is_apex,
                    "record_count": record_count,
                }
        case AssetKind.IP_ADDRESS:
            ip = session.scalar(select(IpAddress).where(IpAddress.asset_id == asset.id))
            if ip is not None:
                payload["ip_address"] = {
                    "address": ip.address,
                    "version": ip.version,
                    "is_private": ip.is_private,
                    "is_global": ip.is_global,
                }
        case AssetKind.CERTIFICATE:
            certificate = session.scalar(
                select(Certificate).where(Certificate.asset_id == asset.id)
            )
            if certificate is not None:
                payload["certificate"] = {
                    "fingerprint_sha256": certificate.fingerprint_sha256,
                    "subject_cn": certificate.subject_cn,
                    "issuer_cn": certificate.issuer_cn,
                    "san": list(certificate.san or []),
                    "not_before": isoformat(certificate.not_before)
                    if certificate.not_before
                    else None,
                    "not_after": isoformat(certificate.not_after)
                    if certificate.not_after
                    else None,
                }
        case AssetKind.SERVICE:
            service = session.scalar(select(Service).where(Service.asset_id == asset.id))
            if service is not None:
                payload["service"] = {
                    "port": service.port,
                    "transport": service.transport,
                    "state": service.state.value,
                    "tls_enabled": service.tls_enabled,
                    "banner": service.banner,
                }

    payload["relationships"] = {
        "out": int(
            session.scalar(
                select(func.count(Relationship.id)).where(Relationship.source_asset_id == asset.id)
            )
            or 0
        ),
        "in": int(
            session.scalar(
                select(func.count(Relationship.id)).where(Relationship.target_asset_id == asset.id)
            )
            or 0
        ),
    }
    payload["findings"] = int(
        session.scalar(select(func.count(Finding.id)).where(Finding.asset_id == asset.id)) or 0
    )
    return payload
