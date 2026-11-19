"""HTTP intelligence: persistence and lookup.

The collector produces an :class:`~atlas.collect.base.HttpObservation`; this module
turns it into state:

* the responding host becomes an asset (only if the target was authorized — the
  discovery gate already checked it);
* the endpoint becomes a ``Service`` row keyed by ``(asset, port, transport)``;
* a redirect edge is written **only** when the destination is already a collected
  asset. A redirect into third-party infrastructure is recorded on the observation,
  never promoted into a node.

Cookie attributes are stored as they were sent. Nothing here assigns a severity:
"missing Secure" is an audit result, and severity belongs to the analysis phase.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from atlas.collect.base import CollectorResult, HttpObservation
from atlas.core.time import isoformat
from atlas.db.enums import AssetKind, RelationshipType, ServiceState, TargetKind
from atlas.db.models import Asset, Project, ScanResult, Service
from atlas.errors import ValidationError
from atlas.scope.normalize import normalize_domain
from atlas.services.observations import ensure_domain, ensure_ip_address, upsert_service
from atlas.services.relationships import upsert_relationship

__all__ = [
    "HttpOutcome",
    "http_services",
    "http_snapshot",
    "http_snapshots",
    "persist_http_result",
]

_REDIRECT_CONFIDENCE = 0.9


@dataclass(slots=True)
class HttpOutcome:
    """What one HTTP persistence pass produced."""

    host: str
    url: str
    status: int | None = None
    final_url: str | None = None
    server: str | None = None
    tls_enabled: bool = False
    tls_version: str | None = None
    port: int | None = None
    service_created: bool = False
    redirects: int = 0
    technologies: list[dict[str, Any]] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    relationships: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "url": self.url,
            "status": self.status,
            "final_url": self.final_url,
            "server": self.server,
            "tls_enabled": self.tls_enabled,
            "tls_version": self.tls_version,
            "port": self.port,
            "service_created": self.service_created,
            "redirects": self.redirects,
            "technologies": list(self.technologies),
            "cookies": list(self.cookies),
            "relationships": self.relationships,
        }


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


def persist_http_result(
    session: Session,
    project: Project,
    result: CollectorResult,
    *,
    scan_job_id: uuid.UUID | None = None,
    link_relationships: bool = True,
) -> HttpOutcome | None:
    """Write an HTTP collector result: asset → service → redirect edges."""

    observations = tuple(
        observation
        for observation in result.observations
        if isinstance(observation, HttpObservation)
    )
    if not observations:
        return None
    observation = observations[0]
    if result.target.kind not in {TargetKind.DOMAIN, TargetKind.IP, TargetKind.URL}:
        return None

    host = observation.host or result.target.value
    asset = _presenting_asset(
        session,
        project,
        host,
        source=result.collector,
        observed_at=observation.observed_at,
        scan_job_id=scan_job_id,
    )

    service, created = upsert_service(
        session,
        project,
        asset,
        port=observation.port,
        transport="tcp",
        protocol=observation.scheme.lower() or None,
        state=ServiceState.OPEN,
        tls_enabled=observation.is_https,
        tls_version=observation.tls_version,
        banner=observation.server,
        source=result.collector,
        observed_at=observation.observed_at,
    )

    outcome = HttpOutcome(
        host=host,
        url=observation.url,
        status=observation.status,
        final_url=observation.final_url,
        server=observation.server,
        tls_enabled=observation.is_https,
        tls_version=observation.tls_version,
        port=service.port,
        service_created=created,
        redirects=max(0, len(observation.redirect_chain) - 1),
        technologies=[tech.as_dict() for tech in observation.technologies],
        cookies=[cookie.as_dict() for cookie in observation.cookies],
    )

    if link_relationships:
        outcome.relationships += _link_redirects(
            session,
            project,
            source_asset=asset,
            observation=observation,
        )
    return outcome


def _link_redirects(
    session: Session,
    project: Project,
    *,
    source_asset: Asset,
    observation: HttpObservation,
) -> int:
    """Link redirect hops that land on an asset ATLAS already knows about."""

    linked = 0
    for hop in observation.redirect_chain[1:]:
        try:
            host = urlsplit(hop).hostname
        except ValueError:
            continue
        if not host:
            continue
        target_asset = session.scalar(
            select(Asset).where(
                Asset.project_id == project.id,
                Asset.key == host.lower().rstrip("."),
                Asset.kind.in_([AssetKind.DOMAIN, AssetKind.IP_ADDRESS]),
            )
        )
        if target_asset is None or target_asset.id == source_asset.id:
            continue
        upsert_relationship(
            session,
            project,
            source=source_asset,
            target=target_asset,
            rel_type=RelationshipType.REDIRECTS_TO,
            evidence_source="http",
            confidence=_REDIRECT_CONFIDENCE,
            observed_at=observation.observed_at,
            attributes={"from": observation.url, "to": hop, "status": observation.status},
        )
        linked += 1
    return linked


# --------------------------------------------------------------------------- #
# Queries used by the CLI and API                                              #
# --------------------------------------------------------------------------- #


def http_snapshots(session: Session, project: Project, *, limit: int = 200) -> list[dict[str, Any]]:
    """Archived HTTP observations, newest first, one entry per exchange."""

    rows = session.scalars(
        select(ScanResult)
        .where(
            ScanResult.project_id == project.id,
            ScanResult.result_type == "http.response",
        )
        .order_by(ScanResult.observed_at.desc())
        .limit(max(1, limit))
    )
    return [dict(row.payload or {}) for row in rows]


def http_snapshot(session: Session, project: Project, host: str) -> dict[str, Any]:
    """The most recent HTTP observation for one host."""

    normalized = host.strip().lower().rstrip(".")
    for payload in http_snapshots(session, project, limit=2000):
        if str(payload.get("host") or "").lower() == normalized:
            return payload
    raise ValidationError(
        f"no HTTP observation recorded for {normalized}: run atlas collect {normalized} --type http"
    )


def http_services(session: Session, project: Project, *, host: str) -> list[dict[str, Any]]:
    """Services recorded on a host, with the TLS facts attached to each."""

    asset = session.scalar(
        select(Asset).where(
            Asset.project_id == project.id,
            Asset.key == host.strip().lower().rstrip("."),
        )
    )
    if asset is None:
        return []
    rows = session.scalars(
        select(Service)
        .where(Service.asset_id == asset.id)
        .order_by(Service.port, Service.transport)
    )
    return [
        {
            "port": service.port,
            "transport": service.transport,
            "protocol": service.protocol,
            "state": service.state.value,
            "tls_enabled": service.tls_enabled,
            "tls_version": service.tls_version,
            "banner": service.banner,
            "first_seen": isoformat(service.first_seen),
            "last_seen": isoformat(service.last_seen),
        }
        for service in rows
    ]
