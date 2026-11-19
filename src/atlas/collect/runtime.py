"""Runtime assembly for collectors.

Kept separate from the collectors themselves so a test can build a context with a
fake limiter and a fixed deadline without dragging in settings plumbing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from atlas.collect.base import CollectorContext, RateLimiterProtocol
from atlas.collect.ratelimit import RateLimiter
from atlas.config import Settings
from atlas.core.time import utcnow
from atlas.scope.matcher import ScopeSet

__all__ = ["build_context", "build_rate_limiter"]


def build_rate_limiter(settings: Settings, **overrides: Any) -> RateLimiter:
    """Global pacing plus a per-host bucket derived from the concurrency limit."""

    collector = settings.collector
    return RateLimiter(
        global_rate=collector.requests_per_second,
        global_burst=max(1.0, float(collector.requests_per_second)),
        per_key_rate=collector.requests_per_second,
        per_key_burst=max(1.0, float(collector.per_host_concurrency)),
        **overrides,
    )


def build_context(
    settings: Settings,
    scope: ScopeSet,
    *,
    job_id: Any = None,
    actor: str = "cli",
    deadline: datetime | None = None,
    rate_limiter: RateLimiterProtocol | None = None,
) -> CollectorContext:
    """Assemble the context for one job. Deadline defaults to the job budget."""

    resolved_deadline = deadline or (
        utcnow() + timedelta(seconds=settings.collector.job_deadline_seconds)
    )
    return CollectorContext(
        settings=settings,
        scope=scope,
        rate_limiter=rate_limiter or build_rate_limiter(settings),
        deadline=resolved_deadline,
        job_id=job_id,
        actor=actor,
    )
