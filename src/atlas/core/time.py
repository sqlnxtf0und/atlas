"""Time helpers. Every timestamp ATLAS writes is timezone-aware UTC."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

__all__ = ["ensure_utc", "isoformat", "parse_datetime", "utc_today", "utcnow"]


def utcnow() -> datetime:
    """Current time as an aware UTC datetime."""

    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Normalise a datetime to aware UTC (naive values are assumed UTC)."""

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def isoformat(value: datetime) -> str:
    """Render as ``2026-11-19T06:00:11Z``."""

    return ensure_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_datetime(value: str) -> datetime:
    """Parse an ISO-8601 string, accepting a trailing ``Z``."""

    cleaned = value.strip()
    if cleaned.endswith(("Z", "z")):
        cleaned = cleaned[:-1] + "+00:00"
    return ensure_utc(datetime.fromisoformat(cleaned))


def utc_today() -> datetime:
    """Midnight UTC of the current day."""

    now = utcnow()
    return now - timedelta(
        hours=now.hour, minutes=now.minute, seconds=now.second, microseconds=now.microsecond
    )
