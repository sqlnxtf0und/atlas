"""Value normalization for scope rules and targets.

Everything that reaches the matcher is normalized exactly once, here. Invalid
input raises :class:`atlas.errors.ValidationError` — never a silently mangled
string.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from atlas.db.enums import ScopeKind
from atlas.errors import ValidationError

__all__ = [
    "infer_scope_kind",
    "normalize_cidr",
    "normalize_domain",
    "normalize_ip",
    "normalize_pattern",
    "normalize_url",
    "registrable_domain",
    "split_hostname",
]

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MAX_HOSTNAME = 253

#: Multi-label public suffixes that need three labels to reach the registrable domain.
#: Curated, not exhaustive — the full PSL is a Phase 2 data dependency.
_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "me.uk",
        "ltd.uk",
        "plc.uk",
        "net.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "id.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "go.jp",
        "co.za",
        "org.za",
        "net.za",
        "gov.za",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.tr",
        "net.tr",
        "org.tr",
        "gov.tr",
        "com.mx",
        "com.ar",
        "com.sg",
        "com.hk",
        "com.tw",
        "co.kr",
        "or.kr",
        "co.il",
        "co.id",
        "co.th",
        "com.pl",
        "com.ua",
        "com.ru",
        "co.at",
        "or.at",
        "eu.com",
        "us.com",
        "uk.com",
        "de.com",
    }
)


def normalize_domain(value: str) -> str:
    """Lowercase, IDNA-encode and validate a hostname. No scheme, no port, no path."""

    raw = value.strip().lower().rstrip(".")
    if not raw:
        raise ValidationError("domain is empty")
    if "://" in raw or "/" in raw or "?" in raw or "#" in raw or "@" in raw:
        raise ValidationError(f"not a bare hostname: {value!r}")
    if ":" in raw:
        raise ValidationError(f"hostname must not contain a port: {value!r}")

    try:
        ascii_host = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"hostname is not IDNA-encodable: {value!r}") from exc

    if len(ascii_host) > _MAX_HOSTNAME:
        raise ValidationError(f"hostname exceeds {_MAX_HOSTNAME} characters: {value!r}")
    labels = ascii_host.split(".")
    if len(labels) < 2 and ascii_host != "localhost":
        raise ValidationError(f"hostname needs at least two labels: {value!r}")
    for label in labels:
        if not _LABEL.match(label):
            raise ValidationError(f"invalid hostname label {label!r} in {value!r}")
    if labels[-1].isdigit():
        raise ValidationError(f"top-level label must not be numeric: {value!r}")
    return ascii_host


def normalize_ip(value: str) -> str:
    """Validate and canonicalise an IPv4/IPv6 address."""

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValidationError(f"not a valid IP address: {value!r}") from exc


def normalize_cidr(value: str) -> str:
    """Validate and canonicalise a CIDR block (host bits are cleared)."""

    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValidationError(f"not a valid CIDR block: {value!r}") from exc


def normalize_url(value: str) -> str:
    """Validate an http(s) URL and return it without a trailing slash on bare hosts."""

    candidate = value.strip()
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValidationError(f"URL scheme must be http or https: {value!r}")
    if not parts.hostname:
        raise ValidationError(f"URL has no host: {value!r}")
    host = normalize_domain(parts.hostname)
    port = f":{parts.port}" if parts.port else ""
    path = parts.path.rstrip("/") or ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{host}{port}{path}{query}"


def infer_scope_kind(pattern: str) -> ScopeKind:
    """Infer the rule kind from the shape of the pattern."""

    candidate = pattern.strip()
    if candidate.upper().startswith("AS") and candidate[2:].isdigit():
        return ScopeKind.ASN
    if "://" in candidate:
        return ScopeKind.URL
    if "/" in candidate:
        return ScopeKind.CIDR
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return ScopeKind.DOMAIN
    return ScopeKind.IP


def normalize_pattern(pattern: str, kind: ScopeKind | None = None) -> tuple[ScopeKind, str]:
    """Normalize a scope pattern and return ``(kind, normalized)``.

    Wildcard domains (``*.example.com``) are normalized to ``example.com`` with
    ``include_subdomains`` implied by the caller — the ``*`` never survives.
    """

    resolved_kind = kind or infer_scope_kind(pattern)
    candidate = pattern.strip()

    match resolved_kind:
        case ScopeKind.DOMAIN:
            if candidate.startswith("*."):
                candidate = candidate[2:]
            return resolved_kind, normalize_domain(candidate)
        case ScopeKind.IP:
            return resolved_kind, normalize_ip(candidate)
        case ScopeKind.CIDR:
            return resolved_kind, normalize_cidr(candidate)
        case ScopeKind.URL:
            return resolved_kind, normalize_url(candidate)
        case ScopeKind.ASN:
            digits = candidate.upper().removeprefix("AS").strip()
            if not digits.isdigit():
                raise ValidationError(f"not a valid ASN: {pattern!r}")
            number = int(digits)
            if not 1 <= number <= 4_294_967_295:
                raise ValidationError(f"ASN out of range: {pattern!r}")
            return resolved_kind, f"AS{number}"
    raise ValidationError(f"unsupported scope kind: {resolved_kind}")


def split_hostname(host: str) -> tuple[str, str]:
    """Split a hostname into ``(subdomain, registrable_domain)``.

    Uses a curated multi-label suffix list, not the full Public Suffix List.
    Callers that need PSL accuracy must supply it explicitly.
    """

    normalized = normalize_domain(host)
    labels = normalized.split(".")
    if len(labels) == 2:
        return "", normalized
    suffix_two = ".".join(labels[-2:])
    if suffix_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        registrable = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3])
    else:
        registrable = suffix_two
        subdomain = ".".join(labels[:-2])
    return subdomain, registrable


def registrable_domain(host: str) -> str:
    """Return the registrable domain (eTLD+1) for a hostname."""

    return split_hostname(host)[1]
