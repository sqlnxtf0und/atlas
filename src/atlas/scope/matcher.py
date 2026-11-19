"""Scope matching.

The matcher answers exactly one question: *is this value inside the project's
authorized scope right now?* Exclusions always beat inclusions; an expired rule
never authorizes anything; an ASN rule never authorizes a host.

The same instance is used by the CLI's ``scope check`` command and by every
collector, so a decision an operator sees is the decision the collector obeys.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from atlas.core.time import ensure_utc, utcnow
from atlas.db.enums import ScopeKind, ScopeMode
from atlas.errors import ScopeViolation, ValidationError
from atlas.scope.normalize import normalize_domain, normalize_pattern
from atlas.scope.policy import NetworkPolicy

__all__ = ["ScopeDecision", "ScopeRuleSpec", "ScopeSet"]

_SCHEME_SEPARATOR = "://"


@dataclass(frozen=True, slots=True)
class ScopeRuleSpec:
    """A normalized, immutable scope rule — the matcher's only input."""

    kind: ScopeKind
    pattern: str
    mode: ScopeMode
    include_subdomains: bool = True
    is_active: bool = True
    expires_at: datetime | None = None
    reference: str | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return ensure_utc(self.expires_at) <= ensure_utc(now or utcnow())

    @classmethod
    def from_orm(cls, rule: Any) -> ScopeRuleSpec:
        """Build a spec from a ``ScopeRule`` row without importing the ORM here."""

        kind = rule.kind
        mode = rule.mode
        return cls(
            kind=kind if isinstance(kind, ScopeKind) else ScopeKind(str(kind)),
            pattern=str(rule.pattern),
            mode=mode if isinstance(mode, ScopeMode) else ScopeMode(str(mode)),
            include_subdomains=bool(getattr(rule, "include_subdomains", True)),
            is_active=bool(getattr(rule, "is_active", True)),
            expires_at=getattr(rule, "expires_at", None),
            reference=str(getattr(rule, "id", "")) or None,
        )


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    """Outcome of a scope evaluation, with the rule that decided it."""

    value: str
    permitted: bool
    reason: str
    matched_rule: ScopeRuleSpec | None = None
    normalized: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "normalized": self.normalized,
            "permitted": self.permitted,
            "reason": self.reason,
            "matched_rule": (
                None
                if self.matched_rule is None
                else {
                    "kind": self.matched_rule.kind.value,
                    "pattern": self.matched_rule.pattern,
                    "mode": self.matched_rule.mode.value,
                }
            ),
        }


@dataclass(frozen=True, slots=True)
class _Query:
    kind: ScopeKind
    host: str
    address: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    scheme: str | None = None
    path: str | None = None


@dataclass
class ScopeSet:
    """An immutable-by-convention set of rules plus the network policy."""

    rules: tuple[ScopeRuleSpec, ...] = field(default_factory=tuple)
    policy: NetworkPolicy = field(default_factory=NetworkPolicy)
    now: datetime | None = None

    @classmethod
    def from_rules(
        cls,
        rules: Iterable[ScopeRuleSpec],
        policy: NetworkPolicy | None = None,
        now: datetime | None = None,
    ) -> ScopeSet:
        return cls(rules=tuple(rules), policy=policy or NetworkPolicy(), now=now)

    # -- introspection ---------------------------------------------------- #

    def active_rules(self) -> tuple[ScopeRuleSpec, ...]:
        moment = self.now or utcnow()
        return tuple(
            rule
            for rule in self.rules
            if rule.is_active and not rule.is_expired(moment) and rule.kind is not ScopeKind.ASN
        )

    @property
    def includes(self) -> tuple[ScopeRuleSpec, ...]:
        return tuple(rule for rule in self.active_rules() if rule.mode is ScopeMode.INCLUDE)

    @property
    def excludes(self) -> tuple[ScopeRuleSpec, ...]:
        return tuple(rule for rule in self.active_rules() if rule.mode is ScopeMode.EXCLUDE)

    def effective(self) -> dict[str, list[dict[str, object]]]:
        return {
            "include": [self._describe(rule) for rule in self.includes],
            "exclude": [self._describe(rule) for rule in self.excludes],
        }

    @staticmethod
    def _describe(rule: ScopeRuleSpec) -> dict[str, object]:
        return {
            "kind": rule.kind.value,
            "pattern": rule.pattern,
            "include_subdomains": rule.include_subdomains,
            "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
            "reference": rule.reference,
        }

    # -- evaluation ------------------------------------------------------- #

    def check(self, value: str) -> ScopeDecision:
        """Evaluate a hostname, IP, CIDR or URL. Never raises on bad input."""

        try:
            query = self._parse_query(value)
        except (ValueError, ValidationError) as exc:
            return ScopeDecision(
                value=value, permitted=False, reason=f"invalid value: {exc}", normalized=""
            )

        if query.address is not None and not self.policy.is_permitted(query.address):
            return ScopeDecision(
                value=value,
                permitted=False,
                reason=("address is not globally routable and private collection is disabled"),
                normalized=query.host,
            )

        for rule in self.excludes:
            if self._matches(rule, query):
                return ScopeDecision(
                    value=value,
                    permitted=False,
                    reason=f"excluded by rule {rule.pattern}",
                    matched_rule=rule,
                    normalized=query.host,
                )

        for rule in self.includes:
            if self._matches(rule, query):
                return ScopeDecision(
                    value=value,
                    permitted=True,
                    reason=f"permitted by rule {rule.pattern}",
                    matched_rule=rule,
                    normalized=query.host,
                )

        if not self.includes:
            reason = "project has no active include rule; collection is denied by default"
        else:
            reason = "not covered by any active include rule"
        return ScopeDecision(value=value, permitted=False, reason=reason, normalized=query.host)

    def permits(self, value: str) -> bool:
        return self.check(value).permitted

    def require_permitted(self, value: str) -> ScopeDecision:
        """Return the decision or raise :class:`ScopeViolation`."""

        decision = self.check(value)
        if not decision.permitted:
            raise ScopeViolation(
                f"{value} is outside the authorized scope: {decision.reason}",
                context={
                    "value": value,
                    "normalized": decision.normalized,
                    "reason": decision.reason,
                },
            )
        return decision

    def require_all_permitted(self, values: Iterable[str]) -> list[ScopeDecision]:
        return [self.require_permitted(value) for value in values]

    # -- internals -------------------------------------------------------- #

    def _parse_query(self, value: str) -> _Query:
        raw = value.strip()
        if not raw:
            raise ValueError("empty value")

        if _SCHEME_SEPARATOR in raw:
            scheme, remainder = raw.split(_SCHEME_SEPARATOR, 1)
            if scheme.lower() not in {"http", "https"}:
                raise ValueError(f"unsupported scheme {scheme!r}")
            authority, _, path = remainder.partition("/")
            host_part = authority.rsplit("@", 1)[-1]
            host_part = host_part.split(":", 1)[0]
            host = normalize_domain(host_part)
            return _Query(
                kind=ScopeKind.URL,
                host=host,
                scheme=scheme.lower(),
                path="/" + path if path else "",
            )

        try:
            network = ipaddress.ip_network(raw, strict=False)
            if "/" in raw:
                return _Query(kind=ScopeKind.CIDR, host=str(network), network=network)
            address = ipaddress.ip_address(raw)
            return _Query(kind=ScopeKind.IP, host=str(address), address=address)
        except ValueError:
            pass

        host = normalize_domain(raw)
        return _Query(kind=ScopeKind.DOMAIN, host=host)

    @staticmethod
    def _matches(rule: ScopeRuleSpec, query: _Query) -> bool:
        if rule.kind is ScopeKind.DOMAIN:
            if query.kind not in {ScopeKind.DOMAIN, ScopeKind.URL}:
                return False
            if query.host == rule.pattern:
                return True
            return rule.include_subdomains and query.host.endswith("." + rule.pattern)

        if rule.kind is ScopeKind.IP:
            return query.address is not None and str(query.address) == rule.pattern

        if rule.kind is ScopeKind.CIDR:
            try:
                rule_network = ipaddress.ip_network(rule.pattern, strict=False)
            except ValueError:  # pragma: no cover - validated at write time
                return False
            if query.address is not None:
                return query.address in rule_network
            if query.network is not None:
                if query.network.version != rule_network.version:
                    return False
                # Same version is guaranteed; mypy cannot narrow the union here.
                return query.network.subnet_of(rule_network)  # type: ignore[arg-type]
            return False

        if rule.kind is ScopeKind.URL:
            if query.kind is not ScopeKind.URL:
                return False
            scheme, _, rest = rule.pattern.partition("://")
            authority, _, path = rest.partition("/")
            rule_host = authority.split(":", 1)[0]
            rule_path = "/" + path if path else ""
            if query.scheme != scheme or query.host != rule_host:
                return False
            return (query.path or "/").startswith(rule_path or "/")

        # ASN rules are enrichment metadata and never authorize a host.
        return False

    @classmethod
    def from_patterns(
        cls,
        patterns: Iterable[str],
        mode: ScopeMode = ScopeMode.INCLUDE,
        policy: NetworkPolicy | None = None,
    ) -> ScopeSet:
        """Convenience constructor used by tests and one-off checks."""

        rules: list[ScopeRuleSpec] = []
        for pattern in patterns:
            kind, normalized = normalize_pattern(pattern)
            rules.append(
                ScopeRuleSpec(kind=kind, pattern=normalized, mode=mode, include_subdomains=True)
            )
        return cls.from_rules(rules, policy=policy)
