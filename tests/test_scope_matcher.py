"""Scope matcher semantics — the authorization contract."""

from __future__ import annotations

from datetime import timedelta

import pytest

from atlas.core.time import utcnow
from atlas.db.enums import ScopeKind, ScopeMode
from atlas.errors import ScopeViolation
from atlas.scope.matcher import ScopeRuleSpec, ScopeSet
from atlas.scope.policy import NetworkPolicy


def rule(
    pattern: str,
    *,
    kind: ScopeKind = ScopeKind.DOMAIN,
    mode: ScopeMode = ScopeMode.INCLUDE,
    subdomains: bool = True,
    active: bool = True,
    expires_in: timedelta | None = None,
) -> ScopeRuleSpec:
    return ScopeRuleSpec(
        kind=kind,
        pattern=pattern,
        mode=mode,
        include_subdomains=subdomains,
        is_active=active,
        expires_at=utcnow() + expires_in if expires_in else None,
    )


def test_empty_scope_denies_everything() -> None:
    scope = ScopeSet.from_rules([])
    decision = scope.check("example.com")
    assert decision.permitted is False
    assert "default" in decision.reason


def test_domain_rule_covers_apex_and_subdomains() -> None:
    scope = ScopeSet.from_rules([rule("example.com")])
    assert scope.permits("example.com")
    assert scope.permits("api.example.com")
    assert scope.permits("a.b.example.com")
    assert not scope.permits("example.org")
    assert not scope.permits("notexample.com")


def test_subdomain_only_rule() -> None:
    scope = ScopeSet.from_rules([rule("example.com", subdomains=False)])
    assert scope.permits("example.com")
    assert not scope.permits("api.example.com")


def test_exclusion_beats_inclusion() -> None:
    scope = ScopeSet.from_rules(
        [
            rule("example.com"),
            rule("admin.example.com", mode=ScopeMode.EXCLUDE),
        ]
    )
    assert scope.permits("api.example.com")
    decision = scope.check("admin.example.com")
    assert decision.permitted is False
    assert decision.matched_rule is not None
    assert decision.matched_rule.mode is ScopeMode.EXCLUDE


def test_expired_rule_does_not_authorize() -> None:
    scope = ScopeSet.from_rules([rule("example.com", expires_in=timedelta(days=-1))])
    assert not scope.permits("example.com")


def test_inactive_rule_does_not_authorize() -> None:
    scope = ScopeSet.from_rules([rule("example.com", active=False)])
    assert not scope.permits("example.com")


def test_ip_and_cidr_rules() -> None:
    scope = ScopeSet.from_rules(
        [
            rule("203.0.113.10", kind=ScopeKind.IP),
            rule("198.51.100.0/24", kind=ScopeKind.CIDR),
        ]
    )
    assert scope.permits("203.0.113.10")
    assert not scope.permits("203.0.113.11")
    assert scope.permits("198.51.100.77")
    assert not scope.permits("198.51.101.1")


def test_cidr_query_is_subnet_checked() -> None:
    scope = ScopeSet.from_rules([rule("10.0.0.0/8", kind=ScopeKind.CIDR)])
    assert scope.permits("10.1.0.0/16")
    assert not scope.permits("11.0.0.0/16")


def test_private_addresses_denied_by_policy() -> None:
    scope = ScopeSet.from_rules([rule("10.0.0.0/8", kind=ScopeKind.CIDR)])
    decision = scope.check("10.1.2.3")
    assert decision.permitted is False
    assert "private" in decision.reason


def test_private_addresses_allowed_when_configured() -> None:
    scope = ScopeSet.from_rules(
        [rule("10.0.0.0/8", kind=ScopeKind.CIDR)],
        policy=NetworkPolicy(allow_private=True),
    )
    assert scope.permits("10.1.2.3")


def test_url_rule_path_prefix() -> None:
    scope = ScopeSet.from_rules([rule("https://example.com/app", kind=ScopeKind.URL)])
    assert scope.permits("https://example.com/app")
    assert scope.permits("https://example.com/app/sub")
    assert not scope.permits("https://example.com/other")
    assert not scope.permits("http://example.com/app")


def test_url_query_matches_domain_rule() -> None:
    scope = ScopeSet.from_rules([rule("example.com")])
    assert scope.permits("https://api.example.com/v1")


def test_asn_rule_never_authorizes_a_host() -> None:
    scope = ScopeSet.from_rules([rule("AS64500", kind=ScopeKind.ASN)])
    assert not scope.permits("example.com")


def test_require_permitted_raises_with_context() -> None:
    scope = ScopeSet.from_rules([rule("example.com")])
    with pytest.raises(ScopeViolation) as excinfo:
        scope.require_permitted("evil.example.org")
    assert excinfo.value.context["value"] == "evil.example.org"
    assert excinfo.value.exit_code == 3


def test_invalid_value_is_denied_not_crashed() -> None:
    scope = ScopeSet.from_rules([rule("example.com")])
    decision = scope.check("not a host")
    assert decision.permitted is False
    assert "invalid" in decision.reason


def test_effective_export() -> None:
    scope = ScopeSet.from_rules(
        [rule("example.com"), rule("bad.example.com", mode=ScopeMode.EXCLUDE)]
    )
    payload = scope.effective()
    assert payload["include"][0]["pattern"] == "example.com"
    assert payload["exclude"][0]["pattern"] == "bad.example.com"
