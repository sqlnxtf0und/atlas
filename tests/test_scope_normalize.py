"""Normalization helpers: domains, addresses, CIDRs, URLs, pattern inference."""

from __future__ import annotations

import pytest

from atlas.db.enums import ScopeKind
from atlas.errors import ValidationError
from atlas.scope.normalize import (
    infer_scope_kind,
    normalize_cidr,
    normalize_domain,
    normalize_ip,
    normalize_pattern,
    normalize_url,
    registrable_domain,
    split_hostname,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  api.example.com  ", "api.example.com"),
        ("münchen.de", "xn--mnchen-3ya.de"),
    ],
)
def test_normalize_domain(raw: str, expected: str) -> None:
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["https://example.com", "example.com/path", "example.com:443", "exa mple.com", "", "-bad.com"],
)
def test_normalize_domain_rejects(raw: str) -> None:
    with pytest.raises(ValidationError):
        normalize_domain(raw)


def test_normalize_ip_and_cidr() -> None:
    assert normalize_ip("2001:0DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert normalize_cidr("10.0.0.5/8") == "10.0.0.0/8"
    with pytest.raises(ValidationError):
        normalize_ip("999.1.1.1")


def test_normalize_url() -> None:
    assert normalize_url("HTTPS://Example.com/Path/") == "https://example.com/Path"
    with pytest.raises(ValidationError):
        normalize_url("ftp://example.com")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", ScopeKind.DOMAIN),
        ("10.0.0.1", ScopeKind.IP),
        ("10.0.0.0/24", ScopeKind.CIDR),
        ("AS64500", ScopeKind.ASN),
        ("https://example.com/app", ScopeKind.URL),
    ],
)
def test_infer_scope_kind(raw: str, expected: ScopeKind) -> None:
    assert infer_scope_kind(raw) is expected


def test_wildcard_normalizes_to_apex() -> None:
    kind, value = normalize_pattern("*.Example.com")
    assert kind is ScopeKind.DOMAIN
    assert value == "example.com"


def test_split_hostname() -> None:
    assert split_hostname("api.eu.example.com") == ("api.eu", "example.com")
    assert split_hostname("shop.example.co.uk") == ("shop", "example.co.uk")
    assert registrable_domain("a.b.example.org") == "example.org"
