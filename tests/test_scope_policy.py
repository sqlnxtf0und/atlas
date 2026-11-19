"""Network policy: address classification and the SSRF gate."""

from __future__ import annotations

import pytest

from atlas.errors import ScopeViolation
from atlas.scope.policy import AddressClass, NetworkPolicy, classify_address


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("8.8.8.8", AddressClass.GLOBAL),
        ("1.1.1.1", AddressClass.GLOBAL),
        ("2606:4700:4700::1111", AddressClass.GLOBAL),
        ("10.1.2.3", AddressClass.PRIVATE),
        ("192.168.1.10", AddressClass.PRIVATE),
        ("172.16.0.1", AddressClass.PRIVATE),
        ("127.0.0.1", AddressClass.LOOPBACK),
        ("::1", AddressClass.LOOPBACK),
        ("169.254.169.254", AddressClass.LINK_LOCAL),
        ("0.0.0.0", AddressClass.UNSPECIFIED),
        ("224.0.0.1", AddressClass.MULTICAST),
    ],
)
def test_classify_address(address: str, expected: AddressClass) -> None:
    assert classify_address(address) is expected


def test_default_policy_allows_only_global() -> None:
    policy = NetworkPolicy()
    assert policy.is_permitted("8.8.8.8")
    for address in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "0.0.0.0"):
        assert not policy.is_permitted(address)


def test_policy_raises_scope_violation() -> None:
    with pytest.raises(ScopeViolation) as excinfo:
        NetworkPolicy().require_permitted("169.254.169.254")
    assert excinfo.value.context["class"] == "link-local"


def test_private_opt_in() -> None:
    policy = NetworkPolicy(allow_private=True)
    assert policy.is_permitted("10.0.0.1")
    assert policy.is_permitted("127.0.0.1")
    assert not policy.is_permitted("0.0.0.0")
