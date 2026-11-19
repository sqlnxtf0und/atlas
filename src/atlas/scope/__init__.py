"""Scope: normalization, matching and network policy.

This package has no dependency on SQLAlchemy or any service, so it can be
unit-tested in isolation and reused verbatim inside workers.
"""

from atlas.scope.matcher import ScopeDecision, ScopeSet
from atlas.scope.normalize import (
    infer_scope_kind,
    normalize_cidr,
    normalize_domain,
    normalize_ip,
    normalize_pattern,
    normalize_url,
    registrable_domain,
)
from atlas.scope.policy import AddressClass, NetworkPolicy, classify_address

__all__ = [
    "AddressClass",
    "NetworkPolicy",
    "ScopeDecision",
    "ScopeSet",
    "classify_address",
    "infer_scope_kind",
    "normalize_cidr",
    "normalize_domain",
    "normalize_ip",
    "normalize_pattern",
    "normalize_url",
    "registrable_domain",
]
