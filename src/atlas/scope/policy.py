"""Network policy: private, loopback, link-local and reserved address refusal.

This is the SSRF gate. It runs on *every* address before a connection is made and
again after DNS resolution, which is what makes DNS rebinding ineffective.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Any

from atlas.errors import ScopeViolation

__all__ = ["AddressClass", "NetworkPolicy", "classify_address"]


class AddressClass(str, Enum):
    GLOBAL = "global"
    PRIVATE = "private"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link-local"
    RESERVED = "reserved"
    MULTICAST = "multicast"
    UNSPECIFIED = "unspecified"
    DOCUMENTATION = "documentation"


#: RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation ranges. They are unroutable,
#: so allowing them cannot reach anything an operator does not already control —
#: and they are the correct addresses to write into scope rules, fixtures and
#: engagement checklists.
_DOCUMENTATION_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def is_documentation_address(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return any(
        ip in network for network in _DOCUMENTATION_NETWORKS if network.version == ip.version
    )


def classify_address(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> AddressClass:
    """Classify an address. Most specific class wins."""

    ip = ipaddress.ip_address(address) if isinstance(address, str) else address
    if ip.is_unspecified:
        return AddressClass.UNSPECIFIED
    if ip.is_loopback:
        return AddressClass.LOOPBACK
    if ip.is_link_local:
        return AddressClass.LINK_LOCAL
    if ip.is_multicast:
        return AddressClass.MULTICAST
    if is_documentation_address(ip):
        return AddressClass.DOCUMENTATION
    if ip.is_reserved:
        return AddressClass.RESERVED
    if ip.is_private:
        return AddressClass.PRIVATE
    return AddressClass.GLOBAL


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """Which address classes a collector may connect to."""

    allow_private: bool = False
    allow_loopback: bool = False
    allow_link_local: bool = False
    allow_reserved: bool = False
    allow_multicast: bool = False
    allow_documentation: bool = True

    @classmethod
    def from_settings(cls, settings: Any) -> NetworkPolicy:
        return cls(allow_private=bool(settings.security.allow_private_addresses))

    def is_permitted(self, address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        classified = classify_address(address)
        if classified is AddressClass.GLOBAL:
            return True
        if classified is AddressClass.DOCUMENTATION:
            return self.allow_documentation
        if classified is AddressClass.PRIVATE:
            return self.allow_private
        if classified is AddressClass.LOOPBACK:
            return self.allow_private or self.allow_loopback
        if classified is AddressClass.LINK_LOCAL:
            return self.allow_private or self.allow_link_local
        if classified is AddressClass.RESERVED:
            return self.allow_private or self.allow_reserved
        if classified is AddressClass.MULTICAST:
            return self.allow_multicast
        # UNSPECIFIED — and any class added later — is denied by default.
        return False

    def require_permitted(
        self, address: str | ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> None:
        """Raise :class:`ScopeViolation` when the address class is not permitted."""

        if self.is_permitted(address):
            return
        classified = classify_address(address)
        raise ScopeViolation(
            f"address {address} is {classified.value} and private address collection is disabled",
            context={"address": str(address), "class": classified.value},
        )
