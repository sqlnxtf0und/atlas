"""Address resolution shared by the network collectors.

Both the TLS and HTTP collectors need the same thing: the addresses a name resolves
to, so the scope gate and the network policy can be applied to them *before* a
socket is opened. The resolver is a protocol rather than a concrete class so the
suite can hand over a fixed answer list and never touch a nameserver.

The fallback uses ``getaddrinfo`` with ``SOCK_STREAM`` — the same lookup a TCP
connection would do — and returns addresses in the resolver's own order, without
deduplication: a caller that cares about ordering or uniqueness does it there,
so this stays a thin, predictable edge.
"""

from __future__ import annotations

import socket
from typing import Protocol

__all__ = ["AddressResolver", "resolve_addresses"]


class AddressResolver(Protocol):
    """The slice of a resolver the network collectors need: addresses for a name."""

    def resolve(self, host: str) -> list[str]: ...


def resolve_addresses(host: str, resolver: AddressResolver | None = None) -> list[str]:
    """Addresses for ``host``, via ``resolver`` when one is supplied.

    Raises :class:`OSError` when the lookup fails, which is the caller's signal to
    record a resolution error rather than to open a connection to nothing.
    """

    if resolver is not None:
        return [str(item) for item in resolver.resolve(host)]
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
