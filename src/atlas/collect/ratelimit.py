"""Token-bucket rate limiting.

Three limits matter to ATLAS and they are all enforced here:

* a **global** ceiling (``collector.requests_per_second``) — politeness towards
  DNS resolvers and target infrastructure alike;
* a **per-host** ceiling (``collector.per_host_concurrency``-derived) — so one
  noisy host cannot exhaust the global budget;
* a **hard cost** for anything expensive, expressed in tokens.

The clock and sleeper are injectable so tests are deterministic without patching
module globals.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from atlas.errors import OperationCancelled

__all__ = ["RateLimiter", "TokenBucket"]

_MAX_WAIT_SECONDS: Final[float] = 60.0


def _monotonic() -> float:
    return time.monotonic()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


@dataclass
class TokenBucket:
    """A single bucket. ``rate`` is tokens per second; ``capacity`` is the burst."""

    rate: float
    capacity: float
    clock: Callable[[], float] = field(default=_monotonic, repr=False)
    sleeper: Callable[[float], None] = field(default=_sleep, repr=False)
    _tokens: float = field(init=False, repr=False)
    _updated: float = field(init=False, repr=False)
    _lock: threading.Lock = field(init=False, repr=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.rate <= 0:
            raise ValueError("rate must be positive")
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        self._tokens = self.capacity
        self._updated = self.clock()

    def _refill_locked(self) -> None:
        now = self.clock()
        elapsed = max(0.0, now - self._updated)
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    def try_acquire(self, tokens: float = 1.0) -> bool:
        if tokens <= 0:
            return True
        with self._lock:
            self._refill_locked()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    def acquire(self, tokens: float = 1.0, *, timeout: float = _MAX_WAIT_SECONDS) -> float:
        """Block until ``tokens`` are available. Returns the seconds waited."""

        if tokens <= 0:
            return 0.0
        if tokens > self.capacity:
            raise ValueError(f"cannot acquire {tokens} tokens from a {self.capacity}-token bucket")

        waited = 0.0
        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = tokens - self._tokens
                delay = max(deficit / self.rate, 0.001)

            if waited + delay > timeout:
                raise OperationCancelled(
                    f"rate limit wait exceeded {timeout:.0f}s", context={"waited": round(waited, 3)}
                )
            self.sleeper(delay)
            waited += delay

    @property
    def available(self) -> float:
        with self._lock:
            self._refill_locked()
            return self._tokens


class RateLimiter:
    """A global bucket plus lazily-created per-key buckets."""

    def __init__(
        self,
        *,
        global_rate: float,
        global_burst: float | None = None,
        per_key_rate: float | None = None,
        per_key_burst: float | None = None,
        clock: Callable[[], float] = _monotonic,
        sleeper: Callable[[float], None] = _sleep,
    ) -> None:
        self._clock = clock
        self._sleeper = sleeper
        self._global = TokenBucket(
            rate=global_rate,
            capacity=global_burst if global_burst is not None else max(1.0, global_rate),
            clock=clock,
            sleeper=sleeper,
        )
        self._per_key_rate = per_key_rate
        self._per_key_burst = per_key_burst
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    @property
    def global_available(self) -> float:
        return self._global.available

    def _bucket(self, key: str) -> TokenBucket | None:
        if self._per_key_rate is None:
            return None
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(
                    rate=self._per_key_rate,
                    capacity=self._per_key_burst
                    if self._per_key_burst is not None
                    else max(1.0, self._per_key_rate),
                    clock=self._clock,
                    sleeper=self._sleeper,
                )
                self._buckets[key] = bucket
            return bucket

    def try_acquire(self, key: str, tokens: float = 1.0) -> bool:
        bucket = self._bucket(key)
        if bucket is not None and not bucket.try_acquire(tokens):
            return False
        # The global bucket is charged last so a per-key refusal costs nothing.
        return self._global.try_acquire(tokens)

    def acquire(self, key: str, tokens: float = 1.0) -> float:
        """Block for both the per-key and the global budget. Returns seconds waited."""

        waited = 0.0
        bucket = self._bucket(key)
        if bucket is not None:
            waited += bucket.acquire(tokens)
        waited += self._global.acquire(tokens)
        return waited
