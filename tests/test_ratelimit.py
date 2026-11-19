"""Token-bucket and composite rate limiter behaviour."""

from __future__ import annotations

import pytest

from atlas.collect.ratelimit import RateLimiter, TokenBucket
from atlas.errors import OperationCancelled


class Clock:
    """Deterministic clock: sleeping advances it."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_bucket_starts_full_and_drains() -> None:
    bucket = TokenBucket(rate=1.0, capacity=2.0, clock=lambda: 0.0, sleeper=lambda _: None)
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False


def test_bucket_refills_over_time() -> None:
    clock = Clock()
    bucket = TokenBucket(rate=2.0, capacity=2.0, clock=clock.time, sleeper=clock.sleep)
    assert bucket.try_acquire(2.0) is True
    clock.now += 0.5  # 2 tokens/second * 0.5s = 1 token
    assert bucket.try_acquire(1.0) is True


def test_acquire_waits_for_refill() -> None:
    clock = Clock()
    bucket = TokenBucket(rate=1.0, capacity=1.0, clock=clock.time, sleeper=clock.sleep)
    assert bucket.try_acquire() is True
    waited = bucket.acquire()
    assert waited > 0
    assert clock.slept == pytest.approx([1.0])


def test_acquire_refuses_impossible_request() -> None:
    bucket = TokenBucket(rate=1.0, capacity=1.0, clock=lambda: 0.0, sleeper=lambda _: None)
    with pytest.raises(ValueError):
        bucket.acquire(5.0)


def test_acquire_times_out_rather_than_hanging() -> None:
    clock = Clock()
    bucket = TokenBucket(rate=0.01, capacity=1.0, clock=clock.time, sleeper=clock.sleep)
    bucket.try_acquire()
    with pytest.raises(OperationCancelled):
        bucket.acquire(timeout=1.0)


def test_limiter_applies_global_and_per_key_budgets() -> None:
    clock = Clock()
    limiter = RateLimiter(
        global_rate=1.0,
        global_burst=1.0,
        per_key_rate=10.0,
        per_key_burst=1.0,
        clock=clock.time,
        sleeper=clock.sleep,
    )
    assert limiter.try_acquire("a") is True
    # The per-key bucket for "a" is empty now, even though "b" has its own.
    assert limiter.try_acquire("a") is False
    assert limiter.try_acquire("b") is False  # global bucket is empty


def test_limiter_without_per_key_rate_only_enforces_global() -> None:
    clock = Clock()
    limiter = RateLimiter(global_rate=1.0, global_burst=2.0, clock=clock.time, sleeper=clock.sleep)
    assert limiter.try_acquire("a") is True
    assert limiter.try_acquire("b") is True
    assert limiter.try_acquire("c") is False


def test_invalid_configuration_is_rejected() -> None:
    with pytest.raises(ValueError):
        TokenBucket(rate=0.0, capacity=1.0)
    with pytest.raises(ValueError):
        TokenBucket(rate=1.0, capacity=0.0)
