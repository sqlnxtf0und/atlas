"""Retry policy with exponential backoff and jitter.

Retries exist for transient network conditions — a slow resolver, a reset
connection — not for programming errors. :func:`RetryPolicy.run` re-raises the
original exception when the budget is exhausted so the caller keeps full
fidelity of what actually failed.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TypeVar

__all__ = ["RetryExhausted", "RetryPolicy"]

T = TypeVar("T")


class RetryExhausted(Exception):
    """Raised by ``raise_on_exhaust`` callers. Wraps the final attempt's error."""

    def __init__(self, attempts: int, last: BaseException) -> None:
        super().__init__(f"retry budget exhausted after {attempts} attempts: {last}")
        self.attempts = attempts
        self.last = last


def _sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded retries with exponential backoff and full jitter."""

    max_retries: int = 2
    base_delay: float = 0.5
    max_delay: float = 8.0
    jitter: float = 0.25
    sleeper: Callable[[float], None] = field(default=_sleep, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.base_delay <= 0:
            raise ValueError("base_delay must be positive")

    @property
    def max_attempts(self) -> int:
        return self.max_retries + 1

    def delays(self, rng: random.Random | None = None) -> Iterable[float]:
        """Backoff sequence, one entry per retry."""

        source = rng or random.Random()
        for attempt in range(self.max_retries):
            base = min(self.base_delay * (2**attempt), self.max_delay)
            spread = base * self.jitter
            yield max(0.0, base + source.uniform(-spread, spread))

    def run(
        self,
        operation: Callable[[int], T],
        *,
        retry_on: tuple[type[BaseException], ...] = (TimeoutError, ConnectionError, OSError),
        rng: random.Random | None = None,
        on_retry: Callable[[int, BaseException, float], None] | None = None,
    ) -> T:
        """Run ``operation(attempt)``; ``attempt`` is 1-based.

        Non-retryable exceptions propagate immediately. When the budget is spent
        the last exception is re-raised unchanged.
        """

        last: BaseException | None = None
        for attempt, delay in enumerate((*self.delays(rng), None), start=1):
            try:
                return operation(attempt)
            except retry_on as exc:
                last = exc
                if delay is None:
                    break
                if on_retry is not None:
                    on_retry(attempt, exc, delay)
                self.sleeper(delay)
        assert last is not None  # only reachable after a retryable failure
        raise last
