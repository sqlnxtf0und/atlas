"""Retry policy: bounded attempts, backoff ceiling, fidelity on exhaustion."""

from __future__ import annotations

import random

import pytest

from atlas.collect.retry import RetryPolicy


class Recorder:
    def __init__(self) -> None:
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


def policy(**kwargs: object) -> tuple[RetryPolicy, Recorder]:
    recorder = Recorder()
    defaults: dict[str, object] = {
        "max_retries": 2,
        "base_delay": 0.5,
        "max_delay": 8.0,
        "jitter": 0.0,
        "sleeper": recorder.sleep,
    }
    defaults.update(kwargs)
    return RetryPolicy(**defaults), recorder  # type: ignore[arg-type]


def test_success_on_first_attempt_does_not_sleep() -> None:
    retry, recorder = policy()
    attempts: list[int] = []

    def operation(attempt: int) -> str:
        attempts.append(attempt)
        return "ok"

    assert retry.run(operation) == "ok"
    assert attempts == [1]
    assert recorder.sleeps == []


def test_transient_failure_is_retried_then_succeeds() -> None:
    retry, recorder = policy()
    attempts: list[int] = []

    def operation(attempt: int) -> str:
        attempts.append(attempt)
        if attempt < 3:
            raise TimeoutError("slow resolver")
        return "ok"

    assert retry.run(operation) == "ok"
    assert attempts == [1, 2, 3]
    assert len(recorder.sleeps) == 2


def test_exhaustion_reraises_original_exception() -> None:
    retry, recorder = policy(max_retries=1)
    failure = ConnectionError("reset")

    def operation(attempt: int) -> str:
        raise failure

    with pytest.raises(ConnectionError) as excinfo:
        retry.run(operation)
    assert excinfo.value is failure
    assert len(recorder.sleeps) == 1


def test_non_retryable_error_propagates_immediately() -> None:
    retry, recorder = policy()
    calls: list[int] = []

    def operation(attempt: int) -> str:
        calls.append(attempt)
        raise ValueError("bad input")

    with pytest.raises(ValueError):
        retry.run(operation)
    assert calls == [1]
    assert recorder.sleeps == []


def test_delays_are_exponential_and_capped() -> None:
    retry, _ = policy(max_retries=5, base_delay=1.0, max_delay=4.0)
    delays = list(retry.delays(random.Random(0)))
    assert delays == [1.0, 2.0, 4.0, 4.0, 4.0]


def test_jitter_stays_within_bounds() -> None:
    retry, _ = policy(max_retries=3, base_delay=1.0, max_delay=4.0, jitter=0.5)
    for delay in retry.delays(random.Random(3)):
        assert 0.0 <= delay <= 6.0


def test_on_retry_callback_sees_attempt_and_delay() -> None:
    retry, _ = policy(max_retries=1)
    seen: list[tuple[int, str, float]] = []

    def operation(attempt: int) -> str:
        if attempt == 1:
            raise TimeoutError("again")
        return "ok"

    retry.run(operation, on_retry=lambda a, exc, d: seen.append((a, str(exc), d)))
    assert seen and seen[0][0] == 1


def test_negative_retries_rejected() -> None:
    with pytest.raises(ValueError):
        RetryPolicy(max_retries=-1)
