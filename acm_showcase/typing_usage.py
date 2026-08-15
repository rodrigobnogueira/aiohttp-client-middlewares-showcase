"""Typed usage of the library, checked by mypy rather than executed.

The scenarios in :mod:`acm_showcase.checks` prove the runtime behaviour. This
file proves the annotations hold up for the usage the documentation
recommends, which the runtime cannot: an inherited ``clone()`` that returns
the base type type-checks fine at runtime and only bites a caller who has
annotated anything.

Run it with ``mypy acm_showcase/typing_usage.py``; nothing imports it.
"""

import asyncio

from aiohttp_client_middlewares import (
    RateLimiter,
    RateLimitMiddleware,
    SyncRateLimiter,
    TokenBucket,
)


def holds_a_sync_limiter(limiter: SyncRateLimiter) -> float:
    """The upgrade note tells a sync algorithm to hold this type.

    Cloning must keep ``acquire()`` and ``release()`` reachable, or that
    advice does not survive contact with a type checker.
    """
    fresh = limiter.clone()
    fresh.release()
    return fresh.acquire()


def returns_the_same_type(limiter: SyncRateLimiter) -> SyncRateLimiter:
    return limiter.clone()


def concrete_stays_concrete(bucket: TokenBucket) -> TokenBucket:
    return bucket.clone()


def any_limiter(limiter: RateLimiter) -> RateLimiter:
    return limiter.clone()


class SyncAlgorithm(SyncRateLimiter):
    """A synchronous algorithm: implement acquire(), inherit wait()."""

    def __init__(self, delay: float) -> None:
        self._delay = delay

    def acquire(self) -> float:
        return self._delay

    def clone(self) -> "SyncAlgorithm":
        return SyncAlgorithm(self._delay)


class AwaitingAlgorithm(RateLimiter):
    """An I/O-backed limiter: implement wait(), and nothing else."""

    def __init__(self, key: str) -> None:
        self._key = key

    async def wait(self, timeout: float | None = None) -> None:
        await asyncio.sleep(0)

    def clone(self) -> "AwaitingAlgorithm":
        return AwaitingAlgorithm(self._key)


def middleware_accepts_both() -> tuple[RateLimitMiddleware, RateLimitMiddleware]:
    """Both halves of the hierarchy satisfy the middleware's parameter type."""
    return (
        RateLimitMiddleware(SyncAlgorithm(0.0)),
        RateLimitMiddleware(AwaitingAlgorithm("k"), per_domain=True),
    )


async def awaits_through_the_base(limiter: RateLimiter) -> None:
    """wait() is a coroutine on the base, so this needs no narrowing."""
    await limiter.wait(timeout=1.0)
    await limiter.wait()
