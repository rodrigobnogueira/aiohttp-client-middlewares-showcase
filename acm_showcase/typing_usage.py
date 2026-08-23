"""Typed usage of the library, checked by mypy rather than executed.

The scenarios in :mod:`acm_showcase.checks` prove the runtime behaviour. This
file proves the annotations hold up for the usage the documentation
recommends, which the runtime cannot: an inherited ``clone()`` that returns
the base type runs perfectly and only bites a caller who has annotated
anything.

Run it with ``mypy acm_showcase/typing_usage.py``; nothing imports it.
"""

import asyncio

from aiohttp_client_middlewares import RateLimiter, RateLimitMiddleware, TokenBucket


async def uses_the_whole_base_surface(limiter: RateLimiter) -> float:
    """Everything a caller can do holding nothing but the base class.

    ``acquire()`` is a coroutine returning ``float``, ``release()`` and
    ``clone()`` are ordinary calls, and none of it needs narrowing.
    """
    fresh = limiter.clone()
    delay = await fresh.acquire()
    fresh.release()
    return delay


def concrete_stays_concrete(bucket: TokenBucket) -> TokenBucket:
    """``TokenBucket`` overrides ``clone()``, so its own type comes back."""
    return bucket.clone()


def any_limiter(limiter: RateLimiter) -> RateLimiter:
    return limiter.clone()


def clone_does_not_narrow(limiter: RateLimiter) -> TokenBucket:
    """Hold the base and ``clone()`` hands back the base, whatever it built.

    ``RateLimiter.clone()`` is annotated ``RateLimiter``; there is no self
    type narrowing it to the receiver's class. The ignore below is the
    assertion, not an escape: ``--strict`` reports an unused one, so this
    starts failing the day ``clone()`` narrows again.
    """
    return limiter.clone()  # type: ignore[return-value]


def narrow_by_hand(limiter: RateLimiter) -> TokenBucket:
    """What a caller who wants the concrete type back has to write instead."""
    fresh = limiter.clone()
    assert isinstance(fresh, TokenBucket)
    return fresh


class InMemoryAlgorithm(RateLimiter):
    """An algorithm that reserves without suspending: acquire() and clone()."""

    def __init__(self, delay: float) -> None:
        self._delay = delay

    async def acquire(self) -> float:
        return self._delay

    def clone(self) -> "InMemoryAlgorithm":
        return InMemoryAlgorithm(self._delay)


class AwaitingAlgorithm(RateLimiter):
    """An I/O-backed algorithm: the same two methods, one of them suspends."""

    def __init__(self, key: str) -> None:
        self._key = key

    async def acquire(self) -> float:
        # Stands in for the round trip that reserves the slot.
        await asyncio.sleep(0)
        return 0.0

    def clone(self) -> "AwaitingAlgorithm":
        return AwaitingAlgorithm(self._key)


def middleware_accepts_both() -> tuple[RateLimitMiddleware, RateLimitMiddleware]:
    """In-memory or I/O-backed, both satisfy the middleware's parameter type."""
    return (
        RateLimitMiddleware(InMemoryAlgorithm(0.0)),
        RateLimitMiddleware(AwaitingAlgorithm("k"), per_domain=True),
    )


async def awaits_through_the_base(limiter: RateLimiter) -> None:
    """``wait()`` is concrete on the base, so this needs no narrowing."""
    await limiter.wait(timeout=1.0)
    await limiter.wait()
