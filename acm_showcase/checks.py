"""The scenarios. Each one returns a short verdict string, or raises.

Run them with ``python -m acm_showcase``. Anything that raises is reported
as a failure with its traceback, so a regression in the library surfaces as
a named scenario rather than a stack trace in the middle of a demo.
"""

import asyncio
import time
from typing import AsyncIterator, Awaitable, Callable

import aiohttp
from aiohttp import web
from aiohttp_client_middlewares import (
    DigestAuthMiddleware,
    RateLimiter,
    RateLimitMiddleware,
    SyncRateLimiter,
    TokenBucket,
)

from .digest_server import ALGORITHMS, DigestServer

Scenario = Callable[[], Awaitable[str]]
_SCENARIOS: list[tuple[str, str, Scenario]] = []


def scenario(group: str, name: str) -> Callable[[Scenario], Scenario]:
    def register(fn: Scenario) -> Scenario:
        _SCENARIOS.append((group, name, fn))
        return fn

    return register


def all_scenarios() -> list[tuple[str, str, Scenario]]:
    return list(_SCENARIOS)


class _Server:
    """Runs an application on a free port for the duration of a ``with``."""

    def __init__(self, app: web.Application) -> None:
        self._app = app
        self._runner: web.AppRunner | None = None
        self.url = ""

    async def __aenter__(self) -> "_Server":
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        host, port = list(self._runner.addresses)[0][:2]
        self.url = f"http://{host}:{port}"
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self._runner is not None
        await self._runner.cleanup()


def _echo_app(log: list[float]) -> web.Application:
    async def handler(request: web.Request) -> web.Response:
        log.append(time.monotonic())
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/{tail:.*}", handler)
    return app


# --- Digest authentication ---------------------------------------------------


@scenario("digest", "every algorithm RFC 7616 defines")
async def digest_all_algorithms() -> str:
    for algorithm in ALGORITHMS:
        server = DigestServer(algorithm=algorithm)
        async with _Server(server.app()) as site:
            digest = DigestAuthMiddleware(login="user", password="pass")
            async with aiohttp.ClientSession(middlewares=(digest,)) as session:
                async with session.get(f"{site.url}/protected") as resp:
                    if resp.status != 200:
                        raise AssertionError(f"{algorithm}: got {resp.status}, want 200")
    return f"{len(ALGORITHMS)} algorithms authenticated"


@scenario("digest", "qop=auth, qop=auth-int, and no qop (RFC 2069)")
async def digest_qop_modes() -> str:
    results = []
    for qop in ("auth", "auth-int", None):
        server = DigestServer(qop=qop)
        async with _Server(server.app()) as site:
            digest = DigestAuthMiddleware(login="user", password="pass")
            async with aiohttp.ClientSession(middlewares=(digest,)) as session:
                # A body exercises auth-int, which hashes it into the response.
                async with session.post(f"{site.url}/protected", data=b"payload") as resp:
                    if resp.status != 200:
                        raise AssertionError(f"qop={qop}: got {resp.status}, want 200")
        results.append(qop or "absent")
    return ", ".join(results)


@scenario("digest", "preemptive auth reuses the challenge")
async def digest_preemptive() -> str:
    server = DigestServer()
    async with _Server(server.app()) as site:
        digest = DigestAuthMiddleware(login="user", password="pass", preemptive=True)
        async with aiohttp.ClientSession(middlewares=(digest,)) as session:
            for _ in range(3):
                async with session.get(f"{site.url}/protected") as resp:
                    assert resp.status == 200
    # One challenge for the first request; the rest ride on the cached one.
    if server.challenges_issued != 1:
        raise AssertionError(f"expected 1 challenge, saw {server.challenges_issued}")
    return f"3 requests, {server.challenges_issued} challenge"


@scenario("digest", "preemptive=False challenges every time")
async def digest_non_preemptive() -> str:
    server = DigestServer()
    async with _Server(server.app()) as site:
        digest = DigestAuthMiddleware(login="user", password="pass", preemptive=False)
        async with aiohttp.ClientSession(middlewares=(digest,)) as session:
            for _ in range(3):
                async with session.get(f"{site.url}/protected") as resp:
                    assert resp.status == 200
    if server.challenges_issued != 3:
        raise AssertionError(f"expected 3 challenges, saw {server.challenges_issued}")
    return f"3 requests, {server.challenges_issued} challenges"


@scenario("digest", "a nonce that ages out is refreshed and retried")
async def digest_stale_nonce() -> str:
    server = DigestServer()
    async with _Server(server.app()) as site:
        digest = DigestAuthMiddleware(login="user", password="pass")
        async with aiohttp.ClientSession(middlewares=(digest,)) as session:
            # Authenticate once so the middleware holds a challenge, which is
            # what a server ageing out a nonce assumes.
            async with session.get(f"{site.url}/protected") as resp:
                assert resp.status == 200
            server.expire_nonce()
            async with session.get(f"{site.url}/protected") as resp:
                if resp.status != 200:
                    raise AssertionError(f"stale retry failed: {resp.status}")
    return "recovered from stale=true on a cached challenge"


@scenario("digest", "stale on the very first exchange is not retried")
async def digest_stale_first_exchange() -> str:
    """The retry budget is two attempts, and a first exchange spends both.

    Unauthenticated -> challenge -> authenticated leaves nothing for a
    ``stale=true`` arriving on that second attempt, so the refreshed
    challenge is stored but never used for this request. A caller sees 401
    and succeeds on the next request. Pinned here because the documented
    behaviour reads as though the retry is always available.
    """
    server = DigestServer(stale_once=True)
    async with _Server(server.app()) as site:
        digest = DigestAuthMiddleware(login="user", password="pass")
        async with aiohttp.ClientSession(middlewares=(digest,)) as session:
            async with session.get(f"{site.url}/protected") as first:
                first_status = first.status
            # The refreshed challenge was captured, so the next one works.
            async with session.get(f"{site.url}/protected") as second:
                second_status = second.status
    if (first_status, second_status) != (401, 200):
        raise AssertionError(f"got {first_status} then {second_status}, want 401 then 200")
    return "401 on the first exchange, 200 on the next"


@scenario("digest", "wrong password stops at 401 without looping")
async def digest_wrong_password() -> str:
    server = DigestServer()
    async with _Server(server.app()) as site:
        digest = DigestAuthMiddleware(login="user", password="wrong")
        async with aiohttp.ClientSession(middlewares=(digest,)) as session:
            async with session.get(f"{site.url}/protected") as resp:
                if resp.status != 401:
                    raise AssertionError(f"expected 401, got {resp.status}")
    return f"401 after {server.challenges_issued} challenges"


@scenario("digest", "credentials are scoped to the first origin seen")
async def digest_origin_scoping() -> str:
    anchor, other = DigestServer(), DigestServer()
    async with _Server(anchor.app()) as a, _Server(other.app()) as b:
        digest = DigestAuthMiddleware(login="user", password="pass")
        async with aiohttp.ClientSession(middlewares=(digest,)) as session:
            async with session.get(f"{a.url}/protected") as resp:
                assert resp.status == 200
            # A different origin must not receive the anchor's credentials.
            async with session.get(f"{b.url}/open") as resp:
                assert resp.status == 200
    leaked = [path for path, had_auth in other.requests if had_auth]
    if leaked:
        raise AssertionError(f"credentials leaked to another origin: {leaked}")
    return "no credentials sent cross-origin"


# --- Rate limiting -----------------------------------------------------------


@scenario("rate-limit", "burst is instant, the rest is throttled")
async def rate_burst_then_throttle() -> str:
    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        middleware = RateLimitMiddleware(TokenBucket(rate=20.0, burst=2))
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            start = time.monotonic()
            for _ in range(5):
                async with session.get(f"{site.url}/x") as resp:
                    assert resp.status == 200
            elapsed = time.monotonic() - start
    # 2 free, then 3 at 20/s = 0.15s floor.
    if elapsed < 0.1:
        raise AssertionError(f"no throttling observed: {elapsed:.3f}s for 5 requests")
    return f"5 requests in {elapsed:.2f}s"


@scenario("rate-limit", "per_domain gives each host its own budget")
async def rate_per_domain() -> str:
    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        port = site.url.rsplit(":", 1)[1]
        # Limiters are keyed on the host string alone, so these two URLs are
        # the same server but different buckets.
        first, second = f"http://127.0.0.1:{port}/x", f"http://localhost:{port}/x"
        middleware = RateLimitMiddleware(TokenBucket(rate=10.0, burst=1), per_domain=True)
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            start = time.monotonic()
            for url in (first, second):
                async with session.get(url) as resp:
                    assert resp.status == 200
            elapsed = time.monotonic() - start
    if elapsed > 0.05:
        raise AssertionError(f"hosts appear to share a bucket: {elapsed:.3f}s")
    return f"2 host names, {elapsed * 1000:.0f} ms"


@scenario("rate-limit", "per_domain=False shares one budget")
async def rate_global_shared() -> str:
    log_a: list[float] = []
    log_b: list[float] = []
    async with _Server(_echo_app(log_a)) as a, _Server(_echo_app(log_b)) as b:
        middleware = RateLimitMiddleware(TokenBucket(rate=10.0, burst=1), per_domain=False)
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            start = time.monotonic()
            async with session.get(f"{a.url}/x") as resp:
                assert resp.status == 200
            async with session.get(f"{b.url}/x") as resp:
                assert resp.status == 200
            elapsed = time.monotonic() - start
    # The second host waits on the shared bucket: ~0.1s at 10/s.
    if elapsed < 0.05:
        raise AssertionError(f"expected a shared bucket to throttle: {elapsed:.3f}s")
    return f"second host waited, {elapsed * 1000:.0f} ms total"


@scenario("rate-limit", "the caller's own limiter is the one used")
async def rate_limiter_identity() -> str:
    bucket = TokenBucket(rate=100.0, burst=5)
    middleware = RateLimitMiddleware(bucket)
    if middleware._global_limiter is not bucket:
        raise AssertionError("the middleware substituted a different limiter")
    return "limiter used directly, not copied"


@scenario("rate-limit", "a custom SyncRateLimiter drives the middleware")
async def rate_custom_sync_limiter() -> str:
    calls: list[None] = []

    class Recording(SyncRateLimiter):
        def acquire(self) -> float:
            calls.append(None)
            return 0.0

        def clone(self) -> "Recording":
            return Recording()

    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        middleware = RateLimitMiddleware(Recording())
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            for _ in range(3):
                async with session.get(f"{site.url}/x") as resp:
                    assert resp.status == 200
    if len(calls) != 3:
        raise AssertionError(f"expected 3 acquires, saw {len(calls)}")
    return f"{len(calls)} acquires through a custom limiter"


@scenario("rate-limit", "a sync limiter left on RateLimiter fails loudly")
async def rate_migration_break() -> str:
    """What the upgrade note promises, as a running program.

    Before the split this class was valid. It now names no ``wait()``, so
    it cannot be instantiated at all rather than misbehaving at runtime.
    """

    class NotMigrated(RateLimiter):
        def acquire(self) -> float:
            return 0.0

        def clone(self) -> "NotMigrated":
            raise NotImplementedError

    try:
        NotMigrated()  # type: ignore[abstract]
    except TypeError as exc:
        if "wait" not in str(exc):
            raise AssertionError(f"unhelpful error: {exc}") from None
        return "TypeError naming wait(), at construction"
    raise AssertionError("a limiter without wait() was accepted")


@scenario("rate-limit", "an I/O-backed limiter implements wait() and nothing else")
async def rate_async_limiter_minimal() -> str:
    seen: list[float | None] = []

    class Awaiting(RateLimiter):
        async def wait(self, timeout: float | None = None) -> None:
            seen.append(timeout)
            await asyncio.sleep(0)

        def clone(self) -> "Awaiting":
            return Awaiting()

    limiter = Awaiting()
    for absent in ("acquire", "release"):
        if hasattr(limiter, absent):
            raise AssertionError(f"{absent}() should not exist on this path")

    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        async with aiohttp.ClientSession(
            middlewares=(RateLimitMiddleware(limiter),)
        ) as session:
            for _ in range(3):
                async with session.get(f"{site.url}/x") as resp:
                    assert resp.status == 200
    if len(seen) != 3:
        raise AssertionError(f"expected 3 waits, saw {len(seen)}")
    return f"{len(seen)} requests, no acquire()/release() in sight"


@scenario("rate-limit", "the documented Redis sketch, against a fake Redis")
async def rate_redis_sketch() -> str:
    """The example from the docs, run rather than read.

    The fake holds one key with an expiry, which is all the sketch relies
    on, so this exercises the real control flow: contend, poll, proceed.
    """

    class FakeRedis:
        def __init__(self) -> None:
            self.held_until = 0.0
            self.sets = 0

        async def set(self, key: str, value: str, nx: bool = False, ex: int = 0) -> bool:
            self.sets += 1
            now = time.monotonic()
            if nx and now < self.held_until:
                return False
            self.held_until = now + (ex or 0) * 0.05  # scaled down for the demo
            return True

    class RedisLimiter(RateLimiter):
        def __init__(self, redis: FakeRedis, key: str) -> None:
            self._redis, self._key = redis, key

        async def _reserve(self) -> None:
            while not await self._redis.set(self._key, "1", nx=True, ex=1):
                await asyncio.sleep(0.01)

        async def wait(self, timeout: float | None = None) -> None:
            await asyncio.wait_for(self._reserve(), timeout)

        def clone(self) -> "RedisLimiter":
            return RedisLimiter(self._redis, self._key)

    redis = FakeRedis()
    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        middleware = RateLimitMiddleware(RedisLimiter(redis, "rate:showcase"))
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            start = time.monotonic()
            for _ in range(4):
                async with session.get(f"{site.url}/x") as resp:
                    assert resp.status == 200
            elapsed = time.monotonic() - start
    if redis.sets < 4:
        raise AssertionError(f"the limiter did not reserve per request: {redis.sets}")
    return f"4 requests in {elapsed * 1000:.0f} ms, {redis.sets} reservations"


@scenario("rate-limit", "an awaiting limiter raises past its timeout")
async def rate_async_limiter_timeout() -> str:
    class NeverFree(RateLimiter):
        async def wait(self, timeout: float | None = None) -> None:
            await asyncio.wait_for(asyncio.Event().wait(), timeout)

        def clone(self) -> "NeverFree":
            return NeverFree()

    start = time.monotonic()
    try:
        await NeverFree().wait(timeout=0.1)
    except asyncio.TimeoutError:
        return f"asyncio.TimeoutError after {(time.monotonic() - start) * 1000:.0f} ms"
    raise AssertionError("a limiter that never frees a slot returned anyway")


@scenario("rate-limit", "clone() keeps the caller's type, including per-domain")
async def rate_clone_type() -> str:
    limiter: SyncRateLimiter = TokenBucket(rate=10.0, burst=1)
    fresh = limiter.clone()
    # acquire() and release() have to survive the clone, or the upgrade
    # note's advice to hold a limiter as SyncRateLimiter would not work.
    if not isinstance(fresh, TokenBucket):
        raise AssertionError(f"clone returned {type(fresh).__name__}")
    fresh.acquire()
    fresh.release()

    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        middleware = RateLimitMiddleware(TokenBucket(rate=50.0, burst=1), per_domain=True)
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            async with session.get(f"{site.url}/x") as resp:
                assert resp.status == 200
        cloned = middleware._domain_limiters["127.0.0.1"]
    if not isinstance(cloned, TokenBucket):
        raise AssertionError(f"per-domain clone is {type(cloned).__name__}")
    return "clone is a TokenBucket, with acquire() and release() intact"


@scenario("rate-limit", "release() returns a slot cancelled mid-sleep")
async def rate_release_on_cancel() -> str:
    bucket = TokenBucket(rate=5.0, burst=1)
    bucket.acquire()  # drain the burst so the next caller must sleep
    task = asyncio.ensure_future(bucket.wait())
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.wait({task})
    if not task.cancelled():
        raise AssertionError("the wait was not cancelled")
    # The slot went back, so the next caller owes one interval, not two.
    owed = bucket.acquire()
    if owed > 0.25:
        raise AssertionError(f"slot was not returned: next caller owes {owed:.3f}s")
    return f"next caller owes {owed:.3f}s, not double"


@scenario("rate-limit", "clone() yields independent state")
async def rate_clone_independent() -> str:
    original = TokenBucket(rate=10.0, burst=1)
    original.acquire()  # drain it
    fresh = original.clone()
    if fresh.acquire() != 0.0:
        raise AssertionError("the clone inherited the original's drained state")
    return "clone starts full"


@scenario("rate-limit", "invalid configuration is rejected at construction")
async def rate_validation() -> str:
    rejected = []
    for kwargs in ({"rate": 0.0}, {"rate": -1.0}, {"rate": float("nan")},
                   {"rate": float("inf")}, {"burst": 0}, {"burst": -1}):
        try:
            TokenBucket(**{"rate": 10.0, "burst": 1, **kwargs})  # type: ignore[arg-type]
        except ValueError:
            rejected.append(next(iter(kwargs)))
        else:
            raise AssertionError(f"accepted invalid config: {kwargs}")
    try:
        RateLimitMiddleware("not a limiter")  # type: ignore[arg-type]
    except TypeError:
        rejected.append("non-limiter")
    else:
        raise AssertionError("accepted a non-RateLimiter")
    return f"{len(rejected)} invalid configurations rejected"


# --- The two together --------------------------------------------------------


@scenario("combined", "digest replays are throttled when listed last")
async def combined_ordering() -> str:
    server = DigestServer()
    async with _Server(server.app()) as site:
        digest = DigestAuthMiddleware(login="user", password="pass")
        limiter = RateLimitMiddleware(TokenBucket(rate=20.0, burst=1))
        # Rate limiting listed last, so it also sees the digest retry.
        async with aiohttp.ClientSession(middlewares=(digest, limiter)) as session:
            async with session.get(f"{site.url}/protected") as resp:
                assert resp.status == 200
            before = len(server.requests)
            server.expire_nonce()
            start = time.monotonic()
            async with session.get(f"{site.url}/protected") as resp:
                if resp.status != 200:
                    raise AssertionError(f"retry through both middlewares: {resp.status}")
            elapsed = time.monotonic() - start
    retry_attempts = len(server.requests) - before
    if retry_attempts < 2:
        raise AssertionError(f"expected a replay, saw {retry_attempts} request(s)")
    # Two wire requests at 20/s with a burst of 1 means the replay waited.
    if elapsed < 0.02:
        raise AssertionError(f"the replay was not throttled: {elapsed:.3f}s")
    return f"{retry_attempts} wire requests, {elapsed * 1000:.0f} ms, replay throttled"
