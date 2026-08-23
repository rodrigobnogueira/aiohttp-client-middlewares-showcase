"""The scenarios. Each one returns a short verdict string, or raises.

Run them with ``python -m acm_showcase``. Anything that raises is reported
as a failure with its traceback, so a regression in the library surfaces as
a named scenario rather than a stack trace in the middle of a demo.
"""

import asyncio
import time
from typing import Awaitable, Callable

import aiohttp
from aiohttp import web
from aiohttp_client_middlewares import (
    DigestAuthMiddleware,
    RateLimiter,
    RateLimitMiddleware,
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
        # the same server but must land in different buckets.
        urls = (f"http://127.0.0.1:{port}/x", f"http://localhost:{port}/x")
        middleware = RateLimitMiddleware(TokenBucket(rate=10.0, burst=1), per_domain=True)
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            for url in urls:
                async with session.get(url) as resp:
                    assert resp.status == 200
        # Assert the structure rather than the clock: connection latency to
        # "localhost" varies by host and would masquerade as throttling.
        buckets = middleware._domain_limiters
        if set(buckets) != {"127.0.0.1", "localhost"}:
            raise AssertionError(f"expected one bucket per host, got {sorted(buckets)}")
        if buckets["127.0.0.1"] is buckets["localhost"]:
            raise AssertionError("both hosts share a limiter instance")
    return f"{len(buckets)} independent buckets: {', '.join(sorted(buckets))}"


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


@scenario("rate-limit", "a limiter is acquire() and clone(); the rest is inherited")
async def rate_custom_limiter() -> str:
    """The whole surface a custom algorithm has to write.

    ``wait()`` and ``release()`` are concrete on the base, so an algorithm
    that has nothing to add to either says nothing about them, and the
    sleeping, timeout and cancellation logic is the library's rather than
    copied into every implementation.
    """
    calls: list[None] = []

    class Recording(RateLimiter):
        async def acquire(self) -> float:
            calls.append(None)
            return 0.0

        def clone(self) -> "Recording":
            return Recording()

    for shared in ("wait", "release"):
        if getattr(Recording, shared) is not getattr(RateLimiter, shared):
            raise AssertionError(f"{shared}() is not the inherited one")

    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        middleware = RateLimitMiddleware(Recording())
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            for _ in range(3):
                async with session.get(f"{site.url}/x") as resp:
                    assert resp.status == 200
    if len(calls) != 3:
        raise AssertionError(f"expected 3 acquires, saw {len(calls)}")
    return f"{len(calls)} acquires through a limiter of two methods"


@scenario("rate-limit", "an I/O-backed limiter awaits inside acquire()")
async def rate_io_backed_acquire() -> str:
    """What an async ``acquire()`` buys: reserving a slot may do I/O.

    A quota service on its own port hands out delays over HTTP, so this
    limiter suspends in the middle of reserving -- which a synchronous
    ``acquire()`` could not express without blocking the loop. Everything
    after the reservation is the library's: ``wait()`` sleeps the delay it
    is handed, the middleware holds the request until it returns.
    """
    granted: list[float] = []

    async def reserve(request: web.Request) -> web.Response:
        # Two slots free, then one every 50 ms.
        delay = 0.0 if len(granted) < 2 else 0.05
        granted.append(delay)
        return web.json_response({"delay": delay})

    quota_app = web.Application()
    quota_app.router.add_get("/reserve", reserve)

    class RemoteQuota(RateLimiter):
        """Reserves every slot over a real socket."""

        def __init__(self, client: aiohttp.ClientSession, url: str) -> None:
            self._client, self._url = client, url

        async def acquire(self) -> float:
            async with self._client.get(self._url) as resp:
                payload = await resp.json()
            return float(payload["delay"])

        def clone(self) -> "RemoteQuota":
            return RemoteQuota(self._client, self._url)

    log: list[float] = []
    async with _Server(quota_app) as quota, _Server(_echo_app(log)) as site:
        async with aiohttp.ClientSession() as quota_client:
            limiter = RemoteQuota(quota_client, f"{quota.url}/reserve")
            middleware = RateLimitMiddleware(limiter)
            async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
                start = time.monotonic()
                for _ in range(4):
                    async with session.get(f"{site.url}/x") as resp:
                        assert resp.status == 200
                elapsed = time.monotonic() - start
    if len(granted) != 4:
        raise AssertionError(f"expected 4 remote reservations, saw {len(granted)}")
    if len(log) != 4:
        raise AssertionError(f"expected 4 requests through, saw {len(log)}")
    # Two free then 2 x 50 ms: the delays the service dictated were slept.
    if elapsed < 0.09:
        raise AssertionError(f"the granted delays were not slept: {elapsed:.3f}s")
    return f"4 requests, 4 reservations over HTTP, {elapsed * 1000:.0f} ms"


@scenario("rate-limit", "the documented Redis sketch, against a fake Redis")
async def rate_redis_sketch() -> str:
    """The example from the docs, run rather than read.

    The fake keeps what the sketch relies on: one key, one atomic script,
    and a delay returned in whole milliseconds, because Redis turns Lua
    numbers into integers and a fractional second cannot come back as one.
    """

    class FakeRedis:
        def __init__(self, interval_ms: int) -> None:
            self._interval_ms = interval_ms
            self._next: dict[str, float] = {}
            self.evaluations = 0

        async def evalsha(self, script: str, numkeys: int, key: str) -> int:
            """Reserve the next slot for ``key`` and return its delay in ms."""
            self.evaluations += 1
            now = time.monotonic() * 1000
            due = max(self._next.get(key, now), now)
            self._next[key] = due + self._interval_ms
            return int(due - now)

    class RedisLimiter(RateLimiter):
        def __init__(self, redis: FakeRedis, key: str, script: str) -> None:
            self._redis, self._key, self._script = redis, key, script

        async def acquire(self) -> float:
            ms = await self._redis.evalsha(self._script, 1, self._key)
            return ms / 1000

        def clone(self) -> "RedisLimiter":
            return RedisLimiter(self._redis, self._key, self._script)

    redis = FakeRedis(interval_ms=50)
    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        limiter = RedisLimiter(redis, "rate:showcase", "deadbeef")
        middleware = RateLimitMiddleware(limiter)
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            start = time.monotonic()
            for _ in range(4):
                async with session.get(f"{site.url}/x") as resp:
                    assert resp.status == 200
            elapsed = time.monotonic() - start
    if redis.evaluations != 4:
        raise AssertionError(f"expected one script call per request, saw {redis.evaluations}")
    # First slot is now, the other three are one 50 ms interval apart.
    if elapsed < 0.1:
        raise AssertionError(f"the script's delays were not slept: {elapsed:.3f}s")
    return f"4 requests in {elapsed * 1000:.0f} ms, {redis.evaluations} reservations"


@scenario("rate-limit", "time spent in acquire() is charged against the timeout")
async def rate_acquire_charged() -> str:
    """A slow reservation spends the caller's budget, and ``wait()`` counts it.

    Reserving takes 50 ms and then asks for a 60 ms sleep. Against a 100 ms
    timeout the sleep alone would fit and the request would still time out
    on the wire; charging the reservation makes ``wait()`` say so up front.
    Given 500 ms the same limiter sleeps and returns.
    """

    class SlowReservation(RateLimiter):
        async def acquire(self) -> float:
            await asyncio.sleep(0.05)
            return 0.06

        def clone(self) -> "SlowReservation":
            return SlowReservation()

    start = time.monotonic()
    try:
        await SlowReservation().wait(timeout=0.1)
    except asyncio.TimeoutError as exc:
        refused_after, message = time.monotonic() - start, str(exc)
    else:
        raise AssertionError("the time spent acquiring was not charged")
    if "remaining timeout" not in message:
        raise AssertionError(f"unhelpful error: {message}")

    start = time.monotonic()
    await SlowReservation().wait(timeout=0.5)
    served = time.monotonic() - start
    if served < 0.1:
        raise AssertionError(f"the returned delay was not slept: {served:.3f}s")
    return f"refused after {refused_after * 1000:.0f} ms, served in {served * 1000:.0f} ms"


@scenario("rate-limit", "a delay past the timeout is refused, not slept")
async def rate_timeout_refuses_up_front() -> str:
    bucket = TokenBucket(rate=5.0, burst=1)
    await bucket.acquire()  # drain the burst: the next caller owes 200 ms
    start = time.monotonic()
    try:
        await bucket.wait(timeout=0.05)
    except asyncio.TimeoutError as exc:
        elapsed, message = time.monotonic() - start, str(exc)
    else:
        raise AssertionError("a 200 ms delay was accepted against a 50 ms timeout")
    if elapsed > 0.1:
        raise AssertionError(f"it slept toward the timeout first: {elapsed:.3f}s")
    if "0.200s" not in message:
        raise AssertionError(f"the error does not name the delay refused: {message}")
    # The refused slot went back, so the next caller owes one interval, not two.
    owed = await bucket.acquire()
    if owed > 0.25:
        raise AssertionError(f"the refused slot was not returned: {owed:.3f}s")
    return f"refused in {elapsed * 1000:.1f} ms; next caller owes {owed:.3f}s"


@scenario("rate-limit", "a hanging acquire() outlives the timeout given to wait()")
async def rate_acquire_is_unbounded() -> str:
    """Documented, and worth seeing run: the budget covers the delay, not the call.

    ``wait()`` charges what acquiring took but cannot interrupt it, so a
    limiter whose backend stops answering hangs the request no matter what
    timeout it was handed. Anything reaching over a network inside
    ``acquire()`` needs a deadline of its own; here the caller's is the only
    one that ever fires.
    """

    class NeverAnswers(RateLimiter):
        async def acquire(self) -> float:
            await asyncio.Event().wait()
            return 0.0

        def clone(self) -> "NeverAnswers":
            return NeverAnswers()

    start = time.monotonic()
    try:
        await asyncio.wait_for(NeverAnswers().wait(timeout=0.02), timeout=0.2)
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start
    else:
        raise AssertionError("a limiter that never reserves a slot returned anyway")
    if elapsed < 0.15:
        raise AssertionError(f"wait() bounded acquire() after all: {elapsed:.3f}s")
    return f"the limiter's 20 ms budget never fired; the caller's did at {elapsed * 1000:.0f} ms"


@scenario("rate-limit", "a sync acquire() passes the ABC and fails on first use")
async def rate_half_migrated_limiter() -> str:
    """What a half-finished migration looks like, as a running program.

    ``acquire()`` is a coroutine now. The ABC checks names, not
    awaitability, so a limiter left synchronous is built without complaint
    and breaks at the first request with a ``TypeError`` from ``await``.
    mypy is what catches it earlier: the ignore below is load-bearing under
    ``--strict``, so if the override ever stops being an error, CI fails on
    the unused ignore instead.
    """

    class NotMigrated(RateLimiter):
        def acquire(self) -> float:  # type: ignore[override]
            return 0.0

        def clone(self) -> "NotMigrated":
            return NotMigrated()

    limiter = NotMigrated()  # the ABC is satisfied: both names are present
    try:
        await limiter.wait()
    except TypeError as exc:
        if "await" not in str(exc):
            raise AssertionError(f"unhelpful error: {exc}") from None
        return f"built without complaint, then TypeError: {exc}"
    raise AssertionError("a synchronous acquire() was awaited without complaint")


@scenario("rate-limit", "release() returns a slot cancelled mid-sleep")
async def rate_release_on_cancel() -> str:
    bucket = TokenBucket(rate=5.0, burst=1)
    await bucket.acquire()  # drain the burst so the next caller must sleep
    task = asyncio.ensure_future(bucket.wait())
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.wait({task})
    if not task.cancelled():
        raise AssertionError("the wait was not cancelled")
    # The slot went back, so the next caller owes one interval, not two.
    owed = await bucket.acquire()
    if owed > 0.25:
        raise AssertionError(f"slot was not returned: next caller owes {owed:.3f}s")
    return f"next caller owes {owed:.3f}s, not double"


@scenario("rate-limit", "clone() builds a fresh limiter of the caller's own class")
async def rate_clone_class() -> str:
    """What ``clone()`` still promises, now that the annotation is the base.

    ``RateLimiter.clone()`` returns ``RateLimiter``, so a caller holding the
    base gets the base back and has to narrow it again -- ``typing_usage.py``
    pins that half. At runtime the object is whatever the limiter's own
    ``clone()`` built, including the one per-domain mode builds per host.
    """
    original = TokenBucket(rate=10.0, burst=1)
    fresh = original.clone()
    if not isinstance(fresh, TokenBucket):
        raise AssertionError(f"clone returned a {type(fresh).__name__}")
    if fresh is original:
        raise AssertionError("clone returned the original limiter")

    class Marked(RateLimiter):
        """Counts how far from the template it is, so a copy cannot hide."""

        def __init__(self, generation: int) -> None:
            self.generation = generation

        async def acquire(self) -> float:
            return 0.0

        def clone(self) -> "Marked":
            return Marked(self.generation + 1)

    template = Marked(0)
    log: list[float] = []
    async with _Server(_echo_app(log)) as site:
        middleware = RateLimitMiddleware(template, per_domain=True)
        async with aiohttp.ClientSession(middlewares=(middleware,)) as session:
            async with session.get(f"{site.url}/x") as resp:
                assert resp.status == 200
        cloned = middleware._domain_limiters["127.0.0.1"]
    if not isinstance(cloned, Marked):
        raise AssertionError(f"per-domain built a {type(cloned).__name__}")
    if cloned is template or cloned.generation != 1:
        raise AssertionError("per-domain did not go through the caller's clone()")
    return "clone() is the caller's class, per host and by hand"


@scenario("rate-limit", "clone() yields independent state")
async def rate_clone_independent() -> str:
    original = TokenBucket(rate=10.0, burst=1)
    await original.acquire()  # drain it
    fresh = original.clone()
    if await fresh.acquire() != 0.0:
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
