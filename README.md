# acm-showcase

A runnable exercise of every feature in
[aiohttp-client-middlewares](https://github.com/aio-libs/aiohttp-client-middlewares),
written to find problems rather than to look good in a screenshot.

Each scenario stands up a real `aiohttp` server on a free port, drives the
middleware against it over a real socket, and asserts something specific. A
scenario that fails prints its name and traceback, so a regression in the
library surfaces as `digest / a nonce that ages out is refreshed and retried`
rather than a stack trace in the middle of a demo.

```console
$ python -m acm_showcase

digest
  ok    every algorithm RFC 7616 defines
        8 algorithms authenticated
  ok    qop=auth, qop=auth-int, and no qop (RFC 2069)
        auth, auth-int, absent
  ...

17/17 scenarios passed
```

The process exits non-zero if anything fails, so it works as a smoke test in
CI as well as by hand.

## Running it

```console
python -m venv .venv && . .venv/bin/activate
pip install -e .
python -m acm_showcase            # everything
python -m acm_showcase digest     # one group: digest, rate-limit, combined
```

`pyproject.toml` pins the library to the `split-rate-limiter-abc` branch
behind [aio-libs/aiohttp-client-middlewares#25][pr25], not to `master` and
not to a release. Nothing is released yet, and the point of this repository
is to exercise the API *before* it ships: the rate-limiting scenarios below
cover the two-base-class design that PR proposes. Repoint it at `master`
once #25 lands, and at a tag once one exists.

[pr25]: https://github.com/aio-libs/aiohttp-client-middlewares/pull/25

`mypy --strict` runs over the package as part of CI. That is not decoration:
`acm_showcase/typing_usage.py` exists only to be type-checked, because the
library's annotations can be wrong in ways no amount of running catches --
an inherited `clone()` returning the base type works perfectly at runtime
and only bites a caller who annotated something.

## What it covers

**Digest authentication** — all eight algorithms RFC 7616 defines, including
the `-sess` variants; `qop=auth`, `qop=auth-int` (with a body, so the body
hash actually participates) and the no-`qop` RFC 2069 form; preemptive auth
on and off, counting challenges to prove the difference; a nonce ageing out
mid-session; a wrong password terminating instead of looping; and credentials
staying scoped to the origin they were first used against.

**Rate limiting**, against the #25 design — burst then throttle;
`per_domain` on and off; the caller's own limiter being used rather than a
copy; a custom `SyncRateLimiter` driving the middleware; an I/O-backed
`RateLimiter` that implements `wait()` **and nothing else**, asserting that
`acquire()` and `release()` are not even present on that path; the Redis
sketch from the library's own docs run against a fake Redis; an awaiting
limiter raising past its timeout; `release()` returning a slot cancelled
mid-sleep; `clone()` producing independent state *and* keeping the caller's
type, including through `per_domain`; the pre-split shape failing loudly at
construction rather than misbehaving later; and every invalid configuration
rejected up front.

**Both together** — digest listed before rate limiting, so an authentication
replay is throttled too, which is the ordering the library's own docs
recommend.

## Two things this turned up

**A `stale=true` on the very first exchange is not retried.** The middleware
allows two attempts per request. A first exchange spends both on
"unauthenticated → challenge → authenticated", so a `stale` challenge
arriving on that second attempt is stored but never used, and the caller sees
a 401. The next request succeeds, because the refreshed challenge was kept.
In practice a server ages a nonce out only after some successful requests, by
which point a challenge is cached and the retry is available — which is the
case `a nonce that ages out is refreshed and retried` covers. The edge is
pinned separately in `stale on the very first exchange is not retried` so
that a change in either direction is visible.

**Per-domain limiters are keyed on the host string alone.** `127.0.0.1` and
`localhost` get separate buckets even when they are the same server, and two
ports on one host share one. That is documented, and worth knowing before
relying on `per_domain=True` to isolate anything.

## Layout

| file | what it is |
| --- | --- |
| `acm_showcase/digest_server.py` | A configurable RFC 7616 digest server. Algorithm, `qop`, `realm`, `domain` and nonce expiry are all constructor arguments. |
| `acm_showcase/checks.py` | The scenarios, one function each, registered with a decorator. |
| `acm_showcase/__main__.py` | Runs them and reports. |

Adding a scenario is one decorated coroutine that returns a short string on
success and raises on failure.
