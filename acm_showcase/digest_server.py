"""A configurable RFC 7616 digest-auth server, for driving the middleware.

Every knob the middleware can encounter is a constructor argument: the hash
algorithm, the ``qop`` the server advertises, whether it issues a ``stale``
challenge once, and whether it advertises a ``domain`` protection space.
"""

import hashlib
import os
from typing import Callable

from aiohttp import web

#: The algorithms RFC 7616 defines, plus the session variants.
ALGORITHMS = (
    "MD5",
    "MD5-sess",
    "SHA",
    "SHA-sess",
    "SHA-256",
    "SHA-256-sess",
    "SHA-512",
    "SHA-512-sess",
)

_HASHES: dict[str, Callable[[bytes], "hashlib._Hash"]] = {
    "MD5": hashlib.md5,
    "SHA": hashlib.sha1,
    "SHA-256": hashlib.sha256,
    "SHA-512": hashlib.sha512,
}


def _digest(algorithm: str, data: str) -> str:
    base = algorithm.removesuffix("-sess")
    return _HASHES[base](data.encode()).hexdigest()


def _parse_authorization(header: str) -> dict[str, str]:
    """Parse a ``Digest`` Authorization header into its fields."""
    if not header.startswith("Digest "):
        return {}
    fields: dict[str, str] = {}
    # Values may be quoted and contain commas, so walk the string rather
    # than splitting on them.
    remainder = header[len("Digest ") :]
    while remainder:
        remainder = remainder.lstrip(" ,")
        if "=" not in remainder:
            break
        key, _, remainder = remainder.partition("=")
        key = key.strip()
        if remainder.startswith('"'):
            value, _, remainder = remainder[1:].partition('"')
        else:
            value, _, remainder = remainder.partition(",")
        fields[key] = value.strip()
    return fields


class DigestServer:
    """Serves ``/protected`` behind digest auth, and ``/open`` without it."""

    def __init__(
        self,
        login: str = "user",
        password: str = "pass",
        algorithm: str = "MD5",
        qop: str | None = "auth",
        realm: str = "showcase",
        stale_once: bool = False,
        domain: str | None = None,
    ) -> None:
        self.login = login
        self.password = password
        self.algorithm = algorithm
        self.qop = qop
        self.realm = realm
        self.domain = domain
        self.stale_once = stale_once

        self.nonce = os.urandom(8).hex()
        #: Every request the server saw, as ``(path, had_authorization)``.
        self.requests: list[tuple[str, bool]] = []
        self.challenges_issued = 0
        self._stale_spent = False

    def expire_nonce(self) -> None:
        """Make the next authenticated request receive one ``stale=true``."""
        self.stale_once = True
        self._stale_spent = False

    # -- challenge / verification -------------------------------------------

    def _challenge_header(self, stale: bool = False) -> str:
        parts = [f'realm="{self.realm}"', f'nonce="{self.nonce}"']
        if self.qop:
            parts.append(f'qop="{self.qop}"')
        parts.append(f"algorithm={self.algorithm}")
        if self.domain:
            parts.append(f'domain="{self.domain}"')
        if stale:
            parts.append("stale=true")
        return "Digest " + ", ".join(parts)

    def _expected_response(self, fields: dict[str, str], method: str, body: bytes) -> str:
        a1 = f"{self.login}:{self.realm}:{self.password}"
        ha1 = _digest(self.algorithm, a1)
        if self.algorithm.endswith("-sess"):
            ha1 = _digest(
                self.algorithm, f"{ha1}:{fields.get('nonce', '')}:{fields.get('cnonce', '')}"
            )

        uri = fields.get("uri", "")
        qop = fields.get("qop", "")
        if qop == "auth-int":
            ha2 = _digest(self.algorithm, f"{method}:{uri}:{_digest(self.algorithm, body.decode())}")
        else:
            ha2 = _digest(self.algorithm, f"{method}:{uri}")

        if qop:
            middle = f"{fields.get('nonce', '')}:{fields.get('nc', '')}:{fields.get('cnonce', '')}:{qop}"
            return _digest(self.algorithm, f"{ha1}:{middle}:{ha2}")
        return _digest(self.algorithm, f"{ha1}:{fields.get('nonce', '')}:{ha2}")

    # -- handlers ------------------------------------------------------------

    async def protected(self, request: web.Request) -> web.Response:
        header = request.headers.get("Authorization", "")
        body = await request.read()
        self.requests.append((request.path, bool(header)))

        if not header:
            self.challenges_issued += 1
            return web.Response(
                status=401,
                headers={"WWW-Authenticate": self._challenge_header()},
                text="unauthorized",
            )

        fields = _parse_authorization(header)

        # Issue exactly one stale challenge, to exercise the refresh path.
        if self.stale_once and not self._stale_spent:
            self._stale_spent = True
            self.nonce = os.urandom(8).hex()
            self.challenges_issued += 1
            return web.Response(
                status=401,
                headers={"WWW-Authenticate": self._challenge_header(stale=True)},
                text="stale nonce",
            )

        if fields.get("response") != self._expected_response(fields, request.method, body):
            self.challenges_issued += 1
            return web.Response(
                status=401,
                headers={"WWW-Authenticate": self._challenge_header()},
                text="bad response",
            )

        return web.Response(text="authenticated")

    async def open_endpoint(self, request: web.Request) -> web.Response:
        self.requests.append((request.path, "Authorization" in request.headers))
        return web.Response(text="open")

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_route("*", "/protected", self.protected)
        app.router.add_route("*", "/protected/sub", self.protected)
        app.router.add_route("*", "/open", self.open_endpoint)
        return app
