"""The user-JWT validator — RS256 against the Brain's JWKS, no shared secret.

This is the piece that lands the audit's #1 fix (G1/G5): every cell-side resource server
(meetings/threads/mesh, and COSA's login leg) validates the Brain-issued user JWT against
`GET /.well-known/jwks.json` by `kid` — instead of an HS256 shared secret that breaks at the
network split. Static-JWK mode is for M1/tests; URL mode fetches + caches the live JWKS.

G4 (revocation coherence): the user-JWT leg is the HIGHER-authority leg, so it consults the SAME
CAEP/SSF revocation feed the capability PEP uses — a killed principal dies on the app/chat leg too,
not just on tools.
"""
from __future__ import annotations

import json
from enum import Enum

import jwt
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm

from xq_auth_client.revocation import RevocationFeed


class UserTokenDeny(str, Enum):
    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    WRONG_ISSUER = "wrong_issuer"
    WRONG_AUDIENCE = "wrong_audience"
    UNKNOWN_KID = "unknown_kid"
    REVOKED_PRINCIPAL = "revoked_principal"


class InvalidUserToken(Exception):
    """Raised on any user-JWT validation failure. `reason` is a closed, machine-actionable code → 401."""

    def __init__(self, reason: UserTokenDeny, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason.value}: {detail}" if detail else reason.value)


class JwksValidator:
    """Validate a Brain-issued RS256 user JWT against a JWK set, by `kid`.

    Provide EITHER `jwks` (a static JWK set: the {"keys":[...]} dict — M1/tests) OR `jwks_url` (the
    Brain's /.well-known/jwks.json — fetched + cached, rotation-transparent). `issuer`/`audience` are
    the values the Brain stamps (dev cell: iss=https://brain.local, aud=xq-app; per-cell via env).
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks: dict | None = None,
        jwks_url: str | None = None,
        revocation: RevocationFeed | None = None,
        leeway: int = 30,
    ) -> None:
        if not jwks and not jwks_url:
            raise ValueError("JwksValidator needs either a static `jwks` set or a `jwks_url`")
        self.issuer = issuer
        self.audience = audience
        self.revocation = revocation
        self.leeway = leeway
        # static mode: index the signing keys by kid up front.
        self._static_keys: dict[str, object] = {}
        if jwks:
            for jwk in jwks.get("keys", []):
                kid = jwk.get("kid")
                if kid:
                    self._static_keys[kid] = RSAAlgorithm.from_jwk(json.dumps(jwk))
        # url mode: PyJWKClient fetches + caches + resolves by kid.
        self._jwk_client = PyJWKClient(jwks_url) if jwks_url else None

    def _resolve_key(self, raw_jwt: str) -> object:
        try:
            kid = jwt.get_unverified_header(raw_jwt).get("kid")
        except jwt.PyJWTError as e:
            raise InvalidUserToken(UserTokenDeny.MALFORMED, type(e).__name__) from e
        if self._jwk_client is not None:
            try:
                return self._jwk_client.get_signing_key_from_jwt(raw_jwt).key
            except Exception as e:  # noqa: BLE001 — any resolution failure is an auth failure
                raise InvalidUserToken(UserTokenDeny.UNKNOWN_KID, str(kid)) from e
        key = self._static_keys.get(kid) if kid else None
        if key is None:
            raise InvalidUserToken(UserTokenDeny.UNKNOWN_KID, str(kid))
        return key

    def validate(self, raw_jwt: str) -> dict:
        """Return the verified claims, or raise InvalidUserToken. Resource servers: catch → 401."""
        key = self._resolve_key(raw_jwt)
        try:
            claims = jwt.decode(
                raw_jwt,
                key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise InvalidUserToken(UserTokenDeny.EXPIRED) from e
        except jwt.InvalidIssuerError as e:
            raise InvalidUserToken(UserTokenDeny.WRONG_ISSUER) from e
        except jwt.InvalidAudienceError as e:
            raise InvalidUserToken(UserTokenDeny.WRONG_AUDIENCE) from e
        except jwt.InvalidSignatureError as e:
            raise InvalidUserToken(UserTokenDeny.BAD_SIGNATURE) from e
        except jwt.PyJWTError as e:
            raise InvalidUserToken(UserTokenDeny.MALFORMED, type(e).__name__) from e

        # G4: the user-JWT leg consults the SAME revocation feed as the PEP — kill the principal here too.
        if self.revocation is not None and self.revocation.is_principal_revoked(claims["sub"]):
            raise InvalidUserToken(UserTokenDeny.REVOKED_PRINCIPAL, claims["sub"])
        return claims
