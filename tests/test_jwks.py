"""JwksValidator — the RS256/JWKS user-JWT leg + the G4 principal-revocation check."""
import time

import jwt
import pytest

from xq_auth_client import InMemoryRevocationFeed, InvalidUserToken, JwksValidator, UserTokenDeny

ISS = "https://brain.local"
AUD = "xq-app"


def _validator(keys, **kw):
    return JwksValidator(issuer=ISS, audience=AUD, jwks=keys["jwks"], **kw)


def test_validates_brain_issued_user_jwt(sign, user_claims, keys):
    claims = _validator(keys).validate(sign(user_claims))
    assert claims["sub"] == user_claims["sub"]


def test_reject_wrong_issuer(sign, user_claims, keys):
    user_claims["iss"] = "https://evil.local"
    with pytest.raises(InvalidUserToken) as e:
        _validator(keys).validate(sign(user_claims))
    assert e.value.reason == UserTokenDeny.WRONG_ISSUER


def test_reject_wrong_audience(sign, user_claims, keys):
    user_claims["aud"] = "someone-else"
    with pytest.raises(InvalidUserToken) as e:
        _validator(keys).validate(sign(user_claims))
    assert e.value.reason == UserTokenDeny.WRONG_AUDIENCE


def test_reject_expired(sign, user_claims, keys):
    user_claims["exp"] = int(time.time()) - 3600
    with pytest.raises(InvalidUserToken) as e:
        _validator(keys).validate(sign(user_claims))
    assert e.value.reason == UserTokenDeny.EXPIRED


def test_reject_unknown_kid(sign, user_claims, keys):
    with pytest.raises(InvalidUserToken) as e:
        _validator(keys).validate(sign(user_claims, kid="not-our-kid"))
    assert e.value.reason == UserTokenDeny.UNKNOWN_KID


def test_g4_principal_revocation_on_user_leg(sign, user_claims, keys):
    feed = InMemoryRevocationFeed()
    feed.revoke_principal(user_claims["sub"])
    with pytest.raises(InvalidUserToken) as e:
        _validator(keys, revocation=feed).validate(sign(user_claims))
    assert e.value.reason == UserTokenDeny.REVOKED_PRINCIPAL


def test_requires_a_key_source():
    with pytest.raises(ValueError):
        JwksValidator(issuer=ISS, audience=AUD)


def test_dual_mode_accepts_legacy_hs256_during_cutover(sign, user_claims, keys):
    # transition state: Brain still mints HS256 while serving JWKS → the validator must accept BOTH.
    secret = "shared-cutover-secret"
    v = JwksValidator(issuer=ISS, audience=AUD, jwks=keys["jwks"], legacy_hs256_secret=secret)
    hs = jwt.encode({**user_claims}, secret, algorithm="HS256")
    assert v.validate(hs)["sub"] == user_claims["sub"]   # legacy HS256 accepted...
    assert v.validate(sign(user_claims))["sub"] == user_claims["sub"]  # ...and RS256 via JWKS too


def test_hs256_rejected_when_no_legacy_secret(user_claims, keys):
    # the end state: no shared secret → an HS256 token can't resolve a kid → rejected
    v = JwksValidator(issuer=ISS, audience=AUD, jwks=keys["jwks"])
    hs = jwt.encode({**user_claims}, "whatever", algorithm="HS256")
    with pytest.raises(InvalidUserToken):
        v.validate(hs)
