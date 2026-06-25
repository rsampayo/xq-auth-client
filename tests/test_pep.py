"""PEP — verify_capability: the allow path + every closed deny reason + the C4 trust clamp."""
import time

import jwt
import pytest

from xq_auth_client import (
    DenyReason,
    InMemoryRevocationFeed,
    PepEnvelope,
    TrustTier,
    verify_capability,
)

ISS = "https://brain.local"


@pytest.fixture
def envelope():
    return PepEnvelope(
        specialist_id="web.search",
        aud="https://mesh.local/web.search",
        allowed_ops=frozenset({"search"}),
        max_scope=frozenset({"read:web"}),
        output_trust_ceiling=TrustTier.TRUSTED_SYSTEM,
    )


def _verify(raw, keys, envelope, **kw):
    return verify_capability(raw_jwt=raw, signing_public_pem=keys["pub"], expected_iss=ISS, envelope=envelope, **kw)


def test_allow_clean_path(sign, cap_claims, keys, envelope):
    d = _verify(sign(cap_claims), keys, envelope)
    assert d.ok is True
    assert d.token.specialist == "web.search"
    # token ceiling (external_untrusted) is below the envelope ceiling -> result clamps to the token's
    assert d.output_trust_ceiling == TrustTier.EXTERNAL_UNTRUSTED


def test_trust_clamp_lowers_to_inbound_hwm(sign, cap_claims, keys, envelope):
    cap_claims["output_trust_ceiling"] = "trusted_system"  # token asks high
    d = _verify(sign(cap_claims), keys, envelope, inbound_trust_hwm=TrustTier.EXTERNAL_UNTRUSTED)
    assert d.ok and d.output_trust_ceiling == TrustTier.EXTERNAL_UNTRUSTED  # clamped DOWN by inbound HWM


def test_deny_no_actor(sign, cap_claims, keys, envelope):
    cap_claims.pop("act")
    assert _verify(sign(cap_claims), keys, envelope).reason == DenyReason.NO_ACTOR


def test_deny_wrong_audience(sign, cap_claims, keys, envelope):
    cap_claims["aud"] = "https://mesh.local/other"
    assert _verify(sign(cap_claims), keys, envelope).reason == DenyReason.WRONG_AUDIENCE


def test_deny_wrong_issuer(sign, cap_claims, keys, envelope):
    cap_claims["iss"] = "https://evil.local"
    assert _verify(sign(cap_claims), keys, envelope).reason == DenyReason.WRONG_ISSUER


def test_deny_op_not_allowed(sign, cap_claims, keys, envelope):
    cap_claims["op"] = "delete"
    assert _verify(sign(cap_claims), keys, envelope).reason == DenyReason.OP_NOT_ALLOWED


def test_deny_scope_exceeds_envelope(sign, cap_claims, keys, envelope):
    cap_claims["scope"] = "read:web write:web"
    assert _verify(sign(cap_claims), keys, envelope).reason == DenyReason.SCOPE_EXCEEDS_ENVELOPE


def test_deny_expired(sign, cap_claims, keys, envelope):
    cap_claims["exp"] = int(time.time()) - 3600
    assert _verify(sign(cap_claims), keys, envelope).reason == DenyReason.EXPIRED


def test_deny_egress_forbidden(sign, cap_claims, keys, envelope):
    envelope.can_egress = True  # a config error must fail closed
    assert _verify(sign(cap_claims), keys, envelope).reason == DenyReason.EGRESS_FORBIDDEN


def test_deny_revoked_jti(sign, cap_claims, keys, envelope):
    feed = InMemoryRevocationFeed()
    feed.revoke_jti(cap_claims["jti"])
    assert _verify(sign(cap_claims), keys, envelope, revocation=feed).reason == DenyReason.REVOKED_JTI


def test_deny_revoked_principal(sign, cap_claims, keys, envelope):
    feed = InMemoryRevocationFeed()
    feed.revoke_principal(cap_claims["sub"])  # kill the human -> all their tokens die
    assert _verify(sign(cap_claims), keys, envelope, revocation=feed).reason == DenyReason.REVOKED_PRINCIPAL


def test_deny_bad_signature(cap_claims, keys, envelope):
    forged = jwt.encode(cap_claims, "different-secret", algorithm="HS256")  # not our key/alg
    d = _verify(forged, keys, envelope)
    assert d.reason in (DenyReason.BAD_SIGNATURE, DenyReason.MALFORMED)
