"""CapabilityToken (de)serialization roundtrip + the CAEP/SSF revocation feed ingestion."""
import time

import pytest

from xq_auth_client import (
    CAEP_SESSION_REVOKED,
    CapabilityToken,
    InMemoryRevocationFeed,
    TrustTier,
)


def test_capability_token_roundtrip(cap_claims):
    tok = CapabilityToken.from_claims(cap_claims)
    assert tok.act_sub == cap_claims["act"]["sub"]
    assert tok.scope == frozenset({"read:web"})
    # re-serialize: act nests, scope joins, tier serializes to its value
    claims = tok.to_claims()
    assert claims["act"] == {"sub": cap_claims["act"]["sub"]}
    assert claims["scope"] == "read:web"
    assert claims["output_trust_ceiling"] == "external_untrusted"
    # and it parses back identically
    assert CapabilityToken.from_claims(claims) == tok


def test_from_claims_rejects_missing_act(cap_claims):
    cap_claims.pop("act")
    with pytest.raises(ValueError, match="act"):
        CapabilityToken.from_claims(cap_claims)


def test_apply_set_session_revoked_kills_principal():
    feed = InMemoryRevocationFeed()
    pid = "principal-123"
    feed.apply_set({
        "iss": "https://brain.local",
        "jti": "evt-1",
        "iat": int(time.time()),
        "aud": "dimer",
        "events": {
            CAEP_SESSION_REVOKED: {"subject": {"format": "opaque", "id": pid}, "event_timestamp": 1},
        },
    })
    assert feed.is_principal_revoked(pid) is True
    assert feed.is_principal_revoked("someone-else") is False


def test_apply_set_token_revoked_by_suffix_kills_jti():
    feed = InMemoryRevocationFeed()
    feed.apply_set({"events": {"https://xq.local/secevent/token-revoked": {"jti": "tok-9"}}})
    assert feed.is_jti_revoked("tok-9") is True


def test_apply_set_malformed_is_noop():
    feed = InMemoryRevocationFeed()
    feed.apply_set({})  # no events
    feed.apply_set({"events": {CAEP_SESSION_REVOKED: {}}})  # no subject
    assert feed.is_principal_revoked("x") is False


def test_trust_tier_values():
    assert TrustTier.TRUSTED_HUMAN_FORWARDED.value == "trusted_human_forwarded"
