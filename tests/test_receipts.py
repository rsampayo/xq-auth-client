"""BR2/BR5 receipt contract — the previously untested half of the shared lib (audit 2026-07-01 P9).

`verify_brain_receipt` is the fail-closed mapper COSA's `honesty-shim.ts::verifyBrainReceipt` mirrors;
these tests freeze the Python side of that cross-language contract, including the confirmation-code
allowlist (the TS copy is hand-duplicated — any change here must be a deliberate, visible diff there too).
"""

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from xq_auth_client import (
    POSITIVE_CONFIRMATION_CODES,
    Confirmed,
    Unconfirmed,
    build_receipt,
    sign_receipt,
    verify_brain_receipt,
)

KEY = "todo:abc:v1"


def _receipt(**overrides) -> dict:
    base = {"confirmationCode": "committed", "idempotencyKey": KEY, "itemVersion": "7"}
    base.update(overrides)
    return base


def test_allowlist_is_frozen_parity_anchor():
    # The TS side (cosa honesty-shim.ts) hand-duplicates this set. Changing it is a cross-repo,
    # deliberate act — this assertion makes any drift a visible diff, not a silent one.
    assert POSITIVE_CONFIRMATION_CODES == frozenset(
        {"committed", "write_committed", "gtc_submitted", "gtc_decision_committed"}
    )


def test_build_receipt_coerces_item_version_to_string_and_omits_sig():
    r = build_receipt("committed", KEY, 42)
    assert r == {"confirmationCode": "committed", "idempotencyKey": KEY, "itemVersion": "42"}


def test_build_receipt_includes_signature_when_given():
    assert build_receipt("committed", KEY, "7", signature="sig.jwt")["sig"] == "sig.jwt"


@pytest.mark.parametrize("code", sorted(POSITIVE_CONFIRMATION_CODES))
def test_verify_confirms_every_allowlisted_code(code):
    state = verify_brain_receipt(_receipt(confirmationCode=code), KEY)
    assert isinstance(state, Confirmed)
    assert state.confirmation_code == code
    assert state.idempotency_key == KEY
    assert state.item_version == "7"


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("not-a-dict", "malformed_response"),
        (None, "malformed_response"),
        (_receipt(idempotencyKey=None), "missing_idempotency_key"),
        (_receipt(idempotencyKey="  "), "missing_idempotency_key"),
        (_receipt(idempotencyKey="todo:OTHER:v1"), "idempotency_key_mismatch"),
        (_receipt(itemVersion=None), "missing_item_version"),
        (_receipt(itemVersion=7), "missing_item_version"),  # a JSON number MUST be rejected (TS parity)
        (_receipt(confirmationCode="ok"), "unrecognized_confirmation_code"),
        (_receipt(confirmationCode=None), "unrecognized_confirmation_code"),
    ],
)
def test_verify_fails_closed(raw, reason):
    state = verify_brain_receipt(raw, KEY)
    assert isinstance(state, Unconfirmed)
    assert state.reason == reason


def test_sign_receipt_round_trips_rs256():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    token = sign_receipt(priv, "kid-1", confirmation_code="committed", idempotency_key=KEY, item_version="7")
    assert jwt.get_unverified_header(token)["kid"] == "kid-1"
    claims = jwt.decode(token, pub, algorithms=["RS256"])
    assert claims == {"confirmationCode": "committed", "idempotencyKey": KEY, "itemVersion": "7"}
