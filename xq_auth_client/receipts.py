"""The BR2/BR5 honesty-floor receipt — the cross-language Python source of truth (RATIFIED 2026-06-28).

The Brain emits a receipt COSA's `honesty-shim.ts::verifyBrainReceipt` accepts; only a verified receipt can
mint a `settled` belief on the COSA side. This module is the Python projection of that contract so every
cell-side Python service (Brain mint/actuator, meetings, threads, mesh) agrees byte-for-byte; the TypeScript
side keeps `honesty-shim.ts` and docs/PHASE-C-RECEIPT-CONTRACT.md is the language-neutral spec.

THE WIRE SHAPE (camelCase keys):
    { "confirmationCode": <one of POSITIVE_CONFIRMATION_CODES>,
      "idempotencyKey":   <the request's idempotency key, echoed UNMUTATED>,
      "itemVersion":      <the post-write row etag, AS A STRING> }

`itemVersion` MUST be a string (COSA reads it via `readStringField` → `typeof === 'string'`; a JSON number is
rejected as `missing_item_version`). `verify_brain_receipt` is a faithful port of the TS fail-closed mapper.

SIGNING (M1): `sig` is OFF — the unforgeable brand + idempotency echo + the durable receipt ledger are the
guarantee. `sign_receipt` builds an OPTIONAL detached RS256 signature (forward-compatible, no wire change).
"""

from __future__ import annotations

from dataclasses import dataclass

import jwt

POSITIVE_CONFIRMATION_CODES: frozenset[str] = frozenset(
    {"committed", "write_committed", "gtc_submitted", "gtc_decision_committed"}
)


def build_receipt(
    confirmation_code: str, idempotency_key: str, item_version: str | int, *, signature: str | None = None
) -> dict:
    """Build the exact wire dict COSA's `verifyBrainReceipt` accepts. `itemVersion` is coerced to a STRING."""
    receipt = {
        "confirmationCode": confirmation_code,
        "idempotencyKey": idempotency_key,
        "itemVersion": str(item_version),
    }
    if signature:
        receipt["sig"] = signature
    return receipt


def sign_receipt(
    private_pem: str, kid: str, *, confirmation_code: str, idempotency_key: str, item_version: str
) -> str:
    """Optional detached RS256 signature over the canonical receipt (off at M1; forward-compatible)."""
    return jwt.encode(
        {"confirmationCode": confirmation_code, "idempotencyKey": idempotency_key, "itemVersion": item_version},
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )


@dataclass(frozen=True)
class Confirmed:
    kind: str  # 'confirmed'
    confirmation_code: str
    idempotency_key: str
    item_version: str


@dataclass(frozen=True)
class Unconfirmed:
    kind: str  # 'unconfirmed'
    reason: str


ConfirmationState = Confirmed | Unconfirmed


def _read_string_field(raw: dict, key: str) -> str | None:
    value = raw.get(key)
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed if trimmed else None


def verify_brain_receipt(raw: object, expected_idempotency_key: str) -> ConfirmationState:
    """Port of COSA's fail-closed mapper. Confirms ONLY a well-formed object that echoes the EXPECTED
    idempotency key, carries a STRING item_version, and a confirmation code in the positive allowlist."""
    if not isinstance(raw, dict):
        return Unconfirmed("unconfirmed", "malformed_response")
    idempotency_key = _read_string_field(raw, "idempotencyKey")
    if not idempotency_key:
        return Unconfirmed("unconfirmed", "missing_idempotency_key")
    if idempotency_key != expected_idempotency_key:
        return Unconfirmed("unconfirmed", "idempotency_key_mismatch")
    item_version = _read_string_field(raw, "itemVersion")
    if not item_version:
        return Unconfirmed("unconfirmed", "missing_item_version")
    confirmation_code = _read_string_field(raw, "confirmationCode")
    if not confirmation_code or confirmation_code not in POSITIVE_CONFIRMATION_CODES:
        return Unconfirmed("unconfirmed", "unrecognized_confirmation_code")
    return Confirmed("confirmed", confirmation_code, idempotency_key, item_version)
