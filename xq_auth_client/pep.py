"""The Policy Enforcement Point — `verify_capability()`: the choke EVERY capability call routes through.

Lifted verbatim from xq-cosa (xq_cosa/auth/pep.py); only the imports are re-homed to this package.
Even at M1 the token is cryptographically VERIFIED — never a same-process trust shortcut — or the
network split silently inherits unvalidated trust and the seam was never real.

The PEP grants because the SIGNATURE + SCOPE + AUDIENCE check out — NEVER because the `act` chain
"looks right" (the act chain is attribution; authority was re-derived server-side at mint). Audience
validation (RFC 8707) + no-token-passthrough are MCP-spec MUSTs.

TRUST CLAMP (Brain-team amendment C4): the result trust tier is clamped to the MIN of (the token
ceiling, the specialist registry ceiling, the inbound read-set high-water-mark). A token may only ever
LOWER trust, never raise it — this closes the trust-laundering hole (canon §16.4 bus-tiering).
"""
from __future__ import annotations

from enum import Enum

import jwt  # PyJWT
from pydantic import BaseModel

from xq_auth_client.revocation import RevocationFeed
from xq_auth_client.types import CapabilityToken, TrustTier

_TRUST_ORDER = {
    TrustTier.TRUSTED_SYSTEM: 4,
    TrustTier.TRUSTED_HUMAN: 3,
    TrustTier.TRUSTED_HUMAN_FORWARDED: 2,
    TrustTier.EXTERNAL_UNTRUSTED: 1,
    TrustTier.EDGE_UNVERIFIED: 0,
}


def _min_trust(a: TrustTier, b: TrustTier) -> TrustTier:
    return a if _TRUST_ORDER[a] <= _TRUST_ORDER[b] else b


class DenyReason(str, Enum):
    """Closed, machine-actionable reason set (no parsing human strings)."""

    MALFORMED = "malformed"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
    NO_ACTOR = "no_actor"                       # an agent must never look like a raw human
    WRONG_ISSUER = "wrong_issuer"
    WRONG_AUDIENCE = "wrong_audience"           # token minted for another specialist
    REVOKED_JTI = "revoked_jti"                 # this specific token was killed
    REVOKED_PRINCIPAL = "revoked_principal"     # the user/agent principal was killed (covers all tokens)
    OP_NOT_ALLOWED = "op_not_allowed"
    SCOPE_EXCEEDS_ENVELOPE = "scope_exceeds_envelope"
    EGRESS_FORBIDDEN = "egress_forbidden"       # no send/money authority rides any token, ever


class PepEnvelope(BaseModel):
    """The specialist's registry envelope the PEP enforces (Brain-owned; cached at the PEP).

    `max_scope` = the ceiling this specialist may EVER be granted (the token's advisory scope must be
    subseteq this). `can_egress` is ALWAYS False for a non-Brain principal — a True here is a config
    error the PEP treats as EGRESS_FORBIDDEN, making 'egress is never a capability' structural."""

    specialist_id: str
    aud: str                                   # this specialist's canonical URI == the token's expected aud
    allowed_ops: frozenset[str]
    max_scope: frozenset[str] = frozenset()
    can_egress: bool = False
    output_trust_ceiling: TrustTier = TrustTier.EXTERNAL_UNTRUSTED


class Allow(BaseModel):
    ok: bool = True
    token: CapabilityToken
    output_trust_ceiling: TrustTier            # clamped MIN(token, envelope, inbound)


class Deny(BaseModel):
    ok: bool = False
    reason: DenyReason
    detail: str = ""


PepDecision = Allow | Deny


def verify_capability(
    *,
    raw_jwt: str,
    signing_public_pem: bytes,
    expected_iss: str,
    envelope: PepEnvelope,
    revocation: RevocationFeed | None = None,
    inbound_trust_hwm: TrustTier = TrustTier.TRUSTED_SYSTEM,
    skew: int = 30,
) -> PepDecision:
    """Verify one capability token for one specialist. Fail-closed: any uncertainty -> Deny.

    Order matters — cryptographic checks first, then structural, then policy. Returns a typed decision.
    `inbound_trust_hwm` = the worst trust tier already in the turn's read-set; the result can never be
    more trusted than it (the C4 lower-only clamp).
    """
    # 1. signature + exp (PyJWT verifies RS256 + exp with leeway). aud checked manually for a typed reason.
    try:
        claims = jwt.decode(
            raw_jwt,
            signing_public_pem,
            algorithms=["RS256"],
            leeway=skew,
            options={"verify_aud": False, "require": ["exp", "iss", "sub", "aud", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        return Deny(reason=DenyReason.EXPIRED)
    except jwt.InvalidSignatureError:
        return Deny(reason=DenyReason.BAD_SIGNATURE)
    except jwt.PyJWTError as e:
        return Deny(reason=DenyReason.MALFORMED, detail=type(e).__name__)

    # 2. parse the typed contract (raises NO_ACTOR if `act` is absent)
    try:
        token = CapabilityToken.from_claims(claims)
    except (ValueError, KeyError) as e:
        if "act" in str(e):
            return Deny(reason=DenyReason.NO_ACTOR)
        return Deny(reason=DenyReason.MALFORMED, detail=str(e))

    # 3. issuer (RFC 9207 anti-mix-up)
    if token.iss != expected_iss:
        return Deny(reason=DenyReason.WRONG_ISSUER, detail=token.iss)

    # 4. audience (RFC 8707) — bound to exactly THIS specialist; a token for A is useless at B
    if token.aud != envelope.aud or token.specialist != envelope.specialist_id:
        return Deny(reason=DenyReason.WRONG_AUDIENCE, detail=f"{token.aud}/{token.specialist}")

    # 5. revocation — read the CAEP/SSF-shaped feed (NOT a local set). Covers BOTH legs: this token's
    #    `jti`, and the user/agent PRINCIPAL (kills all their live tokens). Brain-team audit fix.
    if revocation is not None:
        if revocation.is_jti_revoked(token.jti):
            return Deny(reason=DenyReason.REVOKED_JTI)
        if revocation.is_principal_revoked(token.sub) or revocation.is_principal_revoked(token.act_sub):
            return Deny(reason=DenyReason.REVOKED_PRINCIPAL)

    # 6. operation allowed by the registry envelope
    if token.op not in envelope.allowed_ops:
        return Deny(reason=DenyReason.OP_NOT_ALLOWED, detail=token.op)

    # 7. scope subseteq envelope ceiling (the token's scope is advisory; this caps it to what the specialist may get)
    if not token.scope <= envelope.max_scope:
        return Deny(
            reason=DenyReason.SCOPE_EXCEEDS_ENVELOPE,
            detail=",".join(sorted(token.scope - envelope.max_scope)),
        )

    # 8. egress is NEVER a capability — structural, not policy
    if envelope.can_egress:
        return Deny(reason=DenyReason.EGRESS_FORBIDDEN)

    # 9. allow — clamp result trust to MIN(token ceiling, envelope ceiling, inbound read-set HWM).
    #    The token can only LOWER trust, never raise it (C4).
    clamped = _min_trust(
        _min_trust(token.output_trust_ceiling, envelope.output_trust_ceiling),
        inbound_trust_hwm,
    )
    return Allow(token=token, output_trust_ceiling=clamped)
