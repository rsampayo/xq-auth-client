"""The frozen auth contract types — the SINGLE source of truth every plane imports.

Lifted verbatim from xq-cosa (xq_cosa/types.py), which authored the frozen claim-set. COSA, the
Brain mint, the mesh PEP, and the cell-side resource servers (meetings/threads) all import THESE so
the §4 capability-token contract can never drift across repos (the audit's G5 fix).
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel


class TrustTier(str, Enum):
    """Origin-trust as a monotone taint. A Claim's trust = MIN over its read-set (xq-brain/docs/15 §16)."""

    TRUSTED_SYSTEM = "trusted_system"      # read from a system of record (ERP)
    TRUSTED_HUMAN = "trusted_human"        # an authenticated human asserted it DIRECTLY
    TRUSTED_HUMAN_FORWARDED = "trusted_human_forwarded"  # the agent asserts it ABOUT its user
    #     ^ strictly BELOW an authenticated human's own message — the tier for an agent-minted
    #       user-claim with CLEAN provenance. "About the user" is a SUBJECT axis, never a trust
    #       tier: a user-claim whose ancestry includes external bytes is EXTERNAL_UNTRUSTED
    #       regardless of being about the user (DECIDED-MODEL clause 8 / red-team CHANGE 1).
    EXTERNAL_UNTRUSTED = "external_untrusted"  # inbound email/web/3rd-party
    EDGE_UNVERIFIED = "edge_unverified"    # an ungrounded ORG-FACT pointer (NOT the native user-model)


class CapabilityToken(BaseModel):
    """The single frozen auth contract every plane imports. RS256-signed by the per-cell key.

    THREE LOAD-BEARING RULINGS:
      - `act_sub` (the agent principal) is ATTRIBUTION/AUDIT ONLY — never authority. Authority is
        re-derived server-side as min(agent,user) at mint and re-checked at the PEP. A token with no
        `act` is REJECTED (an agent must never look like a raw human). [RFC 8693]
      - `aud` binds the token to exactly ONE specialist URI; the PEP rejects `aud != self`. [RFC 8707]
      - `scope` is an ADVISORY ceiling (the PDP + registry envelope are the gate); egress is NEVER
        expressible here — no send/money authority rides any token.
    """

    iss: str                                  # RFC 9207 — the Brain canonical URI (PEP validates)
    sub: str                                  # the delegating human (user principal UUID)
    act_sub: str                              # RFC 8693 actor = the COSA agent principal (ATTRIBUTION ONLY)
    aud: str                                  # RFC 8707 — the ONE target specialist canonical URI
    scope: frozenset[str] = frozenset()       # min(agent,user) — ADVISORY ceiling, NOT the gate
    cell: str                                 # per-cell signing key + claim -> cross-cell replay impossible
    specialist: str                           # the leaf specialist id
    op: str                                   # the operation requested
    output_trust_ceiling: TrustTier = TrustTier.EXTERNAL_UNTRUSTED  # PEP clamps results to this
    iat: int                                  # issued-at (epoch seconds)
    exp: int                                  # expiry (epoch seconds) — minutes TTL, bounds revocation lag
    jti: str                                  # unique — deny-list / replay defense

    def to_claims(self) -> dict[str, Any]:
        """Serialize to JWT claims (RFC 8693 nested `act`; space-delimited `scope`)."""
        return {
            "iss": self.iss,
            "sub": self.sub,
            "act": {"sub": self.act_sub},
            "aud": self.aud,
            "scope": " ".join(sorted(self.scope)),
            "cell": self.cell,
            "specialist": self.specialist,
            "op": self.op,
            "output_trust_ceiling": self.output_trust_ceiling.value,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
        }

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> "CapabilityToken":
        """Parse JWT claims back into the typed contract. Raises if `act` is absent (no raw-human tokens)."""
        act = claims.get("act")
        if not isinstance(act, dict) or not act.get("sub"):
            raise ValueError("capability token has no `act` actor claim (an agent must not look like a raw human)")
        scope_raw = claims.get("scope") or ""
        return cls(
            iss=claims["iss"],
            sub=claims["sub"],
            act_sub=act["sub"],
            aud=claims["aud"],
            scope=frozenset(scope_raw.split()) if scope_raw else frozenset(),
            cell=claims["cell"],
            specialist=claims["specialist"],
            op=claims["op"],
            output_trust_ceiling=TrustTier(claims.get("output_trust_ceiling", TrustTier.EXTERNAL_UNTRUSTED.value)),
            iat=int(claims["iat"]),
            exp=int(claims["exp"]),
            jti=claims["jti"],
        )
