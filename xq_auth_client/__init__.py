"""xq-auth-client — the one shared XQ auth contract, imported by every cell-side service.

Source of truth for: the frozen capability token (§4), the PEP (`verify_capability`), the RS256/JWKS
user-JWT validator, and the CAEP/SSF revocation feed. Seeded verbatim from xq-cosa's frozen types so
the contract cannot drift across repos (the audit's G5 fix). COSA/meetings/threads/mesh import THIS.
"""
from xq_auth_client.jwks import InvalidUserToken, JwksValidator, UserTokenDeny
from xq_auth_client.pep import (
    Allow,
    Deny,
    DenyReason,
    PepDecision,
    PepEnvelope,
    verify_capability,
)
from xq_auth_client.revocation import (
    CAEP_SESSION_REVOKED,
    XQ_TOKEN_REVOKED_SUFFIX,
    InMemoryRevocationFeed,
    RevocationFeed,
)
from xq_auth_client.types import CapabilityToken, TrustTier

__all__ = [
    "CapabilityToken",
    "TrustTier",
    "verify_capability",
    "PepEnvelope",
    "PepDecision",
    "Allow",
    "Deny",
    "DenyReason",
    "RevocationFeed",
    "InMemoryRevocationFeed",
    "CAEP_SESSION_REVOKED",
    "XQ_TOKEN_REVOKED_SUFFIX",
    "JwksValidator",
    "InvalidUserToken",
    "UserTokenDeny",
]

__version__ = "0.1.0"
