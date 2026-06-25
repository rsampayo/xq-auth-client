"""The principal-revocation feed — the kill switch that covers BOTH auth legs.

Lifted verbatim from xq-cosa. Short-TTL is only a *backstop*; a fired employee / compromised agent
must be killable NOW. The capability-token leg checks `jti`; the user-JWT leg checks the principal/
session. BOTH consult ONE feed (CAEP/SSF-shaped) — the PEP and the login validator read the feed,
never a local ad-hoc set.

M1: an in-cell `InMemoryRevocationFeed`. End-state: a CAEP/SSF *Receiver* of the Brain's Transmitter
(the Brain pushes `session-revoked` / `token-revoked` Security Event Tokens) — same interface, real
bus. Keep the interface CAEP-shaped now so the swap is a wiring change.
"""
from __future__ import annotations

from typing import Any, Protocol

# CAEP/SSF (RFC 8417) Security Event Token event-type URIs the feed ingests. `session-revoked` is the
# CAEP standard (kill a principal). Single-token revoke is NOT CAEP-standard, so it's a namespaced XQ
# event — the Brain locks the final URI when its Transmitter lands; we match by a suffix to stay robust.
CAEP_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
XQ_TOKEN_REVOKED_SUFFIX = "/secevent/token-revoked"  # provisional namespaced XQ event (URI TBD)


class RevocationFeed(Protocol):
    """What both legs consult. `is_jti_revoked` = the capability-token leg; `is_principal_revoked` =
    the user-JWT/session leg (kill the human or the agent principal)."""

    def is_jti_revoked(self, jti: str) -> bool: ...

    def is_principal_revoked(self, principal_id: str) -> bool: ...


class InMemoryRevocationFeed:
    """M1 in-cell feed. Cell-scoped; survives a turn but not a restart (the Brain's durable feed is the
    end-state source of truth). Methods mirror the CAEP events the Brain Transmitter will push."""

    def __init__(self) -> None:
        self._jtis: set[str] = set()
        self._principals: set[str] = set()

    # -- the CAEP-shaped mutations (end-state: driven by inbound Security Event Tokens) --
    def revoke_jti(self, jti: str) -> None:
        self._jtis.add(jti)

    def revoke_principal(self, principal_id: str) -> None:
        """Kill a human or agent principal (offboarding / compromise) — covers ALL their live tokens."""
        self._principals.add(principal_id)

    # -- the reads both legs perform --
    def is_jti_revoked(self, jti: str) -> bool:
        return jti in self._jtis

    def is_principal_revoked(self, principal_id: str) -> bool:
        return principal_id in self._principals

    # -- CAEP/SSF ingestion (end-state: the Brain Transmitter pushes these SETs; wire each to here) --
    def apply_set(self, set_payload: dict[str, Any]) -> None:
        """Ingest one CAEP/SSF Security Event Token (RFC 8417). `session-revoked` -> kill the principal
        (`subject.id`); the namespaced `token-revoked` -> kill a single `jti`. Lenient on missing fields
        (a malformed event is a no-op, never a crash). This is the ONLY swap point for the real bus."""
        events = set_payload.get("events") or {}
        for event_uri, body in events.items():
            body = body or {}
            if event_uri == CAEP_SESSION_REVOKED:
                pid = (body.get("subject") or {}).get("id")
                if pid:
                    self.revoke_principal(pid)
            elif event_uri.endswith(XQ_TOKEN_REVOKED_SUFFIX):
                jti = body.get("jti") or (body.get("subject") or {}).get("id")
                if jti:
                    self.revoke_jti(jti)
