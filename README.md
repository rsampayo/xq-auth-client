# xq-auth-client

The **one shared XQ auth contract**, imported by every cell-side service so it can never drift across
repos (the ecosystem audit's G5/R2 fix). It carries:

- **`CapabilityToken`** — the frozen §4 claim-set + JWT (de)serialization (seeded verbatim from
  `xq-cosa`, the authoring repo, so there is zero divergence).
- **`verify_capability` (the PEP)** — the choke every capability call routes through: RS256 signature,
  RFC 9207 `iss`, RFC 8707 `aud != self` reject, no-`act` reject, scope ⊆ envelope, egress-forbidden,
  and the C4 lower-only trust clamp `MIN(token, registry, inbound-HWM)`.
- **`JwksValidator`** — validates the Brain-issued **user JWT** against `/.well-known/jwks.json` by
  `kid`, RS256, no shared secret (the HS256→RS256 fix for meetings/threads/mesh; static-JWK mode for
  M1/tests, URL mode for live JWKS).
- **`RevocationFeed` + `InMemoryRevocationFeed`** — the CAEP/SSF kill switch both legs consult: the
  capability leg checks `jti`, the higher-authority user-JWT leg checks the principal (G4). `apply_set`
  ingests the Brain Transmitter's Security Event Tokens (RFC 8417).

## Use

```python
from xq_auth_client import JwksValidator, verify_capability, PepEnvelope, InMemoryRevocationFeed

# resource server (meetings/threads/mesh): validate the Brain user JWT against JWKS
validator = JwksValidator(issuer="https://brain.local", audience="xq-app",
                          jwks_url="https://<brain>/.well-known/jwks.json", revocation=feed)
claims = validator.validate(bearer)          # raises InvalidUserToken -> 401

# mesh PEP: verify a capability token for one specialist
decision = verify_capability(raw_jwt=tok, signing_public_pem=cell_pub_pem,
                             expected_iss="https://brain.local", envelope=env, revocation=feed)
```

Per-cell config: `issuer`/`audience` come from the cell (dev: `iss=https://brain.local`, `aud=xq-app`).
The **shape is fixed; only the strings vary per cell.**

Source of truth lives here. `xq-cosa` seeded it and imports it back (dropping its local copies);
`xq-meetings` / `xq-threads` / `xq-mesh` import it. Build forward — don't fork.
