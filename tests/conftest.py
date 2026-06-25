"""Shared test fixtures: an ephemeral RS256 cell keypair + token factories."""
import json
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

KID = "test-kid"
ISS = "https://brain.local"


@pytest.fixture(scope="session")
def keys():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = k.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub = k.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk = json.loads(RSAAlgorithm.to_jwk(k.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"priv": priv, "pub": pub, "jwks": {"keys": [jwk]}, "kid": KID}


@pytest.fixture
def sign(keys):
    def _sign(claims: dict, *, kid: str = KID) -> str:
        return jwt.encode(claims, keys["priv"], algorithm="RS256", headers={"kid": kid})
    return _sign


@pytest.fixture
def cap_claims():
    """A valid capability-token claim-set (with `act`)."""
    now = int(time.time())
    return {
        "iss": ISS,
        "sub": str(uuid.uuid4()),
        "act": {"sub": str(uuid.uuid4())},
        "aud": "https://mesh.local/web.search",
        "scope": "read:web",
        "cell": "dimer",
        "specialist": "web.search",
        "op": "search",
        "output_trust_ceiling": "external_untrusted",
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }


@pytest.fixture
def user_claims():
    """A valid Brain-issued user-JWT claim-set."""
    now = int(time.time())
    return {"iss": ISS, "sub": str(uuid.uuid4()), "aud": "xq-app", "iat": now, "exp": now + 3600}
