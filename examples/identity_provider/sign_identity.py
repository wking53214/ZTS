"""Reference signer for ZTS identity proofs: what your identity provider runs after it has authenticated someone.

It depends on the ``cryptography`` package and NOT on ZTS, on purpose: the format in ``zts/identity.py`` must be implementable
from its description alone, and the tests check this file against ZTS's verifier. Put the result in the ``signature`` field of
the CNS ``IdentityContext`` you hand to ZTS.

    signature = sign_identity(private_key, tenant_id="t1", subject_id="alice", roles=("reader",),
                              trust_level="verified", authentication_method="oidc", audience="zts-release/prod")

The private key belongs to the identity provider and never leaves it. Register its PUBLIC key in the trust root with role
``identity`` (key id ``ed25519-`` plus the first 16 hex characters of the SHA-256 of the raw public key; ``key_id`` below).
Keep the lifetime short: the signed identity is a bearer credential, valid for anyone who holds it until it expires.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

IDENTITY_TYPE = "zts-identity-1"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def key_id(private_key: Ed25519PrivateKey) -> str:
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519-" + hashlib.sha256(raw).hexdigest()[:16]


def sign_identity(
    private_key: Ed25519PrivateKey,
    *,
    tenant_id: str,
    subject_id: str,
    roles: tuple[str, ...] | list[str],
    trust_level: str,
    authentication_method: str,
    audience: str,
    lifetime_seconds: int = 120,
    issued_at: int | None = None,
) -> str:
    """Return the string for IdentityContext.signature. ``verified`` is always true: you sign only what you authenticated."""
    issued = int(time.time()) if issued_at is None else issued_at
    header = json.dumps({"alg": "Ed25519", "kid": key_id(private_key), "typ": IDENTITY_TYPE},
                        sort_keys=True, separators=(",", ":")).encode()
    payload = json.dumps({"aud": audience, "exp": issued + lifetime_seconds, "iat": issued},
                         sort_keys=True, separators=(",", ":")).encode()
    binding = json.dumps(
        {"tenant_id": tenant_id, "subject_id": subject_id, "roles": list(roles), "trust_level": trust_level,
         "authentication_method": authentication_method, "verified": True},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    h, p = _b64u(header).encode(), _b64u(payload).encode()
    signature = private_key.sign(IDENTITY_TYPE.encode() + b"\x00" + h + b"." + p + b"\x00" + binding)
    return f"{IDENTITY_TYPE}.{h.decode()}.{p.decode()}.{_b64u(signature)}"
