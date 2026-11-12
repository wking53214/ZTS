"""Authenticate the caller's identity at release time, with a signature from your identity provider.

ZTS binds a release to a subject through CNS, and the grant issuer signs that subject into the grant. What none of that
establishes is that the caller really IS the subject: a caller could name any subject the issuer will issue grants for. This
module is the optional check for that. It is the ``identity_verifier`` hook of ``EnforcerReleaseGate``: called with the CNS
``IdentityContext`` before Enforcer is asked and again just before delivery, and only an exact ``True`` lets the release go on.

How the proof travels. The hook receives only the identity object, so the proof is carried in its ``signature`` field, which
CNS leaves to the consumer and which is already part of the subject digest the grant binds. The identity provider signs the
identity's other fields, an audience and a short validity window, with an Ed25519 key it holds. ``signature`` then reads::

    zts-identity-1.<header>.<payload>.<signature>        (each part unpadded base64url)

    header  = {"alg": "Ed25519", "kid": "ed25519-<16 hex>", "typ": "zts-identity-1"}
    payload = {"aud": "<audience>", "exp": <unix seconds>, "iat": <unix seconds>}
    signed  = b"zts-identity-1" + 0x00 + header + b"." + payload + 0x00 + binding

``binding`` is :func:`identity_binding_bytes`: canonical JSON of tenant_id, subject_id, roles, trust_level (its value),
authentication_method and verified. Because the signature covers those fields, changing a role or a subject after the identity
provider signed it makes the check fail. Because it covers ``verified`` and the verifier requires it to be true, the identity
provider says what it authenticated.

Keys. The public keys are held in the same trust root as the grant and status keys, with role ``identity``, so they get the same
rotation, revocation and rollback protection and the same review process. ZTS contains no signing code; a reference signer for the
identity provider is in ``examples/identity_provider/``.

What this does not do. It proves a holder of the identity provider's key vouched for this identity for a short time. It does not
stop someone who has stolen a valid signed identity from presenting it until it expires (so keep the window short), and it cannot
tell whether the identity provider authenticated the person properly. The signed identity is a bearer credential: treat it as one.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from .trust import (
    FileTrustRoot, Rejected, ROLE_IDENTITY, TrustRoot, TrustRootError, b64u_decode, lookup_key, read_header,
    split_signed, strict_json, verify_signature,
)

IDENTITY_TYPE = "zts-identity-1"
MAX_SIGNATURE_BYTES = 4096
DEFAULT_MAX_LIFETIME = 300.0
DEFAULT_SKEW = 5.0
_PAYLOAD_FIELDS = frozenset({"aud", "exp", "iat"})


def identity_binding_bytes(identity: Any) -> bytes:
    """The canonical bytes of the identity fields the identity provider signs. Raises Rejected if any field is the wrong type."""
    for name in ("tenant_id", "subject_id", "authentication_method"):
        value = getattr(identity, name, None)
        if type(value) is not str or not value.strip():
            raise Rejected("identity")
    roles = getattr(identity, "roles", None)
    if not isinstance(roles, (tuple, list)) or not all(type(r) is str and r for r in roles):
        raise Rejected("identity")
    level = getattr(getattr(identity, "trust_level", None), "value", getattr(identity, "trust_level", None))
    if type(level) is not str or not level:
        raise Rejected("identity")
    if getattr(identity, "verified", None) is not True:
        raise Rejected("not_verified")
    fields = {"tenant_id": identity.tenant_id, "subject_id": identity.subject_id, "roles": list(roles),
              "trust_level": level, "authentication_method": identity.authentication_method, "verified": True}
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Ed25519IdentityVerifier:
    """An ``identity_verifier`` hook: True only for an identity signed by a current ``identity`` key for this audience.

    Never raises: any problem is a False, with a short reason passed to ``on_reject`` (never the signature or the identity).
    Needs ``pip install zts[trust]``.
    """

    def __init__(
        self,
        trust: "TrustRoot | FileTrustRoot",
        *,
        audience: str,
        max_lifetime: float = DEFAULT_MAX_LIFETIME,
        max_skew: float = DEFAULT_SKEW,
        clock: Callable[[], datetime] | None = None,
        on_reject: Callable[[str], None] | None = None,
    ) -> None:
        if type(audience) is not str or not audience.strip():
            raise ValueError("audience is required: it stops an identity signed for another service being accepted here")
        for name, value in (("max_lifetime", max_lifetime), ("max_skew", max_skew)):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive number of seconds")
        self._trust, self._audience = trust, audience
        self._max_lifetime, self._max_skew = float(max_lifetime), float(max_skew)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._on_reject = on_reject

    @property
    def trust(self) -> "TrustRoot | FileTrustRoot":
        """The trust root this verifier checks against. Read-only; for deployment checks."""
        return self._trust

    @property
    def audience(self) -> str:
        return self._audience

    def _root(self) -> TrustRoot:
        return self._trust.current() if isinstance(self._trust, FileTrustRoot) else self._trust

    def __call__(self, identity: Any) -> bool:
        try:
            self._verify(identity)
        except Rejected as exc:
            self._notify(exc.reason)
        except TrustRootError:
            self._notify("trust_root")
        except Exception:
            self._notify("error")
        else:
            return True
        return False

    def _notify(self, reason: str) -> None:
        if self._on_reject is not None:
            try:
                self._on_reject(reason)
            except Exception:  # nosec B110
                pass  # an alerting hook must never turn a refusal into something else

    def _verify(self, identity: Any) -> None:
        binding = identity_binding_bytes(identity)
        proof = getattr(identity, "signature", None)
        if type(proof) is not str or not proof.isascii():
            raise Rejected("format")
        header_b64, payload_b64, sig_b64 = split_signed(proof.encode("ascii"), IDENTITY_TYPE.encode(), MAX_SIGNATURE_BYTES)
        kid = read_header(header_b64, IDENTITY_TYPE)
        now = self._clock().astimezone(timezone.utc)
        key = lookup_key(self._root(), kid, ROLE_IDENTITY, now)
        signature = b64u_decode(sig_b64)
        if len(signature) != 64:
            raise Rejected("format")
        verify_signature(key.public_key, signature,
                         IDENTITY_TYPE.encode() + b"\x00" + header_b64 + b"." + payload_b64 + b"\x00" + binding)
        # Only now, with the signature good, is the payload parsed.
        payload = strict_json(b64u_decode(payload_b64))
        if set(payload) != _PAYLOAD_FIELDS:
            raise Rejected("payload")
        issued, expires = payload["iat"], payload["exp"]
        if any(type(v) is not int for v in (issued, expires)) or payload["aud"] != self._audience:
            raise Rejected("audience" if payload["aud"] != self._audience else "payload")
        if expires <= issued or expires - issued > self._max_lifetime:
            raise Rejected("lifetime")
        moment = now.timestamp()
        if issued - self._max_skew > moment:
            raise Rejected("not_yet_valid")
        if moment >= expires:
            raise Rejected("expired")
        if not (key.not_before.timestamp() <= issued and expires <= key.not_after.timestamp()):
            raise Rejected("key_window")


__all__ = ["DEFAULT_MAX_LIFETIME", "Ed25519IdentityVerifier", "IDENTITY_TYPE", "identity_binding_bytes"]
