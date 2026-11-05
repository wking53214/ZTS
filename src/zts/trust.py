"""Ed25519 verification of release grants against an operator-pinned trust root.

This is the verifier half of Enforcer's ``ProofVerifier`` seam. It signs nothing and
issues nothing: authority comes from whoever holds a private key listed in the trust
root, and this module only checks signatures. It follows the stack's existing
convention for signed evidence (TIE, HERALD): Ed25519, public keys pinned by the
caller, keyed by id, unknown keys refused.

Governance is NOT in this file. Who owns the keys, how they are stored and rotated,
and who may edit the trust root are the operator's decisions. What this module
enforces is the mechanism:

  * one algorithm, Ed25519, named in a signed header; anything else is refused, so a
    proof cannot select a weaker one;
  * unknown key id, a key of the wrong role, a revoked key, or a key outside its
    validity window is refused;
  * a key may only sign for the issuer the trust root binds it to;
  * the signature is checked before the claims are parsed;
  * every defect is one generic refusal to Enforcer, with a reason code to an
    optional ``on_reject`` hook for alerting.

Grant wire format (``zts-grant-1``), four dot-separated fields::

    zts-grant-1 . b64u(header) . b64u(claims) . b64u(signature)

    header     {"alg": "Ed25519", "kid": "ed25519-<16 hex>", "typ": "zts-grant-1"}
    claims     the thirteen Enforcer GrantClaims fields, timestamps ISO-8601 with offset
    signature  Ed25519 over  b"zts-grant-1\\x00" + b64u(header) + b"." + b64u(claims)

Base64url is unpadded and must be canonical. The trust root is a JSON file, see
:class:`TrustRoot`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GRANT_TYPE = "zts-grant-1"
ALGORITHM = "Ed25519"
ROLE_GRANT = "grant"
ROLE_STATUS = "status"
MAX_PROOF_BYTES = 8192

_KID = re.compile(r"^ed25519-[0-9a-f]{16}$")
_CLAIM_FIELDS = frozenset({
    "issuer_id", "subject_id", "action", "target_type", "target_id", "evidence_sha256",
    "request_id", "parameters_sha256", "policy_version", "schema_version",
    "issued_at", "expires_at", "nonce",
})


class TrustRootError(RuntimeError):
    """The trust root is missing, unreadable, malformed or unsafe. Everything is refused."""


class Rejected(Exception):
    """Internal: carries a short reason code for the ``on_reject`` hook."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------- encoding helpers


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: bytes | str) -> bytes:
    """Strict unpadded base64url. Refuses padding, other alphabets and non-canonical forms."""
    if isinstance(text, str):
        text = text.encode("ascii")
    if not text or not re.fullmatch(rb"[A-Za-z0-9_-]+", text):
        raise Rejected("format")
    try:
        raw = base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise Rejected("format") from None
    if b64u_encode(raw).encode("ascii") != text:
        raise Rejected("format")
    return raw


def strict_json(raw: bytes) -> dict[str, Any]:
    """A JSON object with no duplicate keys, no NaN/Infinity, UTF-8 only."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise Rejected("format")
            out[key] = value
        return out

    def no_constant(_: str) -> Any:
        raise Rejected("format")

    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                           parse_constant=no_constant)
    except (UnicodeDecodeError, ValueError):
        raise Rejected("format") from None
    if not isinstance(value, dict):
        raise Rejected("format")
    return value


def parse_time(value: Any) -> datetime:
    """ISO-8601 with an explicit offset. Naive and non-string values are refused."""
    if not isinstance(value, str):
        raise Rejected("claims")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise Rejected("claims") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise Rejected("claims")
    return parsed.astimezone(timezone.utc)


def key_id(raw_public_key: bytes) -> str:
    """``ed25519-`` plus 16 hex of SHA-256 of the raw key: the id TIE and HERALD already use."""
    return "ed25519-" + hashlib.sha256(raw_public_key).hexdigest()[:16]


# ---------------------------------------------------------------------- trust root


@dataclass(frozen=True)
class TrustedKey:
    kid: str
    issuer_id: str
    role: str
    public_key: bytes
    not_before: datetime
    not_after: datetime
    status: str  # "active" or "revoked"

    def usable_at(self, moment: datetime) -> bool:
        return self.status == "active" and self.not_before <= moment <= self.not_after


class TrustRoot:
    """An immutable set of pinned public keys.

    File format (JSON)::

        {"version": 1,
         "keys": [{"kid": "ed25519-...", "issuer_id": "...", "role": "grant" | "status",
                   "public_key": "<b64u raw 32 bytes>", "not_before": "...", "not_after": "...",
                   "status": "active" | "revoked"}]}

    Unknown fields, duplicate key ids, a key id that is not derived from its key, a window
    that ends before it starts, and any other role or status are refused.
    """

    def __init__(self, keys: dict[str, TrustedKey], digest: str) -> None:
        self.keys = dict(keys)
        #: SHA-256 of the canonical document: recorded in the verifier id, so a decision
        #: in the audit trail names the exact trust root that made it.
        self.digest = digest

    @classmethod
    def from_dict(cls, doc: Any) -> "TrustRoot":
        try:
            return cls._build(doc)
        except Rejected as exc:
            raise TrustRootError(f"trust root is malformed ({exc.reason})") from None

    @classmethod
    def _build(cls, doc: Any) -> "TrustRoot":
        if not isinstance(doc, dict) or set(doc) != {"version", "keys"} or doc["version"] != 1 \
                or not isinstance(doc["keys"], list):
            raise Rejected("document")
        keys: dict[str, TrustedKey] = {}
        for entry in doc["keys"]:
            fields = {"kid", "issuer_id", "role", "public_key", "not_before", "not_after", "status"}
            if not isinstance(entry, dict) or set(entry) != fields:
                raise Rejected("key fields")
            raw = b64u_decode(entry["public_key"]) if isinstance(entry["public_key"], str) else b""
            issuer = entry["issuer_id"]
            if (len(raw) != 32 or entry["kid"] != key_id(raw) or entry["kid"] in keys
                    or entry["role"] not in (ROLE_GRANT, ROLE_STATUS)
                    or entry["status"] not in ("active", "revoked")
                    or not isinstance(issuer, str) or not issuer.strip()):
                raise Rejected("key")
            not_before, not_after = parse_time(entry["not_before"]), parse_time(entry["not_after"])
            if not_after <= not_before:
                raise Rejected("window")
            keys[entry["kid"]] = TrustedKey(entry["kid"], issuer, entry["role"], raw,
                                            not_before, not_after, entry["status"])
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return cls(keys, hashlib.sha256(canonical).hexdigest())


def _check_trust_file(path: Path) -> None:
    info = path.stat()
    if info.st_uid not in (os.getuid(), 0):
        raise TrustRootError(f"{path} is not owned by this user or root")
    if info.st_mode & 0o022:
        raise TrustRootError(f"{path} is writable by other users; set its mode to 644 or stricter")


class FileTrustRoot:
    """A trust root read from a file and re-read whenever the file changes.

    Re-reading on change is how rotation and revocation take effect without a restart.
    Any problem, a missing file, a bad permission, a parse error, a digest that does not
    match ``expected_sha256``, raises :class:`TrustRootError` on use. There is no fallback
    to the previous contents, because a revocation must not be undone by a broken update.
    ``expected_sha256`` pins the file's bytes out of band; change it together with the file.
    """

    def __init__(self, path: str | Path, *, expected_sha256: str | None = None) -> None:
        self.path = Path(path)
        self._expected = expected_sha256
        self._lock = threading.Lock()
        self._stamp: tuple[int, ...] | None = None
        self._root: TrustRoot | None = None
        self.current()  # fail at construction, not at the first release

    def current(self) -> TrustRoot:
        with self._lock:
            try:
                info = self.path.stat()
                # ctime and mode are in the stamp so a chmod, which changes neither the contents
                # nor the mtime, still forces the permission check to run again.
                stamp = (info.st_mtime_ns, info.st_ctime_ns, info.st_size, info.st_ino, info.st_mode)
                if stamp != self._stamp or self._root is None:
                    _check_trust_file(self.path)
                    data = self.path.read_bytes()
                    if self._expected is not None and hashlib.sha256(data).hexdigest() != self._expected:
                        raise TrustRootError("the trust root file does not match its pinned digest")
                    try:
                        doc = json.loads(data.decode("utf-8", errors="strict"))
                    except (UnicodeDecodeError, ValueError):
                        raise TrustRootError("the trust root file is not valid JSON") from None
                    self._root = TrustRoot.from_dict(doc)
                    self._stamp = stamp
                return self._root
            except OSError as exc:
                self._root, self._stamp = None, None
                raise TrustRootError(f"the trust root file cannot be read: {exc.strerror}") from None
            except TrustRootError:
                self._root, self._stamp = None, None
                raise


# ------------------------------------------------------------------------ verifier


def _enforcer() -> Any:
    try:
        import enforcer
    except ImportError as exc:
        raise Rejected("enforcer unavailable") from exc
    return enforcer


def _ed25519() -> Any:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise Rejected("cryptography unavailable") from exc
    return Ed25519PublicKey, InvalidSignature


def verify_signature(public_key: bytes, signature: bytes, message: bytes) -> None:
    """Raises Rejected("bad_signature") unless ``signature`` is Ed25519 over ``message``."""
    key_type, invalid = _ed25519()
    try:
        key_type.from_public_bytes(public_key).verify(signature, message)
    except (invalid, ValueError):
        raise Rejected("bad_signature") from None


def split_signed(blob: Any, prefix: bytes, limit: int) -> tuple[bytes, bytes, bytes]:
    """Split ``prefix.header.body.signature`` into its three base64url fields, strictly."""
    if not isinstance(blob, (bytes, bytearray)) or not 0 < len(blob) <= limit:
        raise Rejected("format")
    parts = bytes(blob).split(b".")
    if len(parts) != 4 or parts[0] != prefix:
        raise Rejected("format")
    return parts[1], parts[2], parts[3]


def read_header(raw_b64: bytes, typ: str) -> str:
    """Check the signed header names Ed25519 and this document type; return the key id."""
    header = strict_json(b64u_decode(raw_b64))
    if set(header) != {"alg", "kid", "typ"}:
        raise Rejected("header")
    if header["alg"] != ALGORITHM:
        raise Rejected("unsupported_alg")
    if header["typ"] != typ:
        raise Rejected("header")
    kid = header["kid"]
    if not isinstance(kid, str) or not _KID.fullmatch(kid):
        raise Rejected("header")
    return kid


def lookup_key(root: TrustRoot, kid: str, role: str, now: datetime) -> TrustedKey:
    key = root.keys.get(kid)
    if key is None:
        raise Rejected("unknown_kid")
    if key.role != role:
        raise Rejected("wrong_role")
    if key.status != "active":
        raise Rejected("revoked_key")
    if not key.usable_at(now):
        raise Rejected("key_window")
    return key


class Ed25519GrantVerifier:
    """Enforcer ``ProofVerifier`` for ``zts-grant-1`` proofs. Needs ``pip install zts[trust]``."""

    def __init__(
        self,
        trust: "TrustRoot | FileTrustRoot",
        *,
        clock: Callable[[], datetime] | None = None,
        on_reject: Callable[[str], None] | None = None,
        max_proof_bytes: int = MAX_PROOF_BYTES,
    ) -> None:
        self._trust = trust
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._on_reject = on_reject
        self._max = max_proof_bytes

    def _root(self) -> TrustRoot:
        return self._trust.current() if isinstance(self._trust, FileTrustRoot) else self._trust

    @property
    def verifier_id(self) -> str:
        try:
            return f"zts-ed25519/{self._root().digest[:12]}"
        except TrustRootError:
            return "zts-ed25519/unavailable"

    def verify_and_decode(self, proof: bytes) -> Any:
        enforcer = _enforcer_or_raise()
        try:
            return self._verify(proof, enforcer)
        except Rejected as exc:
            self._notify(exc.reason)
        except TrustRootError:
            self._notify("trust_root")
        except Exception:
            self._notify("error")
        raise enforcer.ProofVerificationError("the proof was not accepted")

    def _notify(self, reason: str) -> None:
        if self._on_reject is not None:
            try:
                self._on_reject(reason)
            except Exception:  # nosec B110
                pass  # an alerting hook must never turn a refusal into something else

    def _verify(self, proof: Any, enforcer: Any) -> Any:
        header_b64, claims_b64, sig_b64 = split_signed(proof, GRANT_TYPE.encode(), self._max)
        kid = read_header(header_b64, GRANT_TYPE)
        now = self._clock().astimezone(timezone.utc)
        key = lookup_key(self._root(), kid, ROLE_GRANT, now)
        signature = b64u_decode(sig_b64)
        if len(signature) != 64:
            raise Rejected("format")
        verify_signature(key.public_key, signature,
                         GRANT_TYPE.encode() + b"\x00" + header_b64 + b"." + claims_b64)
        # Only now, with the signature good, is the claims document parsed.
        doc = strict_json(b64u_decode(claims_b64))
        if set(doc) != _CLAIM_FIELDS:
            raise Rejected("claims")
        doc["issued_at"], doc["expires_at"] = parse_time(doc["issued_at"]), parse_time(doc["expires_at"])
        if doc["issuer_id"] != key.issuer_id:
            raise Rejected("issuer_mismatch")
        if not (key.not_before <= doc["issued_at"] and doc["expires_at"] <= key.not_after):
            raise Rejected("key_window")
        try:
            return enforcer.GrantClaims(**doc)
        except (TypeError, ValueError):
            raise Rejected("claims") from None


def _enforcer_or_raise() -> Any:
    try:
        return _enforcer()
    except Rejected:
        raise RuntimeError("Enforcer is required to verify grants") from None


__all__ = [
    "ALGORITHM", "Ed25519GrantVerifier", "FileTrustRoot", "GRANT_TYPE", "Rejected", "ROLE_GRANT",
    "ROLE_STATUS", "TrustRoot", "TrustRootError", "TrustedKey", "b64u_decode", "b64u_encode",
    "key_id", "lookup_key", "parse_time", "read_header", "split_signed", "strict_json",
    "verify_signature",
]
