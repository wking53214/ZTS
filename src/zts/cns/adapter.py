from __future__ import annotations

from dataclasses import replace
from typing import Any

from .artifacts import AuthorityProvenanceArtifact, EpistemicStatus
from .errors import CNSContractError, CNSUnavailableError, CNSVerificationError
from .translation import ADAPTER_VERSION, make_unavailable_artifact, translate_identity


CNS_CONTRACT_VERSION = "1.4.0"


class CNSDock:
    """Narrow ZTS docking seam for the canonical CNS contract.

    The dock translates CNS contract data into ZTS's normalized artifact.
    It does not authorize, approve, or release anything.
    """

    def __init__(self) -> None:
        self._cns = None

    def connect(self) -> None:
        """Import the canonical CNS contract lazily."""
        try:
            import cns
            from cns.governance import IdentityContext
        except (ImportError, ModuleNotFoundError) as exc:
            raise CNSUnavailableError("canonical CNS is unavailable") from exc

        actual_version = getattr(cns, "__version__", None)
        if actual_version != CNS_CONTRACT_VERSION:
            raise CNSContractError(
                f"incompatible CNS version: expected "
                f"{CNS_CONTRACT_VERSION}, got {actual_version}"
            )

        self._cns = IdentityContext

    def validate_contract(self) -> bool:
        """Validate that the available CNS contract matches the frozen seam."""
        if self._cns is None:
            self.connect()

        identity_type = self._cns
        required = (
            "tenant_id",
            "subject_id",
            "roles",
            "trust_level",
            "authentication_method",
            "verified",
            "signature",
        )

        missing = tuple(
            name
            for name in required
            if not hasattr(identity_type, "__dataclass_fields__")
            or name not in identity_type.__dataclass_fields__
        )

        if missing:
            raise CNSContractError(
                f"incompatible CNS IdentityContext; missing fields: {missing}"
            )

        return True

    def canonicalize(self, identity: Any) -> str:
        """Return a deterministic representation of the identity fields."""
        self.validate_contract()

        fields = (
            identity.tenant_id,
            identity.subject_id,
            tuple(identity.roles),
            getattr(identity.trust_level, "value", identity.trust_level),
            identity.authentication_method,
            bool(identity.verified),
            identity.signature,
        )

        return repr(fields)

    def subject_digest(self, identity: Any) -> str:
        """Return a deterministic SHA-256 digest of the canonical identity."""
        import hashlib

        canonical = self.canonicalize(identity)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_zts_artifact(
        self,
        identity: Any,
        *,
        compatibility_status: str = "compatible",
    ) -> AuthorityProvenanceArtifact:
        """Translate a CNS identity into the normalized ZTS artifact."""
        self.validate_contract()

        if not isinstance(identity, self._cns):
            raise CNSContractError(
                "identity is not a canonical CNS IdentityContext"
            )

        artifact = translate_identity(
            identity,
            cns_contract_version=CNS_CONTRACT_VERSION,
            compatibility_status=compatibility_status,
        )

        digest = self.subject_digest(identity)

        return replace(
            artifact,
            subject_digest=digest,
            canonical_representation=self.canonicalize(identity),
            integrity_status=EpistemicStatus.KNOWN,
        )

    def verify_docked_artifact(
        self,
        identity: Any,
        artifact: AuthorityProvenanceArtifact,
    ) -> bool:
        """Verify representation and subject digest without authorizing."""
        expected_digest = self.subject_digest(identity)
        expected_canonical = self.canonicalize(identity)

        if artifact.subject_digest != expected_digest:
            raise CNSVerificationError("subject digest mismatch")

        if artifact.canonical_representation != expected_canonical:
            raise CNSVerificationError("canonical representation mismatch")

        return True

    def unavailable(self) -> AuthorityProvenanceArtifact:
        """Return the fail-closed non-authorizing CNS-unavailable artifact."""
        return make_unavailable_artifact()


__all__ = [
    "ADAPTER_VERSION",
    "CNS_CONTRACT_VERSION",
    "CNSDock",
]
