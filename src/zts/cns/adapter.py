from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from .artifacts import AuthorityProvenanceArtifact, EpistemicStatus
from .errors import CNSContractError, CNSUnavailableError, CNSVerificationError
from .translation import ADAPTER_VERSION, make_unavailable_artifact, translate_identity


# The CNS release this seam was frozen against. It is the oldest release the
# dock accepts, not the only one. CNS adds a field only with a default in a
# minor release and removes or renames one only in a new major release (the
# VERSIONING note in cns/__init__.py), and validate_contract checks the
# IdentityContext fields themselves. So any release of the same major version
# at or above this one is accepted, and a new major version is refused until
# ZTS moves to it deliberately.
CNS_CONTRACT_VERSION = "1.4.0"


def cns_version_supported(version: Any) -> bool:
    """Whether a CNS ``__version__`` is one this dock accepts.

    Only a plain ``X.Y.Z`` string is read; anything else is refused.
    """
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        return False
    found = tuple(int(part) for part in version.split("."))
    floor = tuple(int(part) for part in CNS_CONTRACT_VERSION.split("."))
    return found[0] == floor[0] and found >= floor


class CNSDock:
    """Narrow ZTS docking seam for the canonical CNS contract.

    The dock translates CNS contract data into ZTS's normalized artifact.
    It does not authorize, approve, or release anything.
    """

    def __init__(self) -> None:
        self._cns = None
        self._cns_digest = None
        self._cns_version = None

    def connect(self) -> None:
        """Import the canonical CNS contract lazily."""
        try:
            import cns
            from cns.gate import subject_digest
            from cns.governance import IdentityContext
        except (ImportError, ModuleNotFoundError) as exc:
            raise CNSUnavailableError("canonical CNS is unavailable") from exc

        actual_version = getattr(cns, "__version__", None)
        if not cns_version_supported(actual_version):
            raise CNSContractError(
                f"incompatible CNS version: expected "
                f"{CNS_CONTRACT_VERSION} or a later "
                f"{CNS_CONTRACT_VERSION.split('.')[0]}.x release, got {actual_version}"
            )

        self._cns = IdentityContext
        self._cns_digest = subject_digest
        self._cns_version = actual_version

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

    def identity_content(self, identity: Any) -> dict:
        """Return the identity fields as plain data, the content a CNS verdict binds to."""
        self.validate_contract()

        return {
            "tenant_id": identity.tenant_id,
            "subject_id": identity.subject_id,
            "roles": list(identity.roles),
            "trust_level": getattr(identity.trust_level, "value", identity.trust_level),
            "authentication_method": identity.authentication_method,
            "verified": bool(identity.verified),
            "signature": identity.signature,
        }

    def subject_digest(self, identity: Any) -> str:
        """Return CNS's own digest (``cns.gate.subject_digest``) of the identity.

        This is the value a CNS ``GateResult.subject_digest`` is compared with,
        so it must be computed the way CNS computes it, not ZTS's own way.
        """
        return self._cns_digest(self.identity_content(identity))

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
            cns_contract_version=self._cns_version,
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
    "cns_version_supported",
]
