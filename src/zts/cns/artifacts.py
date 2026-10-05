from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


class EpistemicStatus(str, Enum):
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


@dataclass(frozen=True, slots=True)
class AuthorityProvenanceArtifact:
    # Identity
    tenant_id: Optional[str]
    subject_id: Optional[str]
    roles: Tuple[str, ...]
    identity_status: EpistemicStatus

    # Trust / Authentication
    trust_level: Optional[str]
    authentication_method: Optional[str]
    verified: bool
    signature_present: bool
    trust_status: EpistemicStatus

    # Authority
    authority_source: Optional[str]
    authority_id: Optional[str]
    delegation_chain: Tuple[str, ...]
    delegation_status: EpistemicStatus
    scope: Tuple[str, ...]
    scope_status: EpistemicStatus
    claimed_action: Optional[str]
    authority_status: EpistemicStatus

    # Provenance / Integrity
    provenance_ref: Optional[str]
    subject_digest: Optional[str]
    canonical_representation: Optional[str]
    integrity_status: EpistemicStatus

    # Contract metadata
    cns_contract_version: Optional[str]
    adapter_version: str
    compatibility_status: str
    translation_notes: Tuple[str, ...]

    # Overall
    overall_status: EpistemicStatus
