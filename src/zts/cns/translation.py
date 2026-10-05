from __future__ import annotations

from typing import Any, Optional, Tuple

from .artifacts import AuthorityProvenanceArtifact, EpistemicStatus


ADAPTER_VERSION = "0.1.0"


def _value(source: Any, name: str, default: Any = None) -> Any:
    if source is None:
        return default
    return getattr(source, name, default)


def _tuple(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, tuple):
        return value
    return tuple(value)


def _enum_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    return getattr(value, "value", value)


def translate_identity(
    identity: Any,
    *,
    cns_contract_version: Optional[str] = None,
    compatibility_status: str = "compatible",
) -> AuthorityProvenanceArtifact:
    """
    Translate CNS identity/trust information without manufacturing authority.

    Identity and trust facts are translated when present.
    Authority provenance remains UNKNOWN because the CNS IdentityContext
    does not establish authority source, delegation, scope, or action.
    """
    if identity is None:
        return AuthorityProvenanceArtifact(
            tenant_id=None,
            subject_id=None,
            roles=(),
            identity_status=EpistemicStatus.UNKNOWN,
            trust_level=None,
            authentication_method=None,
            verified=False,
            signature_present=False,
            trust_status=EpistemicStatus.UNKNOWN,
            authority_source=None,
            authority_id=None,
            delegation_chain=(),
            delegation_status=EpistemicStatus.UNKNOWN,
            scope=(),
            scope_status=EpistemicStatus.UNKNOWN,
            claimed_action=None,
            authority_status=EpistemicStatus.UNKNOWN,
            provenance_ref=None,
            subject_digest=None,
            canonical_representation=None,
            integrity_status=EpistemicStatus.UNKNOWN,
            cns_contract_version=cns_contract_version,
            adapter_version=ADAPTER_VERSION,
            compatibility_status=compatibility_status,
            translation_notes=("identity unavailable",),
            overall_status=EpistemicStatus.UNKNOWN,
        )

    subject_id = _value(identity, "subject_id")
    signature = _value(identity, "signature", "")

    return AuthorityProvenanceArtifact(
        tenant_id=_value(identity, "tenant_id"),
        subject_id=subject_id,
        roles=_tuple(_value(identity, "roles", ())),
        identity_status=(
            EpistemicStatus.KNOWN
            if subject_id is not None
            else EpistemicStatus.UNKNOWN
        ),
        trust_level=_enum_value(_value(identity, "trust_level")),
        authentication_method=_value(identity, "authentication_method"),
        verified=bool(_value(identity, "verified", False)),
        signature_present=bool(signature),
        trust_status=(
            EpistemicStatus.UNKNOWN
            if _enum_value(_value(identity, "trust_level")) == "unknown"
            else (
                EpistemicStatus.KNOWN
                if (
                    _value(identity, "trust_level") is not None
                    or bool(_value(identity, "verified", False))
                    or bool(signature)
                )
                else EpistemicStatus.UNKNOWN
            )
        ),
        authority_source=None,
        authority_id=None,
        delegation_chain=(),
        delegation_status=EpistemicStatus.UNKNOWN,
        scope=(),
        scope_status=EpistemicStatus.UNKNOWN,
        claimed_action=None,
        authority_status=EpistemicStatus.UNKNOWN,
        provenance_ref=None,
        subject_digest=None,
        canonical_representation=None,
        integrity_status=EpistemicStatus.UNKNOWN,
        cns_contract_version=cns_contract_version,
        adapter_version=ADAPTER_VERSION,
        compatibility_status=compatibility_status,
        translation_notes=(
            "authority not inferred from identity or trust",
            "delegation not supplied by CNS IdentityContext",
            "scope not supplied by CNS IdentityContext",
        ),
        overall_status=(
            EpistemicStatus.INVALID
            if compatibility_status == "incompatible"
            else EpistemicStatus.UNKNOWN
        ),
    )


def make_unavailable_artifact(
    *,
    note: str = "CNS unavailable",
) -> AuthorityProvenanceArtifact:
    return AuthorityProvenanceArtifact(
        tenant_id=None,
        subject_id=None,
        roles=(),
        identity_status=EpistemicStatus.UNKNOWN,
        trust_level=None,
        authentication_method=None,
        verified=False,
        signature_present=False,
        trust_status=EpistemicStatus.UNKNOWN,
        authority_source=None,
        authority_id=None,
        delegation_chain=(),
        delegation_status=EpistemicStatus.UNKNOWN,
        scope=(),
        scope_status=EpistemicStatus.UNKNOWN,
        claimed_action=None,
        authority_status=EpistemicStatus.UNKNOWN,
        provenance_ref=None,
        subject_digest=None,
        canonical_representation=None,
        integrity_status=EpistemicStatus.UNKNOWN,
        cns_contract_version=None,
        adapter_version=ADAPTER_VERSION,
        compatibility_status="unavailable",
        translation_notes=(note,),
        overall_status=EpistemicStatus.UNKNOWN,
    )
