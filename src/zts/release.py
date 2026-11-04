"""The G7 release boundary: a narrow adapter between ZTS and Enforcer.

Who does what, and nothing more:

  CNS       Supplies the identity contract: the subject digest and canonical
            representation of who the output is for. It authorizes nothing.
  Enforcer  Decides. It verifies an externally issued grant, checks that the
            grant is bound to this exact envelope, current, revalidated and
            unused, and consumes it. It owns all authorization policy.
  ZTS       Enforces. This module builds the envelope from the artifact about to
            leave, hands Enforcer the release as the guarded callback, and
            treats anything other than an ALLOW followed by a completed callback
            as "not released".

The release is the callback. Enforcer's ``execute`` invokes the callback only
after it allows the action, so the output is never reachable on a denial: there
is no separate "check, then release" step for a later edit to separate.

The envelope (Enforcer action envelope, schema v1) is built like this. An
issuer that wants to grant a release must compute the same values:

  subject_id         the CNS subject digest of the identity the output is for
  action             the requested operation (default ``zts.release``)
  target_type        ``zts.output``
  target_id          the authorization scope the output is released into
  request_id         the release identifier (unique per release attempt)
  parameters_sha256  SHA-256 of :func:`release_parameters_bytes`
  policy_version     the policy version configured on the gate
  evidence_sha256    SHA-256 of the UTF-8 bytes of the exact artifact
  schema_version     1

Every failure is a denial. Nothing here raises to the caller for a release
problem, and no failure path falls back to another way of releasing.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .cns.adapter import CNSDock
from .cns.artifacts import AuthorityProvenanceArtifact, EpistemicStatus
from .cns.errors import CNSContractError, CNSUnavailableError

#: The operation a ZTS output release requests unless the caller names another.
RELEASE_OPERATION = "zts.release"
#: Envelope target type for a released artifact.
TARGET_TYPE = "zts.output"
#: Version of the parameter encoding in :func:`release_parameters_bytes`.
PARAMETERS_VERSION = "zts-release/1"
#: The Enforcer envelope schema this adapter builds.
ENVELOPE_SCHEMA_VERSION = 1

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ENFORCER_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


class ReleaseReason:
    """Stable ZTS denial codes. Enforcer's own reason codes pass through unchanged."""

    NOT_CONFIGURED = "RELEASE_NOT_CONFIGURED"
    REQUEST_MISSING = "RELEASE_REQUEST_MISSING"
    RELEASE_ID_MISSING = "RELEASE_ID_MISSING"
    SCOPE_MISSING = "RELEASE_SCOPE_MISSING"
    CNS_UNAVAILABLE = "CNS_UNAVAILABLE"
    CNS_CONTRACT_INCOMPATIBLE = "CNS_CONTRACT_INCOMPATIBLE"
    CNS_IDENTITY_UNTRUSTED = "CNS_IDENTITY_UNTRUSTED"
    CNS_VERIFICATION_FAILED = "CNS_VERIFICATION_FAILED"
    ENFORCER_UNAVAILABLE = "ENFORCER_UNAVAILABLE"
    ENFORCER_INCOMPATIBLE = "ENFORCER_INCOMPATIBLE"
    ENFORCER_ERROR = "ENFORCER_ERROR"
    ENVELOPE_INVALID = "ENVELOPE_INVALID"
    PROOF_PROVIDER_ERROR = "PROOF_PROVIDER_ERROR"
    ARTIFACT_CHANGED = "ARTIFACT_CHANGED"
    LEDGER_UNAVAILABLE = "LEDGER_UNAVAILABLE"
    ACTION_FAILED = "RELEASE_ACTION_FAILED"
    SIEVE_BREACH = "SIEVE_BREACH"
    #: What Enforcer reports when it allows.
    ALLOWED = "VERIFIED_ACTION_BOUND_GRANT"


class EnforcerUnavailableError(RuntimeError):
    """Enforcer cannot be imported."""


class EnforcerContractError(RuntimeError):
    """The installed Enforcer is not a release this adapter was verified against."""


class ReleaseAbort(Exception):
    """Raised by the release action to stop before any effect, with a ZTS reason.

    Only raise it before the action has delivered anything. The adapter reports
    the release as not started; any other exception is reported as an
    unconfirmed release, because delivery cannot then be ruled out.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def enforcer_version_supported(version: Any) -> bool:
    """Enforcer is a 0.x prototype whose minor releases may break, so only 0.1.x is accepted."""
    if not isinstance(version, str):
        return False
    found = _ENFORCER_VERSION.fullmatch(version)
    return found is not None and (int(found[1]), int(found[2])) == (0, 1)


def _load_enforcer() -> Any:
    """Import Enforcer lazily and check its release. Anything else is a denial upstream."""
    try:
        import enforcer
    except ImportError as exc:  # includes ModuleNotFoundError and a blocked import
        raise EnforcerUnavailableError("Enforcer is unavailable") from exc
    version = getattr(enforcer, "__version__", None)
    if not enforcer_version_supported(version):
        raise EnforcerContractError(
            f"incompatible Enforcer version: expected 0.1.x, got {version}"
        )
    return enforcer


def artifact_sha256(payload: str) -> str:
    """The identity of the exact artifact: SHA-256 of its UTF-8 bytes."""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def release_parameters_bytes(*, canonical_representation: str, profile: str) -> bytes:
    """The canonical bytes whose SHA-256 is the envelope's ``parameters_sha256``.

    Binds the CNS canonical representation of the identity (not only its
    digest) and the ZTS profile the artifact cleared.
    """
    body = {
        "canonical_sha256": hashlib.sha256(canonical_representation.encode("utf-8")).hexdigest(),
        "parameters_version": PARAMETERS_VERSION,
        "profile": profile,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class ReleaseCandidate:
    """What an issuer needs in order to grant this exact release.

    Contains digests only. The artifact text never leaves ZTS through it.
    """

    release_id: str
    subject_digest: str
    artifact_sha256: str
    operation: str
    scope: str
    policy_version: str
    profile: str
    envelope_bytes: bytes
    envelope_sha256: str


@dataclass(frozen=True)
class ReleaseRequest:
    """The caller's claim about one release. Evidence to be checked, never authority.

    ``identity`` is the CNS ``IdentityContext`` and ``artifact`` its docked
    form (``CNSDock.to_zts_artifact``). The gate re-derives the artifact from
    the identity at release time and refuses a mismatch. Supply the grant as
    ``proof``, or as ``proof_provider``, a callable that receives the
    :class:`ReleaseCandidate` and returns the grant bytes. The provider is what
    makes it possible to obtain a grant for output that did not exist when the
    request was made. Exactly one of the two may be set.
    """

    identity: Any
    artifact: AuthorityProvenanceArtifact
    release_id: str
    scope: str
    proof: bytes | None = None
    proof_provider: Callable[[ReleaseCandidate], bytes | None] | None = None
    operation: str = RELEASE_OPERATION

    def __post_init__(self) -> None:
        if self.proof is not None and self.proof_provider is not None:
            raise ValueError("supply proof or proof_provider, not both")


@dataclass(frozen=True)
class ReleaseOutcome:
    """Result of one pass through the release boundary.

    ``released`` is True only when Enforcer allowed the action AND the guarded
    action ran to completion. ``authorized`` alone is not a release. Neither is
    evidence of anything else: this object is a record, not a credential.
    """

    released: bool
    authorized: bool
    action_started: bool
    reason_code: str
    release_id: str = ""
    subject_digest: str = ""
    operation: str = ""
    scope: str = ""
    policy_version: str = ""
    profile: str = ""
    decided_at: str = ""
    decision: dict[str, object] | None = None
    value: Any = field(default=None, repr=False)

    def evidence(self) -> dict[str, object]:
        """Ledger-safe evidence: identifiers, digests, codes and times. No artifact text."""
        return {
            "release_id": self.release_id,
            "subject_digest": self.subject_digest,
            "operation": self.operation,
            "scope": self.scope,
            "policy_version": self.policy_version,
            "profile": self.profile,
            "authorized": self.authorized,
            "released": self.released,
            "action_started": self.action_started,
            "reason_code": self.reason_code,
            "decided_at": self.decided_at,
            "decision": self.decision,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EnforcerReleaseGate:
    """Connects Enforcer's ``execute`` to the ZTS output-release boundary.

    ``enforcer`` is a configured ``enforcer.Enforcer``: its proof verifier,
    authorization revalidator and replay store are chosen and reviewed by the
    deployment, not here. Enforcer's defaults reject everything, so an
    unconfigured one denies every release.

    ``policy_version`` is the policy version this deployment releases under. A
    grant issued under another version is refused by Enforcer.
    """

    def __init__(
        self,
        enforcer: Any,
        *,
        policy_version: str,
        dock: CNSDock | None = None,
    ) -> None:
        if not callable(getattr(enforcer, "execute", None)):
            raise TypeError("enforcer must provide execute(envelope, proof, action)")
        if not isinstance(policy_version, str) or not policy_version.strip():
            raise ValueError("policy_version is required")
        self._enforcer = enforcer
        self._policy_version = policy_version
        self._dock = dock if dock is not None else CNSDock()

    @property
    def policy_version(self) -> str:
        return self._policy_version

    # ------------------------------------------------------------------ API

    def release(
        self,
        request: ReleaseRequest | None,
        payload: str,
        *,
        profile: str,
        action: Callable[[str], Any],
    ) -> ReleaseOutcome:
        """Run ``action(payload)`` if and only if Enforcer allows this exact release.

        Never raises for a release problem. ``action`` receives the exact text
        the envelope was built from, and runs inside Enforcer's guarded call,
        after its allow decision. Anything the action raises is reported, not
        propagated; ``ReleaseAbort`` means it stopped before any effect.
        """
        if not callable(action):
            raise TypeError("action must be callable")
        state = _State()
        try:
            return self._release(request, payload, profile, action, state)
        except _Deny as denial:
            return self._outcome(state, request, profile, denial.reason)
        except Exception as exc:  # fail closed: an unexpected error is a denial
            if isinstance(exc, ReleaseAbort):
                return self._outcome(state, request, profile, exc.reason)
            if state.started:
                return self._outcome(state, request, profile, ReleaseReason.ACTION_FAILED)
            return self._outcome(state, request, profile, ReleaseReason.ENFORCER_ERROR)

    # ------------------------------------------------------------ internals

    def _release(
        self,
        request: ReleaseRequest | None,
        payload: str,
        profile: str,
        action: Callable[[str], Any],
        state: "_State",
    ) -> ReleaseOutcome:
        if not isinstance(request, ReleaseRequest):
            raise _Deny(ReleaseReason.REQUEST_MISSING)
        if not isinstance(request.release_id, str) or not request.release_id.strip():
            raise _Deny(ReleaseReason.RELEASE_ID_MISSING)
        if not isinstance(request.scope, str) or not request.scope.strip():
            raise _Deny(ReleaseReason.SCOPE_MISSING)
        if not isinstance(payload, str):
            raise _Deny(ReleaseReason.ENVELOPE_INVALID)

        try:
            enforcer = _load_enforcer()
        except EnforcerUnavailableError:
            raise _Deny(ReleaseReason.ENFORCER_UNAVAILABLE) from None
        except EnforcerContractError:
            raise _Deny(ReleaseReason.ENFORCER_INCOMPATIBLE) from None

        # Identity first, and again inside the guarded call: the CNS binding is
        # re-checked as late as possible, and a non-grant failure here never
        # consumes a grant.
        self._check_identity(request)

        try:
            envelope = enforcer.ActionEnvelope(
                subject_id=request.artifact.subject_digest,
                action=request.operation,
                target_type=TARGET_TYPE,
                target_id=request.scope,
                request_id=request.release_id,
                parameters_sha256=hashlib.sha256(
                    release_parameters_bytes(
                        canonical_representation=request.artifact.canonical_representation,
                        profile=profile,
                    )
                ).hexdigest(),
                policy_version=self._policy_version,
                evidence_sha256=artifact_sha256(payload),
                schema_version=ENVELOPE_SCHEMA_VERSION,
            )
        except (ValueError, TypeError, AttributeError):
            raise _Deny(ReleaseReason.ENVELOPE_INVALID) from None

        state.candidate = ReleaseCandidate(
            release_id=request.release_id,
            subject_digest=request.artifact.subject_digest,
            artifact_sha256=envelope.evidence_sha256,
            operation=request.operation,
            scope=request.scope,
            policy_version=self._policy_version,
            profile=profile,
            envelope_bytes=envelope.canonical_bytes(),
            envelope_sha256=envelope.envelope_sha256,
        )

        proof = request.proof
        if request.proof_provider is not None:
            try:
                proof = request.proof_provider(state.candidate)
            except Exception:
                raise _Deny(ReleaseReason.PROOF_PROVIDER_ERROR) from None

        def guarded() -> Any:
            # Runs only after Enforcer allowed, and by then the grant is consumed.
            # Record that before anything can fail, so an abort still reports
            # "authorized, grant spent, nothing delivered" and not a plain denial.
            state.authorized = True
            # Last-moment rebinding to CNS.
            try:
                self._check_identity(request)
            except _Deny as denial:
                raise ReleaseAbort(denial.reason) from None
            state.started = True
            try:
                value = action(payload)
            except ReleaseAbort:
                # The action says it stopped before any effect, so nothing began.
                state.started = False
                raise
            state.completed = True
            return value

        outcome = self._enforcer.execute(envelope, proof, guarded)

        decision = getattr(outcome, "decision", None)
        allowed = (
            isinstance(outcome, enforcer.ExecutionOutcome)
            and isinstance(decision, enforcer.Decision)
            and decision.status is enforcer.DecisionStatus.ALLOW
        )
        state.decision = _decision_record(decision) if isinstance(decision, enforcer.Decision) else None
        if not allowed:
            reason = decision.reason_code if isinstance(decision, enforcer.Decision) else ""
            raise _Deny(reason or ReleaseReason.ENFORCER_ERROR)

        state.authorized = True
        # Released means our own callback finished, not that Enforcer said so.
        if outcome.action_invoked and state.completed:
            state.released = True
            state.value = outcome.value
            return self._outcome(state, request, profile, ReleaseReason.ALLOWED)
        raise _Deny(ReleaseReason.ENFORCER_ERROR)

    def _check_identity(self, request: ReleaseRequest) -> None:
        """Re-derive and compare the CNS binding. Raises _Deny; never authorizes."""
        try:
            self._dock.connect()
            self._dock.validate_contract()
        except CNSUnavailableError:
            raise _Deny(ReleaseReason.CNS_UNAVAILABLE) from None
        except CNSContractError:
            raise _Deny(ReleaseReason.CNS_CONTRACT_INCOMPATIBLE) from None
        except Exception:
            raise _Deny(ReleaseReason.CNS_UNAVAILABLE) from None

        artifact = request.artifact
        if not isinstance(artifact, AuthorityProvenanceArtifact):
            raise _Deny(ReleaseReason.CNS_IDENTITY_UNTRUSTED)
        try:
            fresh = self._dock.to_zts_artifact(request.identity)
        except Exception:
            raise _Deny(ReleaseReason.CNS_IDENTITY_UNTRUSTED) from None

        if (
            artifact.identity_status is not EpistemicStatus.KNOWN
            or artifact.integrity_status is not EpistemicStatus.KNOWN
            or artifact.compatibility_status != "compatible"
            or not isinstance(artifact.subject_digest, str)
            or _HEX64.fullmatch(artifact.subject_digest) is None
            or not isinstance(artifact.canonical_representation, str)
            or not artifact.canonical_representation
        ):
            raise _Deny(ReleaseReason.CNS_IDENTITY_UNTRUSTED)
        if artifact.cns_contract_version != fresh.cns_contract_version:
            raise _Deny(ReleaseReason.CNS_CONTRACT_INCOMPATIBLE)
        try:
            self._dock.verify_docked_artifact(request.identity, artifact)
        except Exception:
            raise _Deny(ReleaseReason.CNS_VERIFICATION_FAILED) from None

    def _outcome(
        self,
        state: "_State",
        request: ReleaseRequest | None,
        profile: str,
        reason: str,
    ) -> ReleaseOutcome:
        candidate = state.candidate
        known = request if isinstance(request, ReleaseRequest) else None
        artifact = getattr(known, "artifact", None)
        decided = ""
        if state.decision:
            decided = str(state.decision.get("evaluated_at", ""))
        return ReleaseOutcome(
            released=state.released,
            authorized=state.authorized,
            action_started=state.started,
            reason_code=reason,
            release_id=_text(getattr(known, "release_id", "")),
            subject_digest=candidate.subject_digest if candidate else _text(getattr(artifact, "subject_digest", "")),
            operation=_text(getattr(known, "operation", "")),
            scope=_text(getattr(known, "scope", "")),
            policy_version=self._policy_version,
            profile=profile,
            decided_at=decided or _now(),
            decision=state.decision,
            value=state.value if state.released else None,
        )


class _Deny(Exception):
    """Internal: carries a denial reason out of the checks."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class _State:
    candidate: ReleaseCandidate | None = None
    decision: dict[str, object] | None = None
    authorized: bool = False
    started: bool = False
    completed: bool = False
    released: bool = False
    value: Any = None


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _decision_record(decision: Any) -> dict[str, object]:
    """The parts of an Enforcer decision worth keeping. Drops the free-text message."""
    evaluated = getattr(decision, "evaluated_at", None)
    return {
        "status": getattr(getattr(decision, "status", None), "value", None),
        "reason_code": getattr(decision, "reason_code", None),
        "request_id": getattr(decision, "request_id", None),
        "evaluated_at": evaluated.isoformat() if isinstance(evaluated, datetime) else None,
        "proof_sha256": getattr(decision, "proof_sha256", None),
        "verifier_id": getattr(decision, "verifier_id", None),
        "revalidator_id": getattr(decision, "revalidator_id", None),
    }


__all__ = [
    "ENVELOPE_SCHEMA_VERSION",
    "EnforcerContractError",
    "EnforcerReleaseGate",
    "EnforcerUnavailableError",
    "PARAMETERS_VERSION",
    "RELEASE_OPERATION",
    "ReleaseAbort",
    "ReleaseCandidate",
    "ReleaseOutcome",
    "ReleaseReason",
    "ReleaseRequest",
    "TARGET_TYPE",
    "artifact_sha256",
    "enforcer_version_supported",
    "release_parameters_bytes",
]
