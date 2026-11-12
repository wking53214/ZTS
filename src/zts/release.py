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
import inspect
import json
import re
import threading
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
    DELIVERY_UNCONFIRMED = "DELIVERY_UNCONFIRMED"
    CANCELLED = "RELEASE_CANCELLED"
    SHUTTING_DOWN = "SHUTTING_DOWN"
    ENFORCER_TIMEOUT = "ENFORCER_TIMEOUT"
    PROOF_PROVIDER_TIMEOUT = "PROOF_PROVIDER_TIMEOUT"
    POLICY_CHANGED = "POLICY_CHANGED"
    INVARIANT_VIOLATED = "PRODUCTION_INVARIANT_VIOLATED"
    IDENTITY_NOT_AUTHENTICATED = "IDENTITY_NOT_AUTHENTICATED"
    #: The ledger anchor has fallen too far behind the ledger; no new release is attempted until it catches up.
    ANCHOR_BEHIND = "ANCHOR_BEHIND"
    #: The status source was asked again just before delivery and said the grant is now revoked.
    REVOKED_BEFORE_DELIVERY = "GRANT_REVOKED_BEFORE_DELIVERY"
    #: The status source was asked again just before delivery and did not give a usable current answer.
    STATUS_RECHECK_FAILED = "STATUS_RECHECK_FAILED"
    #: What Enforcer reports when it allows.
    ALLOWED = "VERIFIED_ACTION_BOUND_GRANT"


class ReleaseState:
    """The values of ``TowerResult.release_outcome``. Each is a different fact; none is a synonym.

    denied                      An authorization or precondition check said no. Nothing was spent.
    not_attempted               No attempt reached an authority: nothing configured, a sieve breach,
                                no release request, the audit write-ahead failed, or shutting down.
    failed_before_delivery      Enforcer allowed and the grant is spent, but ZTS stopped before the
                                delivery callback ran. Nothing was delivered. A new grant is needed.
    delivery_unknown            The callback began and did not finish, or it finished and the
                                receiving side did not confirm it. Delivery cannot be ruled out.
    delivered_audit_incomplete  Delivered, and the final audit record is not durably on disk (the
                                ledger is in memory, or its last write failed).
    delivered_unverified        Delivered and durably recorded, but no independent confirmation is
                                configured, so completion rests on the callback's own return.
    delivered                   Delivered, independently confirmed, and durably recorded.
    released_legacy             Released by an explicit legacy capstone. No Enforcer authorization.
    """

    DENIED = "denied"
    NOT_ATTEMPTED = "not_attempted"
    FAILED_BEFORE_DELIVERY = "failed_before_delivery"
    DELIVERY_UNKNOWN = "delivery_unknown"
    DELIVERED_AUDIT_INCOMPLETE = "delivered_audit_incomplete"
    DELIVERED_UNVERIFIED = "delivered_unverified"
    DELIVERED = "delivered"
    RELEASED_LEGACY = "released_legacy"

    DELIVERED_STATES = frozenset({DELIVERED, DELIVERED_UNVERIFIED, DELIVERED_AUDIT_INCOMPLETE})


#: Reasons that mean nothing was put in front of an authority, as opposed to an authority saying no.
NOT_ATTEMPTED_REASONS = frozenset({
    ReleaseReason.NOT_CONFIGURED,
    ReleaseReason.REQUEST_MISSING,
    ReleaseReason.SIEVE_BREACH,
    ReleaseReason.CANCELLED,
    ReleaseReason.SHUTTING_DOWN,
    ReleaseReason.ANCHOR_BEHIND,
})

#: Reasons after which Enforcer may or may not have consumed the grant.
GRANT_STATE_UNKNOWN_REASONS = frozenset({
    ReleaseReason.ENFORCER_TIMEOUT,
    "REPLAY_STORE_ERROR",
})


class CallTimeout(Exception):
    """A bounded call did not return in time. The call may still be running."""


def call_with_timeout(fn: Callable[..., Any], timeout: float | None, *args: Any) -> Any:
    """Run ``fn(*args)`` on a daemon thread and wait at most ``timeout`` seconds.

    A timeout abandons the wait, not the call: Python cannot stop a thread. Anything
    that could still act after the caller gave up must check its own abandoned flag
    (see the release gate). ``timeout=None`` calls ``fn`` inline.
    """
    if timeout is None:
        return fn(*args)
    box: dict[str, Any] = {}
    done = threading.Event()

    def runner() -> None:
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # carried back to the caller
            box["error"] = exc
        finally:
            done.set()

    threading.Thread(target=runner, daemon=True).start()
    if not done.wait(timeout):
        raise CallTimeout(f"no answer within {timeout}s")
    if "error" in box:
        raise box["error"]
    return box["value"]


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
    #: "spent" (Enforcer allowed), "unspent", or "unknown" (a timeout or replay-store error:
    #: the grant may or may not have been consumed, so treat it as spent).
    grant_state: str = "unspent"
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
            "grant_state": self.grant_state,
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

    ``timeout`` and ``identity_verifier`` are fixed once the gate is built, for the
    same reason the tower's release controls are: an ordinary assignment must not be
    able to remove a bound or a check from a running gate.
    """

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("timeout", "identity_verifier") and self.__dict__.get("_sealed"):
            raise AttributeError(f"{name} is fixed after construction; build a new gate")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        enforcer: Any,
        *,
        policy_version: str,
        dock: CNSDock | None = None,
        timeout: float | None = None,
        identity_verifier: Callable[[Any], bool] | None = None,
        reask_status: bool = False,
    ) -> None:
        if not callable(getattr(enforcer, "execute", None)):
            raise TypeError("enforcer must provide execute(envelope, proof, action)")
        if not isinstance(policy_version, str) or not policy_version.strip():
            raise ValueError("policy_version is required")
        self._enforcer = enforcer
        if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
            raise ValueError("timeout must be a positive number of seconds, or None")
        self._policy_version = policy_version
        # Enforcer 0.1.1 can hand us the ALLOW decision before the callback runs, so even a release that
        # aborts after the grant is spent keeps its decision record. 0.1.0 cannot; then the record is
        # simply absent on that path, as before.
        self._dock = dock if dock is not None else CNSDock()
        #: Bounds the proof provider and the whole Enforcer call (proof verification,
        #: status revalidation, replay consumption). None waits forever.
        self.timeout = timeout
        #: Optional. Called with the CNS IdentityContext, before Enforcer is asked and again just
        #: before delivery; only an exact True passes. ZTS binds an identity but does not
        #: authenticate one: this is where an operator who has an authenticator plugs it in.
        #: With none configured, the grant issuer is the only authentication, and it signs
        #: the subject digest into the grant.
        self.identity_verifier = identity_verifier
        if identity_verifier is not None and not callable(identity_verifier):
            raise TypeError("identity_verifier must be callable")
        self._reask: tuple[Any, Any] | None = None
        if reask_status:
            verifier = getattr(enforcer, "verifier", None)
            revalidator = getattr(enforcer, "revalidator", None)
            if not callable(getattr(verifier, "verify_and_decode", None)) or not callable(
                    getattr(revalidator, "revalidate", None)):
                raise ValueError(
                    "reask_status needs an Enforcer that exposes its verifier and status source (0.1.2 or later)")
            self._reask = (verifier, revalidator)
        self._sealed = True

    @property
    def policy_version(self) -> str:
        return self._policy_version

    @property
    def enforcer(self) -> Any:
        """The Enforcer this gate calls. Read-only; for deployment checks, not a way to call it."""
        return self._enforcer

    @property
    def reask_status(self) -> bool:
        """Whether the status source is asked a second time, immediately before delivery."""
        return self._reask is not None

    @property
    def dock(self) -> CNSDock:
        """The CNS dock this gate uses. Read-only; for deployment checks."""
        return self._dock

    # ------------------------------------------------------------------ API

    def release(
        self,
        request: ReleaseRequest | None,
        payload: str,
        *,
        profile: str,
        action: Callable[[str], Any],
        cancelled: Callable[[], bool] | None = None,
    ) -> ReleaseOutcome:
        """Run ``action(payload)`` if and only if Enforcer allows this exact release.

        ``cancelled`` is polled before Enforcer is asked and again, after its allow,
        immediately before the action. A cancelled release stops there: before any
        authority is consulted it spends nothing; after the allow the grant is spent
        and nothing was delivered.

        Never raises for a release problem. ``action`` receives the exact text
        the envelope was built from, and runs inside Enforcer's guarded call,
        after its allow decision. Anything the action raises is reported, not
        propagated; ``ReleaseAbort`` means it stopped before any effect.
        """
        if not callable(action):
            raise TypeError("action must be callable")
        state = _State()
        try:
            return self._release(request, payload, profile, action, state, cancelled)
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
        cancelled: Callable[[], bool] | None = None,
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

        if cancelled is not None and cancelled():
            raise _Deny(ReleaseReason.CANCELLED)

        proof = request.proof
        if request.proof_provider is not None:
            try:
                proof = call_with_timeout(request.proof_provider, self.timeout, state.candidate)
            except CallTimeout:
                raise _Deny(ReleaseReason.PROOF_PROVIDER_TIMEOUT) from None
            except Exception:
                raise _Deny(ReleaseReason.PROOF_PROVIDER_ERROR) from None
            if cancelled is not None and cancelled():
                raise _Deny(ReleaseReason.CANCELLED)

        def guarded() -> Any:
            # Runs only after Enforcer allowed, and by then the grant is consumed.
            # Record that before anything can fail, so an abort still reports
            # "authorized, grant spent, nothing delivered" and not a plain denial.
            with state.lock:
                state.authorized = True
                if state.abandoned:
                    # The caller stopped waiting (timeout). Never deliver after that.
                    raise ReleaseAbort(ReleaseReason.ENFORCER_TIMEOUT)
            if cancelled is not None and cancelled():
                raise ReleaseAbort(ReleaseReason.CANCELLED)
            # Last-moment rebinding to the policy this envelope was built under, and to CNS.
            if self._policy_version != state.candidate.policy_version:
                raise ReleaseAbort(ReleaseReason.POLICY_CHANGED)
            try:
                self._check_identity(request)
            except _Deny as denial:
                raise ReleaseAbort(denial.reason) from None
            # The last look at revocation, as close to delivery as the code allows. It runs before the
            # abandoned check below, so a re-ask that outlives the gate timeout cannot deliver.
            self._reask_status_now(enforcer, envelope, proof)
            with state.lock:
                if state.abandoned:
                    raise ReleaseAbort(ReleaseReason.ENFORCER_TIMEOUT)
                state.started = True
            try:
                value = action(payload)
            except ReleaseAbort:
                # The action says it stopped before any effect, so nothing began.
                state.started = False
                raise
            state.completed = True
            return value

        outcome = self._execute_bounded(envelope, proof, guarded, state)

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

    def _takes_on_allow(self) -> bool:
        """Whether the Enforcer in use accepts ``on_allow``. Asked per call, never cached."""
        try:
            return "on_allow" in inspect.signature(self._enforcer.execute).parameters
        except (TypeError, ValueError):
            return False

    def _execute_bounded(self, envelope: Any, proof: Any, guarded: Callable[[], Any], state: "_State") -> Any:
        """Call Enforcer, giving up after ``timeout``, without letting a late call deliver.

        A timed-out call keeps running on its thread. If it has not reached the
        delivery callback, ``abandoned`` is set under the same lock the callback
        takes, so the callback refuses when it arrives. If the callback is already
        running, delivery is in progress and is waited for rather than abandoned.
        """
        extra: dict[str, Any] = {}
        if self._takes_on_allow():
            extra["on_allow"] = lambda decision: setattr(state, "decision", _decision_record(decision))
        if self.timeout is None:
            return self._enforcer.execute(envelope, proof, guarded, **extra)
        box: dict[str, Any] = {}
        done = threading.Event()

        def runner() -> None:
            try:
                box["value"] = self._enforcer.execute(envelope, proof, guarded, **extra)
            except BaseException as exc:
                box["error"] = exc
            finally:
                done.set()

        threading.Thread(target=runner, daemon=True).start()
        if not done.wait(self.timeout):
            with state.lock:
                if not state.started:
                    state.abandoned = True
                    raise _Deny(ReleaseReason.ENFORCER_TIMEOUT)
            done.wait()  # delivery began; it cannot be taken back, so wait for it
        if "error" in box:
            raise box["error"]
        return box["value"]

    def _reask_status_now(self, enforcer: Any, envelope: Any, proof: Any) -> None:
        """Ask the status source again, just before delivery. Raises ReleaseAbort; never authorizes.

        Enforcer asked once, inside ``authorize``, before it spent the grant and before the audit write
        and the callback chain ran. A revocation that landed in between was invisible. This asks again
        with the same verifier and status source, so the window shrinks to this one round trip. It does
        not close it: a status can still change after this answer. The grant is already spent, so
        a refusal here is reported as authorized, spent, nothing delivered.

        Freshness of the answer is the status client's job (its challenge is echoed back); the
        timestamps are checked here only for shape, because the status source's clock is not ours.
        """
        if self._reask is None:
            return
        verifier, revalidator = self._reask
        try:
            claims = verifier.verify_and_decode(proof)
            status = revalidator.revalidate(envelope, claims)
        except Exception:
            raise ReleaseAbort(ReleaseReason.STATUS_RECHECK_FAILED) from None
        if not isinstance(status, enforcer.AuthorizationStatus):
            raise ReleaseAbort(ReleaseReason.STATUS_RECHECK_FAILED)
        if status.status is enforcer.AuthorizationStatusValue.REVOKED:
            raise ReleaseAbort(ReleaseReason.REVOKED_BEFORE_DELIVERY)
        stamps = (status.checked_at, status.valid_until)
        if (status.status is not enforcer.AuthorizationStatusValue.CURRENT
                or status.envelope_sha256 != envelope.envelope_sha256
                or status.policy_version != envelope.policy_version
                or not all(isinstance(t, datetime) and t.utcoffset() is not None for t in stamps)
                or status.valid_until < status.checked_at):
            raise ReleaseAbort(ReleaseReason.STATUS_RECHECK_FAILED)

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
        if self.identity_verifier is not None:
            try:
                ok = call_with_timeout(self.identity_verifier, self.timeout, request.identity) is True
            except Exception:  # includes CallTimeout: an authenticator that cannot answer is a no
                ok = False
            if not ok:
                raise _Deny(ReleaseReason.IDENTITY_NOT_AUTHENTICATED)

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
            grant_state=(
                "spent" if state.authorized
                else "unknown" if reason in GRANT_STATE_UNKNOWN_REASONS
                else "unspent"
            ),
            value=state.value if state.released else None,
        )


class _Deny(Exception):
    """Internal: carries a denial reason out of the checks."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class _State:
    lock: threading.Lock = field(default_factory=threading.Lock)
    abandoned: bool = False
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
    "CallTimeout",
    "NOT_ATTEMPTED_REASONS",
    "ReleaseCandidate",
    "ReleaseOutcome",
    "ReleaseState",
    "ReleaseReason",
    "ReleaseRequest",
    "TARGET_TYPE",
    "artifact_sha256",
    "call_with_timeout",
    "enforcer_version_supported",
    "release_parameters_bytes",
]
