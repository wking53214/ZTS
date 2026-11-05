"""Deterministic Integrity Tower: the full vertical assembly.

Stack order, bottom to top:

    LC   Logic Cornerstone      ingestion normalization
    ZTS  Zero Trust Sieve       G1-G6, fail-fast
    KG   Kinetic Governor       temporal budget, concurrent with the sieve
    TAP  Architect's Protocol   G7 capstone, out-of-band release

Two execution paths:

  `enforce()` is synchronous, runs the sieve once, and is the path you want for
  filtering text you already have. No governor, no event loop.

  `run()` is async, adds the governor and the rewrite loop, and is the path for
  wrapping a generator: it filters, and when the filter finds a blocking
  violation it asks the generator to try again with the specific constraints
  that failed.

The governor runs concurrently with the sieve rather than before it. Both
paths exist in the archive; the concurrent one is correct, because the pacing
delay and the regex work are independent and serializing them pays for both.

Release. Both paths end in `_finish` -> `_decide`, the only place output leaves
the tower. There are three configurations, and the default is the safe one:

  * `release_gate=EnforcerReleaseGate(...)` is the production path. Output is
    released only inside Enforcer's guarded call, after an ALLOW for this exact
    artifact, subject, operation, scope and release id (see zts.release).
  * `capstone=ArchitectsProtocol(...)` is the legacy path, kept for development,
    tests and existing callers. It must be passed explicitly. AUTO performs no
    authorization at all.
  * Neither: everything is held. There is no implicit grant.

`require_enforcer=True` makes the second path impossible, so a production
deployment cannot be misconfigured into a development mode.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from .capstone import ArchitectsProtocol
from .dashboard import TelemetryDashboard
from .gates import Gate
from .governor import KineticGovernor
from .ledger import ValLedger, key_id_for, load_or_create_ledger_key, signature_block
from .normalizer import StructureNormalizer, tidy
from .ops import (
    FAIL,
    ProductionConfigError,
    ReadinessReport,
    ReleaseMetrics,
    audit_event,
    check_configuration,
    check_runtime,
    log_event,
)
from .profiles import Profile
from .profiles import get as get_profile
from .release import (
    NOT_ATTEMPTED_REASONS,
    EnforcerReleaseGate,
    ReleaseAbort,
    ReleaseOutcome,
    ReleaseReason,
    ReleaseRequest,
    ReleaseState,
    artifact_sha256,
    call_with_timeout,
)
from .result import SieveResult, TowerResult, Verdict
from .sieve import ZeroTrustSieve

Generator = Callable[[str], Awaitable[str]]
#: Receives the released text and its signature block. Runs only on a release.
ReleaseSink = Callable[[str, dict[str, str]], None]
#: Asks the RECEIVING side whether it holds this artifact: (release_id, artifact_sha256) -> bool.
#: It must not be answered from the sink's own return value; that is the thing being checked.
DeliveryConfirmer = Callable[[str, str], bool]

#: Rewrite instruction emitted per gate when asking a generator to retry.
CONSTRAINT_TEXT: dict[Gate, str] = {
    Gate.G6: "Remove first-person and collective pronouns. State findings without a speaker.",
    Gate.G3: "Remove hedging and filler. Every claim must resolve to something checkable.",
    Gate.G1: "Do not restate, negate, or override the governing instructions.",
    Gate.G5: "Remove flattery, agreement openers, and assistant-voice phrasing.",
    Gate.G2: "Remove affect vocabulary. Report what is observed, not what is felt or believed.",
    Gate.G4: "Rewrite with different structure and phrasing. The previous attempt repeated itself.",
}


class TowerClosedError(RuntimeError):
    """The tower has been closed and takes no new work. Nothing was filtered or released."""


class LogicCornerstone:
    """Ingestion perimeter.

    Normalizes what arrives before any gate sees it: unicode whitespace, stray
    control characters, and the punctuation rule. Cheap, unconditional, and
    idempotent. It is the only component in the stack that the archive
    described as tied to hardware, which it was not and is not.
    """

    def __init__(self, profile: str = "default") -> None:
        self.normalizer = StructureNormalizer(profile)

    def intake(self, payload: str) -> str:
        cleaned = "".join(
            ch for ch in payload if ch == "\n" or ch == "\t" or ch >= " "
        )
        return tidy(cleaned)


#: Attributes that decide whether and how output leaves. Fixed once the tower is built.
_RELEASE_CONTROLS = frozenset({
    "tap", "release_gate", "release_sink", "require_enforcer",
    "delivery_confirmer", "confirm_timeout", "ledger", "profile", "production", "metrics",
    # The content sieve, its time budget, the logic cornerstone and the release signature key decide what is
    # released and how it is signed; the seal flag itself must not be clearable by an ordinary assignment.
    "zts", "kg", "lc", "_key", "_key_id", "_sealed",
})


class DeterministicIntegrityTower:
    """LC -> ZTS -> KG -> TAP.

    The attributes that control release are read-only after construction. That stops
    an ordinary assignment (``tower.release_gate = None``, ``tower.tap = AUTO``) from
    turning a production tower into a development one. It is not a sandbox: code in
    the same process can still bypass ``__setattr__``, and a process that can run
    arbitrary code can call the delivery callback directly. Containment against that
    is process isolation, which a library cannot provide. See docs/RELEASE_BOUNDARY.md.
    """

    def __setattr__(self, name: str, value: object) -> None:
        if name in _RELEASE_CONTROLS and self.__dict__.get("_sealed"):
            raise AttributeError(f"{name} is fixed after construction; build a new tower")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        profile: str | Profile = "default",
        capstone: ArchitectsProtocol | None = None,
        governor: KineticGovernor | None = None,
        hmac_key: bytes | None = None,
        dashboard: TelemetryDashboard | None = None,
        ledger_key_file: str | Path | None = None,
        persist_ledger_key: bool = True,
        release_gate: EnforcerReleaseGate | None = None,
        require_enforcer: bool = False,
        release_sink: ReleaseSink | None = None,
        delivery_confirmer: DeliveryConfirmer | None = None,
        confirm_timeout: float | None = 10.0,
        ledger: ValLedger | None = None,
        production: bool = False,
    ) -> None:
        # production=True means "refuse to start unless this is configured as production".
        # It implies require_enforcer, and the checks in zts.ops.check_configuration must
        # not FAIL. Checks that can only be UNKNOWN (custom adapters) do not block.
        require_enforcer = require_enforcer or production
        if release_gate is not None and capstone is not None:
            raise ValueError(
                "configure one release authority: release_gate (Enforcer) or capstone (legacy), not both"
            )
        if require_enforcer and capstone is not None:
            raise ValueError("require_enforcer forbids a legacy capstone")
        if require_enforcer and release_gate is None:
            raise ValueError("require_enforcer needs a release_gate")
        self.profile = get_profile(profile) if isinstance(profile, str) else profile
        self.lc = LogicCornerstone(self.profile.name)
        self.zts = ZeroTrustSieve(self.profile)
        self.kg = governor or KineticGovernor()
        #: Legacy capstone, or None. There is no default: None holds everything.
        self.tap = capstone
        #: The production release authority, or None.
        self.release_gate = release_gate
        self.require_enforcer = require_enforcer
        #: Optional delivery hook. Called only after a release is authorized, inside
        #: the guarded call, so a denied release never reaches it.
        self.release_sink = release_sink
        #: Optional independent check that the receiving side holds the artifact.
        #: With one, success needs its True. Without one the best state is delivered_unverified.
        self.delivery_confirmer = delivery_confirmer
        self.confirm_timeout = confirm_timeout
        self._closing = False
        self._key_supplied = hmac_key is not None
        self.production = production
        #: Security-relevant counters. Records only; never changes a decision.
        self.metrics = ReleaseMetrics()
        self._sealed = False
        self._inflight = 0
        self._idle = threading.Condition()
        self._key = hmac_key or secrets.token_bytes(32)
        self._key_id = key_id_for(self._key)
        # By default the ledger key is read from (or created in) an owner-only file,
        # so fingerprints can be checked after a restart. persist_ledger_key=False
        # gives a random key for this run only. Either way it is separate from the
        # release-checksum key.
        if persist_ledger_key:
            ledger_key = load_or_create_ledger_key(ledger_key_file)
        else:
            ledger_key = secrets.token_bytes(32)
        self.ledger = ledger if ledger is not None else ValLedger(key=ledger_key)
        #: Optional outcome counter. Records only; never changes a decision.
        self.dashboard = dashboard
        self._sealed = True
        if production:
            failed = [c for c in check_configuration(self) if c.status == FAIL]
            if failed:
                raise ProductionConfigError(
                    "not configured as a production tower: "
                    + "; ".join(f"{c.name}: {c.detail}" for c in failed)
                )

    # --- synchronous path ---------------------------------------------------

    def enforce(
        self,
        payload: str,
        signature: str | None = None,
        *,
        release: ReleaseRequest | None = None,
    ) -> TowerResult:
        """Filter one payload. No generator, no event loop, no pacing.

        `release` carries the identity and release id for the Enforcer path.
        `signature` is the legacy HANDSHAKE token and means nothing to Enforcer.
        """
        if self._closing:
            raise TowerClosedError("the tower is closed")
        started = time.perf_counter_ns()
        held = self._hold_if_anchor_behind(started)
        if held is not None:
            return held

        intake = self.lc.intake(payload)
        self.ledger.log("LC", "PASS", "ingestion normalized", intake)

        # No history: a single pass has nothing to oscillate against.
        # Submitting the same text twice is a legitimate request, not a loop.
        result = self.zts.run(intake)
        self._log_sieve(result)

        return self._finish(
            result, signature, attempts=1, budget=0.0, started=started, release=release
        )

    # --- asynchronous path --------------------------------------------------

    async def run(
        self,
        prompt: str,
        generator: Generator,
        signature: str | None = None,
        *,
        release: ReleaseRequest | None = None,
    ) -> TowerResult:
        """Generate, filter, and retry with targeted constraints.

        Each retry carries only the constraints the last attempt actually
        violated. The archived loop accumulated the full prompt plus every
        prior instruction on every attempt, which grew the context on each pass
        and made later attempts more expensive than earlier ones for no gain.
        """
        if self._closing:
            raise TowerClosedError("the tower is closed")
        started = time.perf_counter_ns()
        # Off the event loop: when the anchor is behind this may wait for the TSA (bounded by its timeout).
        held = await asyncio.to_thread(self._hold_if_anchor_behind, started)
        if held is not None:
            return held
        working_prompt = prompt
        result: SieveResult | None = None
        budget_seconds = 0.0
        attempts = 0
        # Oscillation is a property of one rewrite loop, so history is scoped
        # to this call. A tower-lifetime history would flag a caller who
        # legitimately submits the same prompt twice.
        history: list[str] = []

        for attempt in range(1, self.profile.max_retries + 1):
            attempts = attempt
            output = await generator(working_prompt)
            intake = self.lc.intake(output)
            self.ledger.log("LC", "PASS", f"attempt {attempt} intake", intake)

            # Thread Alpha (sieve) and Thread Beta (governor) run concurrently.
            sieve_task = asyncio.create_task(asyncio.to_thread(
                self.zts.run, intake, list(history)
            ))
            budget_task = asyncio.create_task(self.kg.pace(intake))

            result, budget = await asyncio.gather(sieve_task, budget_task)
            budget_seconds = budget.seconds
            history.append(result.payload_out)
            self._log_sieve(result)

            if result.verdict is not Verdict.BREACH:
                break

            blocking = sorted(
                {
                    f.gate
                    for f in result.findings
                    if f.verdict is Verdict.BREACH
                },
                key=lambda g: g.value.gate_id,
            )
            if not blocking:
                break

            working_prompt = self._rewrite_prompt(prompt, result.payload_out, blocking)

        assert result is not None
        # One release attempt, for the final result only. A retry that produced
        # different text produced a different artifact, and a grant is bound to
        # exactly one.
        #
        # The release path makes blocking calls (grant issuer, status source, replay
        # store, ledger fsync, delivery, confirmation), so it runs on a worker thread
        # and the event loop stays free. Cancellation is cooperative: it sets a flag
        # that the release checks before it asks an authority and again, after the
        # allow, immediately before delivery. A release that has already begun
        # delivering cannot be stopped, so it is waited for and its outcome is in the
        # ledger. Either way the caller sees CancelledError, which means "outcome not
        # returned", never "nothing happened": consult the ledger before retrying.
        cancelled = threading.Event()
        call = asyncio.ensure_future(
            asyncio.to_thread(
                self._finish,
                result,
                signature,
                attempts,
                budget_seconds,
                started,
                release,
                cancelled.is_set,
            )
        )
        try:
            return await asyncio.shield(call)
        except asyncio.CancelledError:
            cancelled.set()
            await asyncio.wait({call})
            if not call.cancelled():
                call.exception()  # mark retrieved; the ledger holds what happened
            raise

    # --- internals ----------------------------------------------------------

    def _rewrite_prompt(
        self, original: str, last_output: str, gates: list[Gate]
    ) -> str:
        rules = "\n".join(f"- {CONSTRAINT_TEXT[g]}" for g in gates)
        return (
            f"Original task:\n{original}\n\n"
            f"Previous response:\n{last_output}\n\n"
            f"Rewrite requirements:\n{rules}\n"
        )

    def _log_sieve(self, result: SieveResult) -> None:
        for gate_result in result.gates:
            # The gate, verdict and number of findings. Never the matched text: the
            # ledger holds keyed fingerprints of payloads, and a matched fragment is
            # payload text.
            count = len(gate_result.findings)
            self.ledger.log(
                gate_result.gate.value.gate_id,
                gate_result.verdict.value.upper(),
                f"{gate_result.gate.value.code}: {count} finding(s)" if count else gate_result.gate.value.code,
                gate_result.payload_out,
                elapsed_ns=gate_result.elapsed_ns,
            )
        self.ledger.log(
            "ZTS",
            result.verdict.value.upper(),
            f"score={result.score}",
            result.payload_out,
            score=result.score,
        )

    def _finish(
        self,
        result: SieveResult,
        signature: str | None,
        attempts: int,
        budget: float,
        started: int,
        release: ReleaseRequest | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> TowerResult:
        """Decide release, then record the outcome if a dashboard is attached."""
        with self._idle:
            closing = self._closing
            if not closing:
                self._inflight += 1
        if closing:
            return self._held(
                result, budget, attempts, started, reason=ReleaseReason.SHUTTING_DOWN
            )
        try:
            outcome = self._decide(result, signature, attempts, budget, started, release, cancelled)
            if self.dashboard is not None:
                self.dashboard.record(outcome)
            self._observe(outcome)
            return outcome
        finally:
            with self._idle:
                self._inflight -= 1
                self._idle.notify_all()

    def _observe(self, outcome: TowerResult) -> None:
        """Count and log the decision. A failure here must never alter or hide it."""
        try:
            self.metrics.record(outcome.release_outcome, outcome.reason_code)
            policy = self.release_gate.policy_version if self.release_gate is not None else ""
            log_event(audit_event(outcome, policy_version=policy))
        except Exception:
            # Observability must never break or alter a release, but it must not fail silently
            # either: the failure is counted and shows up in metrics and health().
            self.metrics.observer_failed()

    def readiness(self) -> ReadinessReport:
        """Every configuration and runtime check, each PASS, FAIL or UNKNOWN. See zts.ops."""
        return ReadinessReport(check_configuration(self) + check_runtime(self))

    def health(self) -> dict[str, object]:
        """Live status for a health endpoint: ok, degraded (a runtime check failed) or closed."""
        checks = check_runtime(self)
        failed = [c.name for c in checks if c.status == FAIL]
        status = "closed" if self._closing else ("degraded" if failed else "ok")
        return {
            "status": status,
            "failed": failed,
            "inflight": self._inflight,
            "metrics": self.metrics.snapshot(),
        }

    def close(self, timeout: float | None = 30.0) -> bool:
        """Stop accepting releases, wait for those in flight, then close the ledger files.

        New calls to enforce() and run() raise TowerClosedError; a call that was already
        past that check when shutdown began returns ``not_attempted`` / SHUTTING_DOWN
        instead of releasing. Returns True
        when nothing was still running at the deadline. Safe to call twice. A release
        that is mid-delivery is waited for, not interrupted.
        """
        with self._idle:
            self._closing = True
            drained = self._idle.wait_for(lambda: self._inflight == 0, timeout)
        if drained:
            for part in (getattr(self.ledger, "_store", None), getattr(self.ledger, "_anchor", None)):
                closer = getattr(part, "close", None)
                if callable(closer):
                    closer()
        return drained

    @property
    def closing(self) -> bool:
        return self._closing

    @property
    def inflight(self) -> int:
        return self._inflight

    def _hold_if_anchor_behind(self, started: int) -> TowerResult | None:
        """Admission check, made before the tower writes anything.

        Entries that no timestamp covers can be removed without anyone noticing. Past the anchor's bound, a
        new release is not started: nothing is filtered, no entry is written and no grant is spent, so the
        uncovered tail cannot grow while the hold is open. A release already admitted runs to its end.
        The sieve did not run, so the result carries an empty sieve whose verdict is BREACH: ``passed`` stays
        False and nothing downstream can read it as content that was cleared.
        """
        if self.release_gate is None or self.ledger.anchor_behind() is None:
            return None
        empty = SieveResult(payload_in="", payload_out="", profile=self.profile.name, verdict=Verdict.BREACH)
        outcome = self._held(empty, 0.0, 0, started, outcome=ReleaseState.NOT_ATTEMPTED,
                             reason=ReleaseReason.ANCHOR_BEHIND)
        self._observe(outcome)
        return outcome

    def _held(
        self,
        result: SieveResult,
        budget: float,
        attempts: int,
        started: int,
        *,
        outcome: str = ReleaseState.NOT_ATTEMPTED,
        reason: str = "",
        release_id: str = "",
        authorization: dict[str, object] | None = None,
    ) -> TowerResult:
        """A result that carries no output. The only way the tower withholds."""
        return TowerResult(
            sieve=result.redacted(),
            output="",
            released=False,
            temporal_budget=budget,
            attempts=attempts,
            elapsed_ns=time.perf_counter_ns() - started,
            release_outcome=outcome,
            reason_code=reason,
            release_id=release_id,
            authorization=authorization or {},
        )

    def _decide(
        self,
        result: SieveResult,
        signature: str | None,
        attempts: int,
        budget: float,
        started: int,
        release: ReleaseRequest | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> TowerResult:
        if result.verdict is Verdict.BREACH:
            self.ledger.log("TAP", "HELD", "sieve breach: release withheld", result.payload_out)
            return self._held(
                result, budget, attempts, started, reason=ReleaseReason.SIEVE_BREACH
            )

        if self.require_enforcer and (self.release_gate is None or self.tap is not None):
            # Defense in depth for a tower whose controls were forced past __setattr__:
            # a production tower never falls back to a development release path.
            self.ledger.log(
                "TAP", "HELD", "production invariant violated: release withheld", result.payload_out,
                reason_code=ReleaseReason.INVARIANT_VIOLATED,
            )
            return self._held(
                result, budget, attempts, started, outcome=ReleaseState.DENIED,
                reason=ReleaseReason.INVARIANT_VIOLATED,
            )

        if self.release_gate is not None:
            return self._decide_enforced(result, attempts, budget, started, release, cancelled)

        if self.tap is None:
            self.ledger.log(
                "TAP",
                "HELD",
                "no release authority configured: release withheld",
                result.payload_out,
                reason_code=ReleaseReason.NOT_CONFIGURED,
            )
            return self._held(
                result, budget, attempts, started, reason=ReleaseReason.NOT_CONFIGURED
            )

        return self._decide_legacy(result, signature, attempts, budget, started)

    def _decide_legacy(
        self,
        result: SieveResult,
        signature: str | None,
        attempts: int,
        budget: float,
        started: int,
    ) -> TowerResult:
        """The capstone path, unchanged in what it decides. Explicit opt-in only."""
        if self.tap is None:  # not an assert: asserts vanish under python -O
            return self._held(
                result, budget, attempts, started, reason=ReleaseReason.NOT_CONFIGURED
            )
        decision = self.tap.authorize(result.payload_out, signature)
        self.ledger.log(
            "TAP",
            "RELEASED" if decision.released else "HELD",
            decision.reason,
            result.payload_out,
            release_authority=f"legacy-capstone:{decision.mode.value}",
            enforcer_authorized=False,
        )

        if not decision.released:
            return self._held(result, budget, attempts, started, outcome=ReleaseState.DENIED)

        signature_value = signature_block(result.payload_out, self._key, self._key_id)
        if self.release_sink is not None:
            try:
                self.release_sink(result.payload_out, signature_value)
            except Exception:
                self.ledger.log(
                    "TAP",
                    "UNCONFIRMED",
                    "release sink failed after the capstone approved",
                    result.payload_out,
                    reason_code=ReleaseReason.ACTION_FAILED,
                )
                return self._held(
                    result,
                    budget,
                    attempts,
                    started,
                    outcome=ReleaseState.DELIVERY_UNKNOWN,
                    reason=ReleaseReason.ACTION_FAILED,
                )
        return TowerResult(
            sieve=result,
            output=result.payload_out,
            released=True,
            temporal_budget=budget,
            checksum=signature_value["value"],
            signature=signature_value,
            attempts=attempts,
            elapsed_ns=time.perf_counter_ns() - started,
            release_outcome=ReleaseState.RELEASED_LEGACY,
            authorization={
                "kind": "legacy-capstone",
                "mode": decision.mode.value,
                "enforcer_authorized": False,
            },
        )

    def _decide_enforced(
        self,
        result: SieveResult,
        attempts: int,
        budget: float,
        started: int,
        release: ReleaseRequest | None,
        cancelled: Callable[[], bool] | None = None,
    ) -> TowerResult:
        """Release through Enforcer. The output is reachable only inside its guarded call."""
        if self.release_gate is None:  # not an assert: asserts vanish under python -O
            return self._held(
                result, budget, attempts, started, reason=ReleaseReason.NOT_CONFIGURED
            )
        payload = result.payload_out
        release_id = getattr(release, "release_id", "")
        release_id = release_id if isinstance(release_id, str) else ""

        if cancelled is not None and cancelled():
            return self._held(
                result, budget, attempts, started,
                reason=ReleaseReason.CANCELLED, release_id=release_id,
            )

        # Write-ahead: record the attempt before Enforcer can consume a grant.
        # If the ledger cannot take it, nothing is released and no grant is spent.
        try:
            self.ledger.log(
                "TAP",
                "ATTEMPT",
                "release attempt",
                payload,
                release_id=release_id,
                policy_version=self.release_gate.policy_version,
                profile=self.profile.name,
            )
        except Exception:
            return self._held(
                result,
                budget,
                attempts,
                started,
                outcome=ReleaseState.NOT_ATTEMPTED,
                reason=ReleaseReason.LEDGER_UNAVAILABLE,
                release_id=release_id,
            )

        def deliver(snapshot: str) -> dict[str, str]:
            # Inside the guarded call, after ALLOW. Nothing has left yet.
            if result.payload_out != snapshot:
                raise ReleaseAbort(ReleaseReason.ARTIFACT_CHANGED)
            try:
                self.ledger.log(
                    "TAP", "RELEASING", "authorized: delivering", snapshot, release_id=release_id
                )
            except Exception:
                raise ReleaseAbort(ReleaseReason.LEDGER_UNAVAILABLE) from None
            block = signature_block(snapshot, self._key, self._key_id)
            if self.release_sink is not None:
                self.release_sink(snapshot, block)
            return block

        outcome = self.release_gate.release(
            release, payload, profile=self.profile.name, action=deliver, cancelled=cancelled
        )
        return self._conclude(result, payload, outcome, attempts, budget, started)

    def _conclude(
        self,
        result: SieveResult,
        payload: str,
        outcome: ReleaseOutcome,
        attempts: int,
        budget: float,
        started: int,
    ) -> TowerResult:
        # `payload` is the snapshot the envelope was built from and the callback
        # received. It is used for the output and the ledger so nothing that
        # touches `result` after delivery can change what is reported released.
        verified = False
        reason = outcome.reason_code
        if outcome.released and self.delivery_confirmer is not None:
            # Ask the receiving side. The callback returning is not evidence it arrived.
            try:
                verified = (
                    call_with_timeout(
                        self.delivery_confirmer,
                        self.confirm_timeout,
                        outcome.release_id,
                        artifact_sha256(payload),
                    )
                    is True
                )
            except Exception:
                verified = False
            if not verified:
                reason = ReleaseReason.DELIVERY_UNCONFIRMED

        delivered = outcome.released and (verified or self.delivery_confirmer is None)
        if delivered:
            status = "RELEASED"
        elif outcome.released or outcome.action_started:
            status = "UNCONFIRMED"
        else:
            status = "HELD"

        # `released` in the ledger means the artifact was delivered AND not left unconfirmed;
        # `callback_completed` is the narrower fact that the callback returned.
        evidence = {**outcome.evidence(), "reason_code": reason, "delivery_verified": verified,
                    "released": delivered, "callback_completed": outcome.released,
                    "ledger_durable": self.ledger.durable}
        recorded = True
        try:
            self.ledger.log("TAP", status, reason, payload, **evidence)
        except Exception:
            recorded = False
        durable = recorded and self.ledger.durable
        anchored = False
        if recorded and self.ledger.anchored:
            # The delivery has happened; a failing anchor cannot undo it, so it is reported, not raised.
            try:
                anchored = self.ledger.flush_anchor()
            except Exception:
                self.metrics.anchor_failed()
        evidence["anchored"] = anchored

        if not delivered:
            if outcome.released or outcome.action_started:
                label = ReleaseState.DELIVERY_UNKNOWN
            elif outcome.authorized:
                label = ReleaseState.FAILED_BEFORE_DELIVERY
            elif reason in NOT_ATTEMPTED_REASONS:
                label = ReleaseState.NOT_ATTEMPTED
            else:
                label = ReleaseState.DENIED
            return self._held(
                result,
                budget,
                attempts,
                started,
                outcome=label,
                reason=reason,
                release_id=outcome.release_id,
                authorization=evidence,
            )

        if not durable:
            label = ReleaseState.DELIVERED_AUDIT_INCOMPLETE
        elif verified:
            label = ReleaseState.DELIVERED
        else:
            label = ReleaseState.DELIVERED_UNVERIFIED

        block = outcome.value
        return TowerResult(
            sieve=result,
            output=payload,
            released=True,
            temporal_budget=budget,
            checksum=block["value"],
            signature=block,
            attempts=attempts,
            elapsed_ns=time.perf_counter_ns() - started,
            release_outcome=label,
            delivery_verified=verified,
            audit_durable=durable,
            audit_anchored=anchored,
            reason_code=reason,
            release_id=outcome.release_id,
            authorization=evidence,
        )


__all__ = ["DeterministicIntegrityTower", "LogicCornerstone", "CONSTRAINT_TEXT"]
