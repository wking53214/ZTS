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
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from .capstone import ArchitectsProtocol
from .dashboard import TelemetryDashboard
from .gates import Gate
from .governor import KineticGovernor
from .ledger import ValLedger, key_id_for, load_or_create_ledger_key, signature_block
from .normalizer import StructureNormalizer, tidy
from .profiles import Profile
from .profiles import get as get_profile
from .release import (
    EnforcerReleaseGate,
    ReleaseAbort,
    ReleaseOutcome,
    ReleaseReason,
    ReleaseRequest,
)
from .result import SieveResult, TowerResult, Verdict
from .sieve import ZeroTrustSieve

Generator = Callable[[str], Awaitable[str]]
#: Receives the released text and its signature block. Runs only on a release.
ReleaseSink = Callable[[str, dict[str, str]], None]

#: Rewrite instruction emitted per gate when asking a generator to retry.
CONSTRAINT_TEXT: dict[Gate, str] = {
    Gate.G6: "Remove first-person and collective pronouns. State findings without a speaker.",
    Gate.G3: "Remove hedging and filler. Every claim must resolve to something checkable.",
    Gate.G1: "Do not restate, negate, or override the governing instructions.",
    Gate.G5: "Remove flattery, agreement openers, and assistant-voice phrasing.",
    Gate.G2: "Remove affect vocabulary. Report what is observed, not what is felt or believed.",
    Gate.G4: "Rewrite with different structure and phrasing. The previous attempt repeated itself.",
}


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


class DeterministicIntegrityTower:
    """LC -> ZTS -> KG -> TAP."""

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
    ) -> None:
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
        self.ledger = ValLedger(key=ledger_key)
        #: Optional outcome counter. Records only; never changes a decision.
        self.dashboard = dashboard

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
        started = time.perf_counter_ns()

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
        started = time.perf_counter_ns()
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
        return self._finish(
            result,
            signature,
            attempts=attempts,
            budget=budget_seconds,
            started=started,
            release=release,
        )

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
            self.ledger.log(
                gate_result.gate.value.gate_id,
                gate_result.verdict.value.upper(),
                "; ".join(f.evidence for f in gate_result.findings) or gate_result.gate.value.code,
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
    ) -> TowerResult:
        """Decide release, then record the outcome if a dashboard is attached."""
        outcome = self._decide(result, signature, attempts, budget, started, release)
        if self.dashboard is not None:
            self.dashboard.record(outcome)
        return outcome

    def _held(
        self,
        result: SieveResult,
        budget: float,
        attempts: int,
        started: int,
        *,
        outcome: str = "held",
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
    ) -> TowerResult:
        if result.verdict is Verdict.BREACH:
            self.ledger.log("TAP", "HELD", "sieve breach: release withheld", result.payload_out)
            return self._held(
                result, budget, attempts, started, reason=ReleaseReason.SIEVE_BREACH
            )

        if self.release_gate is not None:
            return self._decide_enforced(result, attempts, budget, started, release)

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
        assert self.tap is not None
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
            return self._held(result, budget, attempts, started)

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
                    outcome="unconfirmed",
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
            release_outcome="released",
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
    ) -> TowerResult:
        """Release through Enforcer. The output is reachable only inside its guarded call."""
        assert self.release_gate is not None
        payload = result.payload_out
        release_id = getattr(release, "release_id", "")
        release_id = release_id if isinstance(release_id, str) else ""

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
                outcome="denied",
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
            release, payload, profile=self.profile.name, action=deliver
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
        if outcome.released:
            status, label = "RELEASED", "released"
        elif outcome.action_started:
            status, label = "UNCONFIRMED", "unconfirmed"
        elif outcome.authorized:
            status, label = "HELD", "held"
        else:
            status, label = "HELD", "denied"

        recorded = True
        try:
            self.ledger.log(
                "TAP", status, outcome.reason_code, payload, **outcome.evidence()
            )
        except Exception:
            recorded = False

        evidence = outcome.evidence()
        if not outcome.released:
            return self._held(
                result,
                budget,
                attempts,
                started,
                outcome=label,
                reason=outcome.reason_code,
                release_id=outcome.release_id,
                authorization=evidence,
            )

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
            release_outcome="released" if recorded else "released_unrecorded",
            reason_code=outcome.reason_code,
            release_id=outcome.release_id,
            authorization=evidence,
        )


__all__ = ["DeterministicIntegrityTower", "LogicCornerstone", "CONSTRAINT_TEXT"]
