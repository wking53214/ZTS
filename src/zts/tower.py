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
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

from .capstone import ArchitectsProtocol, ReleaseMode
from .dashboard import TelemetryDashboard
from .gates import Gate
from .governor import KineticGovernor
from .ledger import ValLedger, checksum, load_or_create_ledger_key
from .normalizer import StructureNormalizer, tidy
from .profiles import Profile
from .profiles import get as get_profile
from .result import SieveResult, TowerResult, Verdict
from .sieve import ZeroTrustSieve

Generator = Callable[[str], Awaitable[str]]

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
    ) -> None:
        self.profile = get_profile(profile) if isinstance(profile, str) else profile
        self.lc = LogicCornerstone(self.profile.name)
        self.zts = ZeroTrustSieve(self.profile)
        self.kg = governor or KineticGovernor()
        self.tap = capstone or ArchitectsProtocol(ReleaseMode.AUTO)
        self._key = hmac_key or secrets.token_bytes(32)
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

    def enforce(self, payload: str, signature: str | None = None) -> TowerResult:
        """Filter one payload. No generator, no event loop, no pacing."""
        started = time.perf_counter_ns()

        intake = self.lc.intake(payload)
        self.ledger.log("LC", "PASS", "ingestion normalized", intake)

        # No history: a single pass has nothing to oscillate against.
        # Submitting the same text twice is a legitimate request, not a loop.
        result = self.zts.run(intake)
        self._log_sieve(result)

        return self._finish(result, signature, attempts=1, budget=0.0, started=started)

    # --- asynchronous path --------------------------------------------------

    async def run(
        self,
        prompt: str,
        generator: Generator,
        signature: str | None = None,
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
        return self._finish(
            result, signature, attempts=attempts, budget=budget_seconds, started=started
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
    ) -> TowerResult:
        """Decide release, then record the outcome if a dashboard is attached."""
        outcome = self._decide(result, signature, attempts, budget, started)
        if self.dashboard is not None:
            self.dashboard.record(outcome)
        return outcome

    def _decide(
        self,
        result: SieveResult,
        signature: str | None,
        attempts: int,
        budget: float,
        started: int,
    ) -> TowerResult:
        if result.verdict is Verdict.BREACH:
            self.ledger.log("TAP", "HELD", "sieve breach: release withheld", result.payload_out)
            return TowerResult(
                sieve=result,
                output="",
                released=False,
                temporal_budget=budget,
                attempts=attempts,
                elapsed_ns=time.perf_counter_ns() - started,
            )

        decision = self.tap.authorize(result.payload_out, signature)
        self.ledger.log(
            "TAP",
            "RELEASED" if decision.released else "HELD",
            decision.reason,
            result.payload_out,
        )

        if not decision.released:
            return TowerResult(
                sieve=result,
                output="",
                released=False,
                temporal_budget=budget,
                attempts=attempts,
                elapsed_ns=time.perf_counter_ns() - started,
            )

        return TowerResult(
            sieve=result,
            output=result.payload_out,
            released=True,
            temporal_budget=budget,
            checksum=checksum(result.payload_out, self._key),
            attempts=attempts,
            elapsed_ns=time.perf_counter_ns() - started,
        )


__all__ = ["DeterministicIntegrityTower", "LogicCornerstone", "CONSTRAINT_TEXT"]
