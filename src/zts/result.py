"""Result types returned by the sieve and the tower."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .gates import Gate


class Verdict(Enum):
    """Outcome of a single gate or of a whole pass."""

    #: No finding.
    CLEAN = "clean"
    #: Finding recorded; profile does not block on it.
    ADVISORY = "advisory"
    #: Finding recorded; profile blocks on it.
    BREACH = "breach"
    #: Gate not enabled by the active profile.
    SKIPPED = "skipped"
    #: Gate never ran because an earlier gate short-circuited the array.
    NOT_REACHED = "not_reached"


@dataclass
class Finding:
    """One violation detected by one gate."""

    gate: Gate
    verdict: Verdict
    #: The matched text, or a description when the finding is an absence.
    evidence: str
    #: Character offset of the match, or -1 when the finding is an absence.
    offset: int = -1
    detail: str = ""

    @property
    def gate_id(self) -> str:
        return self.gate.value.gate_id

    @property
    def code(self) -> str:
        return self.gate.code


@dataclass
class GateResult:
    """What one gate did to one payload."""

    gate: Gate
    verdict: Verdict
    payload_in: str
    payload_out: str
    findings: list[Finding] = field(default_factory=list)
    elapsed_ns: int = 0

    @property
    def mutated(self) -> bool:
        return self.payload_in != self.payload_out


@dataclass(frozen=True)
class Flag:
    """A review prompt. It never changes the verdict, the score, or the payload.

    Flags sit beside the gate findings. A finding is a rule the payload broke.
    A flag is a spot a person should look at before release, such as an outcome
    stated without its cause.
    """

    code: str
    evidence: str
    offset: int = -1
    detail: str = ""


@dataclass
class SieveResult:
    """Outcome of one pass through the gate array."""

    payload_in: str
    payload_out: str
    profile: str
    verdict: Verdict
    #: Per-gate results in execution order, including gates never reached.
    gates: list[GateResult] = field(default_factory=list)
    #: Parity score, 0-100. 100 means no findings of any kind.
    parity: float = 1.0
    score: int = 100
    #: Gate that short-circuited the array, if any.
    breached_at: Gate | None = None
    #: Gates that never ran because of the short circuit.
    gates_skipped: int = 0
    elapsed_ns: int = 0
    #: Review prompts. Informational only: not part of the verdict or score.
    flags: list[Flag] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.verdict in (Verdict.CLEAN, Verdict.ADVISORY)

    @property
    def findings(self) -> list[Finding]:
        return [f for g in self.gates for f in g.findings]

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_ns / 1_000_000

    def summary(self) -> str:
        """One-line human summary."""
        where = f" at {self.breached_at.value}" if self.breached_at else ""
        return (
            f"{self.verdict.value.upper()}{where} "
            f"| profile={self.profile} score={self.score} "
            f"parity={self.parity:.4f} "
            f"| {len(self.findings)} finding(s) "
            f"| {self.elapsed_ms:.3f}ms"
        )


@dataclass
class TowerResult:
    """Outcome of a full Deterministic Integrity Tower run."""

    sieve: SieveResult
    #: Final payload after capstone handling.
    output: str
    #: True only when the G7 handshake authorized release.
    released: bool
    #: Temporal budget the governor computed, in seconds.
    temporal_budget: float = 0.0
    #: HMAC-SHA384 of the released payload, or "" when not released.
    checksum: str = ""
    #: Rewrite attempts consumed.
    attempts: int = 1
    elapsed_ns: int = 0

    @property
    def elapsed_ms(self) -> float:
        return self.elapsed_ns / 1_000_000

    @property
    def passed(self) -> bool:
        return self.sieve.passed


__all__ = [
    "Verdict",
    "Finding",
    "Flag",
    "GateResult",
    "SieveResult",
    "TowerResult",
]
