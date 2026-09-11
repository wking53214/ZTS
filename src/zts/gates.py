"""The gate array: G1 through G7.

Two orderings exist and both are load-bearing.

CANONICAL_ORDER is how the gates were numbered when the stack was designed:
a hierarchy running from the axioms outward to the user handshake. It is the
order people refer to by number, and it is preserved so that "G4" means the
same thing here as it does in the archive.

FAIL_FAST_ORDER is how the gates actually execute after the v2.0 refactor. The
observation behind it: most rejections are caused by cheap, character-level
violations, and running an expensive semantic gate before a cheap syntactic one
means paying for analysis of a payload that was going to be rejected anyway.
Sorting the array by ascending cost and rejecting at the first failure means the
common case pays only for the cheap gates.

That is the whole idea, and it is a real one. It is short-circuit evaluation
with the predicates sorted by cost, which is standard practice in query
planners and packet filters. The archive states the refactor moved latency from
214ms to 32ms; those numbers were produced by a language model narrating a
simulation, not by a profiler, so they are recorded in PROVENANCE.md as claims
and are not repeated as results. Run `bench/bench_failfast.py` for measurements
taken on the machine you are actually on.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Cost(Enum):
    """Execution cost class. Determines fail-fast position."""

    #: Single pre-compiled regex pass over the payload.
    SYNTACTIC = 1
    #: Set membership or table lookup over the payload.
    LEXICAL = 2
    #: Requires prior state, cross-payload comparison, or model inference.
    SEMANTIC = 3
    #: Requires an out-of-band signal from a human. Never automatic.
    MANUAL = 4


@dataclass(frozen=True)
class GateSpec:
    """Static description of one gate."""

    gate_id: str
    code: str
    name: str
    cost: Cost
    summary: str

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.gate_id}/{self.code}"


G1 = GateSpec(
    gate_id="G1",
    code="AB",
    name="Axiomatic Base",
    cost=Cost.LEXICAL,
    summary=(
        "Rejects payloads that attempt to restate, negate, or overwrite the "
        "stack's own bedrock axioms. A payload is allowed to be about the "
        "axioms; it is not allowed to assert new ones."
    ),
)

G2 = GateSpec(
    gate_id="G2",
    code="SCF",
    name="Semantic Contamination Filter",
    cost=Cost.SEMANTIC,
    summary=(
        "Flags affect vocabulary carried into a payload that is supposed to be "
        "declarative. Detects the leak; does not decide whether the leak matters."
    ),
)

G3 = GateSpec(
    gate_id="G3",
    code="SBF",
    name="Syntactic Breach Filter",
    cost=Cost.SYNTACTIC,
    summary=(
        "Strips epistemic hedges and conversational puffery so that assertions "
        "resolve to something that can be checked."
    ),
)

G4 = GateSpec(
    gate_id="G4",
    code="HCA",
    name="Historical Context Anchor",
    cost=Cost.SEMANTIC,
    summary=(
        "Compares the payload against the ledger of prior payloads. Catches "
        "oscillation, verbatim repetition, and contradiction of an earlier "
        "accepted assertion. The only gate that requires memory."
    ),
)

G5 = GateSpec(
    gate_id="G5",
    code="SND",
    name="Sycophancy Neutralization Deck",
    cost=Cost.LEXICAL,
    summary=(
        "Removes mechanical flattery and assistant-voice tells. Targets the "
        "specific failure this whole stack was built to address."
    ),
)

G6 = GateSpec(
    gate_id="G6",
    code="PPA",
    name="Pronominal Purge Array",
    cost=Cost.SYNTACTIC,
    summary=(
        "Removes first-person singular and collective identity markers. The "
        "cheapest gate in the array and the most frequently tripped, which is "
        "why the fail-fast refactor moved it to position one."
    ),
)

G7 = GateSpec(
    gate_id="G7",
    code="TAP",
    name="The Architect's Protocol",
    cost=Cost.MANUAL,
    summary=(
        "Terminal capstone. Holds a passing payload in an unreleased state "
        "until an out-of-band human handshake authorizes release. Cannot be "
        "satisfied by anything inside the pipeline."
    ),
)


class Gate(Enum):
    """Gate identity. Members are the specs; `.value` is the GateSpec."""

    G1 = G1
    G2 = G2
    G3 = G3
    G4 = G4
    G5 = G5
    G6 = G6
    G7 = G7

    @property
    def spec(self) -> GateSpec:
        return self.value

    @property
    def code(self) -> str:
        return self.value.code

    @property
    def cost(self) -> Cost:
        return self.value.cost

    @classmethod
    def by_code(cls, code: str) -> "Gate":
        code = code.upper()
        for member in cls:
            if member.code == code:
                return member
        raise KeyError(f"no gate with code {code!r}")


#: Design order. G1 through G7 as numbered.
CANONICAL_ORDER: tuple[Gate, ...] = (
    Gate.G1,
    Gate.G2,
    Gate.G3,
    Gate.G4,
    Gate.G5,
    Gate.G6,
    Gate.G7,
)

#: Execution order after the v2.0 fail-fast refactor: ascending cost.
#: G6 -> G3 -> G1 -> G2 -> G5 -> G4, with G7 held out as the manual capstone.
FAIL_FAST_ORDER: tuple[Gate, ...] = (
    Gate.G6,  # PPA  - syntactic
    Gate.G3,  # SBF  - syntactic
    Gate.G1,  # AB   - lexical
    Gate.G5,  # SND  - lexical
    Gate.G2,  # SCF  - semantic
    Gate.G4,  # HCA  - semantic
)

#: Gates that run inside the automated pipeline. G7 is excluded by definition.
PIPELINE_GATES: tuple[Gate, ...] = FAIL_FAST_ORDER


def verify_fail_fast_order() -> None:
    """Assert FAIL_FAST_ORDER is sorted by ascending cost.

    The ordering is the entire optimization. If an edit reorders a gate such
    that an expensive gate runs before a cheap one, the array silently loses
    its point. This is checked at import and in the test suite.
    """
    costs = [gate.cost.value for gate in FAIL_FAST_ORDER]
    if costs != sorted(costs):
        raise AssertionError(
            "FAIL_FAST_ORDER is not sorted by ascending cost: "
            + " -> ".join(f"{g.value.gate_id}({g.cost.name})" for g in FAIL_FAST_ORDER)
        )


verify_fail_fast_order()

__all__ = [
    "Cost",
    "GateSpec",
    "Gate",
    "CANONICAL_ORDER",
    "FAIL_FAST_ORDER",
    "PIPELINE_GATES",
    "verify_fail_fast_order",
    "G1",
    "G2",
    "G3",
    "G4",
    "G5",
    "G6",
    "G7",
]
