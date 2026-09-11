"""Enforcement profiles.

A profile decides which gates are enforced, how hard, and what parity score is
required to pass. The four profile names and their thresholds are reproduced
from the archived Citadel v1.1 router; the per-gate enable flags come from the
same build's PROFILES table.

The distinction that matters: `enforced` gates can fail a payload, `advisory`
gates record a finding without failing it. A finding is always recorded either
way, so a run under `exec` still tells you about the causality gap it chose not
to block on.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .gates import Gate


@dataclass(frozen=True)
class Profile:
    """One enforcement configuration."""

    name: str
    #: Minimum parity score (0-100) a payload must reach to pass.
    threshold: int
    #: Gates whose findings fail the payload.
    enforced: frozenset[Gate]
    #: Gates that record findings but never fail the payload.
    advisory: frozenset[Gate] = field(default_factory=frozenset)
    #: Enforce the em dash rule (en dash allowed, em dash forbidden).
    punctuation: bool = True
    #: Maximum rewrite attempts before the pipeline returns best-effort output.
    max_retries: int = 3

    def enables(self, gate: Gate) -> bool:
        """Does this profile run `gate` at all?"""
        return gate in self.enforced or gate in self.advisory

    def blocks_on(self, gate: Gate) -> bool:
        """Does a finding from `gate` fail the payload?"""
        return gate in self.enforced

    def with_threshold(self, threshold: int) -> "Profile":
        return replace(self, threshold=threshold)


_SYNTACTIC = {Gate.G6, Gate.G3}
_ANTI_SYCOPHANCY = {Gate.G5}
_SEMANTIC = {Gate.G2, Gate.G4}
_AXIOMATIC = {Gate.G1}

#: Baseline. Blocks identity and hedging; everything else is advisory.
DEFAULT = Profile(
    name="default",
    threshold=88,
    enforced=frozenset(_SYNTACTIC | _ANTI_SYCOPHANCY),
    advisory=frozenset(_AXIOMATIC | _SEMANTIC),
)

#: Operational reporting. Adds causal grounding and history anchoring.
OPS = Profile(
    name="ops",
    threshold=90,
    enforced=frozenset(_SYNTACTIC | _ANTI_SYCOPHANCY | _AXIOMATIC | _SEMANTIC),
    advisory=frozenset(),
)

#: Executive summary. Tolerates unsupported claims; will not tolerate voice.
EXEC = Profile(
    name="exec",
    threshold=85,
    enforced=frozenset(_SYNTACTIC | _ANTI_SYCOPHANCY),
    advisory=frozenset(_AXIOMATIC | _SEMANTIC),
)

#: Strictest. Every gate enforced, near-perfect parity required.
LEGAL = Profile(
    name="legal",
    threshold=97,
    enforced=frozenset(_SYNTACTIC | _ANTI_SYCOPHANCY | _AXIOMATIC | _SEMANTIC),
    advisory=frozenset(),
    max_retries=5,
)

PROFILES: dict[str, Profile] = {
    p.name: p for p in (DEFAULT, OPS, EXEC, LEGAL)
}


def get(name: str = "default") -> Profile:
    """Look up a profile by name.

    Raises KeyError with the available names rather than silently falling back,
    because a typo that silently degrades to `default` is the kind of failure
    this stack exists to prevent.
    """
    try:
        return PROFILES[name]
    except KeyError:
        raise KeyError(
            f"unknown profile {name!r}; available: {', '.join(sorted(PROFILES))}"
        ) from None


__all__ = ["Profile", "PROFILES", "DEFAULT", "OPS", "EXEC", "LEGAL", "get"]
