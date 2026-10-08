"""ZTS - the Zero Trust Stack.

A deterministic linguistic filtration array. Seven gates, G1 through G7, run in
ascending cost order so that cheap syntactic checks reject a payload before an
expensive semantic one has to look at it.

Quick start:

    >>> from zts import scrub
    >>> scrub("I think we could probably leverage this methodology.")
    'apply this approach.'

    >>> from zts import ZeroTrustSieve
    >>> result = ZeroTrustSieve("legal").run("As an AI, I may be wrong.")
    >>> result.verdict.value
    'breach'

See ARCHITECTURE.md for what each gate does and PROVENANCE.md for where this
came from and which parts of the original claims survived verification.
"""

from __future__ import annotations

from .capstone import ArchitectsProtocol, ReleaseDecision, ReleaseMode
from .gates import (
    CANONICAL_ORDER,
    FAIL_FAST_ORDER,
    Cost,
    Gate,
    GateSpec,
)
from .governor import Budget, KineticGovernor
from .ledger import LedgerEntry, ValLedger
from .normalizer import StructureNormalizer
from .profiles import PROFILES, Profile
from .profiles import get as get_profile
from .result import Finding, Flag, GateResult, SieveResult, TowerResult, Verdict
from .sieve import BEDROCK_AXIOMS, PENALTIES, ZeroTrustSieve
from .tower import DeterministicIntegrityTower, LogicCornerstone
from .dashboard import TelemetryDashboard

__version__ = "13.0.0"

#: The version designation the stack carried in the archive.
ARCHIVE_DESIGNATION = "GSA v13.0 Adamantium-Grade"


def scrub(text: str, profile: str = "default") -> str:
    """Filter `text` and return the cleaned payload.

    The one-liner entry point. Returns the scrubbed text regardless of verdict;
    use `ZeroTrustSieve.run` when you need the verdict, the findings, or the
    score.
    """
    return ZeroTrustSieve(profile).run(text).payload_out


def audit(text: str, profile: str = "default") -> SieveResult:
    """Filter `text` and return the full result with findings and score."""
    return ZeroTrustSieve(profile).run(text)


__all__ = [
    "__version__",
    "ARCHIVE_DESIGNATION",
    "scrub",
    "audit",
    # gates
    "Gate",
    "GateSpec",
    "Cost",
    "CANONICAL_ORDER",
    "FAIL_FAST_ORDER",
    "BEDROCK_AXIOMS",
    "PENALTIES",
    # pipeline
    "ZeroTrustSieve",
    "DeterministicIntegrityTower",
    "LogicCornerstone",
    "KineticGovernor",
    "Budget",
    "ArchitectsProtocol",
    "ReleaseMode",
    "ReleaseDecision",
    "StructureNormalizer",
    # config
    "Profile",
    "PROFILES",
    "get_profile",
    # results
    "Verdict",
    "Finding",
    "Flag",
    "GateResult",
    "SieveResult",
    "TowerResult",
    # telemetry
    "TelemetryDashboard",
    # audit
    "ValLedger",
    "LedgerEntry",
]
