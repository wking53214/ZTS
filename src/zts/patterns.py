"""Centralized pre-compiled regex cache.

Historical note: the archived ZTS builds all opened with a module-level dict of
pre-compiled patterns, described in the source records as the
"CENTRALIZED FAIL-FAST REGEX CACHE". Compiling once at import and reusing the
compiled objects across every gate is what makes the syntactic gates cheap
enough to run ahead of the semantic ones.

Every pattern below is reproduced from the archived v13.0 cache. Additions made
during reconstruction are marked RECONSTRUCTED and listed in PROVENANCE.md.
"""

from __future__ import annotations

import re
from typing import Final

# --- Gate-owned patterns (archived verbatim) ---------------------------------

#: G6 / PPA - first-person singular and collective identity markers.
PPA: Final = re.compile(
    r"\b(i|me|my|mine|myself|we|us|our|ours|ourselves)\b",
    re.IGNORECASE,
)

#: G3 / SBF - epistemic hedges and softeners.
SBF: Final = re.compile(
    r"\b(may|might|could|seems|generally|potentially|likely|perhaps|maybe|probably|i think)\b",
    re.IGNORECASE,
)

#: G5 / SND - mechanical flattery and assistant-voice tells.
SND: Final = re.compile(
    r"\b(great point|excellent point|great work|i agree|as an ai|certainly|"
    r"you are correct|you're correct|good question|happy to help)\b",
    re.IGNORECASE,
)

#: G2 / SCF - affect vocabulary that contaminates a declarative payload.
SCF: Final = re.compile(
    r"\b(feel|feels|felt|hope|hopes|believe|believes|sad|happy|worry|worried|afraid)\b",
    re.IGNORECASE,
)

# --- Shared heuristics -------------------------------------------------------

#: Passive-voice heuristic. Deliberately loose; used as a signal, not a hard gate.
PASSIVE: Final = re.compile(
    r"\b(am|is|are|was|were|be|been|being)\b\s+\w+(ed|en)\b",
    re.IGNORECASE,
)

#: Numeric or percentage evidence.
METRIC: Final = re.compile(r"\b\d+(\.\d+)?%|\b\d+\b")

#: Explicit causal connectives.
CAUSAL: Final = re.compile(
    r"\b(because|due to|driven by|resulting from|caused by|therefore|consequently)\b",
    re.IGNORECASE,
)

#: Abstract corporate verbs the normalizer collapses to concrete equivalents.
ABSTRACT_VERBS: Final = re.compile(
    r"\b(improve|optimize|enhance|enable|support|strengthen|utilize|leverage)\b",
    re.IGNORECASE,
)

#: Conversational puffery removed by the SBF transform stage.
PUFFERY: Final = re.compile(
    r"\b(honestly|humbly|actually|basically|really|just|very|please|thank you)\b",
    re.IGNORECASE,
)

#: Em dash. The archive's punctuation rule: en dash allowed, em dash forbidden.
EMDASH: Final = re.compile(r"—")

#: Collapse runs of whitespace left behind by substitution.
WHITESPACE: Final = re.compile(r"\s{2,}")

#: Orphaned punctuation left behind by substitution (" ," / " ." / ",,").
ORPHAN_PUNCT: Final = re.compile(r"\s+([,.;:!?])")

CACHE: Final[dict[str, re.Pattern[str]]] = {
    "PPA": PPA,
    "SBF": SBF,
    "SND": SND,
    "SCF": SCF,
    "PASSIVE": PASSIVE,
    "METRIC": METRIC,
    "CAUSAL": CAUSAL,
    "ABSTRACT_VERBS": ABSTRACT_VERBS,
    "PUFFERY": PUFFERY,
    "EMDASH": EMDASH,
}

__all__ = [
    "CACHE",
    "PPA",
    "SBF",
    "SND",
    "SCF",
    "PASSIVE",
    "METRIC",
    "CAUSAL",
    "ABSTRACT_VERBS",
    "PUFFERY",
    "EMDASH",
    "WHITESPACE",
    "ORPHAN_PUNCT",
]
