"""Evidence review flag: a prompt to check claims that state more than they show.

An absolute or superlative claim ("always", "never", "all", "best", "guaranteed")
with no stated cause and no measured number is hard to check. This module flags
that sentence so a person can look at it before release.

Flag-only, by design, the same as the causality and passive flags:

  - It never rewrites text. It never adds a cause or a number.
  - It is not a gate. It adds no score penalty and does not change the verdict.
  - It is raised only on ops and legal (Profile.evidence_review). The exec
    profile tolerates unsupported claims by design.

What counts as a measured number is strict on purpose. A bare integer does not:
a clock time ("02:17"), a date ("2026-10-08"), or a version-style token is not
evidence. A number counts when it is a percentage, a currency amount, a decimal,
or a count with a unit ("3 retries", "40 ms", "12 nodes").

The cause test reuses patterns.CAUSAL, so a sentence that names a cause is not
flagged, as with the causality flag.
"""

from __future__ import annotations

import re
from typing import Final

from . import patterns
from .result import Flag

#: Absolute and superlative words that make a claim hard to check.
ABSOLUTE: Final = re.compile(
    r"\b(?:always|never|all|every|none|guaranteed|proven|best|worst|fastest|slowest"
    r"|significantly|dramatically|substantially)\b",
    re.IGNORECASE,
)

#: A measured number: a percentage, a currency amount, a decimal, or a count with a unit.
MEASURED: Final = re.compile(
    r"[$€£]\s?\d"
    r"|\b\d+(?:\.\d+)?\s?%"
    r"|\b\d+\.\d+\b"
    r"|\b\d+\s?(?:ms|seconds?|secs?|minutes?|mins?|hours?|days?|weeks?|months?|years?"
    r"|MB|GB|TB|requests?|users?|customers?|nodes?|calls?|tickets?|cases?|times|x"
    r"|percent|dollars?|USD|items?|errors?|failures?|incidents?|records?)\b",
    re.IGNORECASE,
)

#: One sentence: text up to a full stop, question mark, or exclamation mark, or to a line break.
_SENTENCE: Final = re.compile(r"[^.!?\n]+[.!?]?")

CODE: Final = "UNSUPPORTED_CLAIM"
DETAIL: Final = (
    "absolute claim with no stated cause or measured number; check it before release"
)
MAX_FLAGS: Final = 10


def evidence_flags(text: str) -> list[Flag]:
    """Return review flags for absolute claims that show neither a cause nor a number.

    Capped at MAX_FLAGS. Each flag points at the absolute word that triggered it.
    """
    flags: list[Flag] = []
    for sentence_match in _SENTENCE.finditer(text):
        sentence = sentence_match.group(0)
        trigger = ABSOLUTE.search(sentence)
        if trigger is None:
            continue
        if patterns.CAUSAL.search(sentence) or MEASURED.search(sentence):
            continue
        flags.append(
            Flag(
                code=CODE,
                evidence=trigger.group(0),
                offset=sentence_match.start() + trigger.start(),
                detail=DETAIL,
            )
        )
        if len(flags) >= MAX_FLAGS:
            break
    return flags


__all__ = ["ABSOLUTE", "MEASURED", "CODE", "DETAIL", "MAX_FLAGS", "evidence_flags"]
