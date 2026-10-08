"""Causality flag: a review prompt for outcomes stated without a cause.

A payload that says something "increased", "improved", or "had an impact"
makes a causal claim without naming the cause. This module flags that spot so
a person can check it before release.

Flag-only, by design:

  - It never rewrites text. An earlier build inserted a made-up cause
    ("due to measurable operational impact"), which turned an unsupported
    claim into a fabricated one. The flag leaves the words alone.
  - It is not a gate. It adds no score penalty and does not change the verdict,
    so a flagged payload releases exactly as it would have without the flag.
  - It is noisy on purpose. "result" also matches "test results". A flag asks
    a question; it does not decide anything.
"""

from __future__ import annotations

import re
from typing import Final

from . import patterns
from .result import Flag

#: Outcome words that usually need a stated cause. Matches the stem plus the
#: common endings ("increase", "increased", "improves"), not longer words like
#: "increasingly" or "improvement".
TRIGGER: Final = re.compile(
    r"\b(?:(?:increas|decreas|improv)(?:e|es|ed|ing)?|impacts?|results?)\b",
    re.IGNORECASE,
)

CODE: Final = "CAUSAL_UNSTATED"
DETAIL: Final = (
    "outcome stated without a cause; check the causal claim before release"
)


def causality_flags(text: str) -> list[Flag]:
    """Return at most one flag for `text`.

    No flag when the payload already names a cause anywhere (a causal
    connective from patterns.CAUSAL), or when no outcome word appears.
    """
    if patterns.CAUSAL.search(text):
        return []
    match = TRIGGER.search(text)
    if match is None:
        return []
    return [
        Flag(
            code=CODE,
            evidence=match.group(0),
            offset=match.start(),
            detail=DETAIL,
        )
    ]


__all__ = ["TRIGGER", "CODE", "DETAIL", "causality_flags"]
