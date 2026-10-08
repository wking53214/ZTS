"""Passive-voice review flag: a prompt to check who or what does the action.

Passive wording ("the report was completed") hides the actor. That is not
always wrong, but a reviewer should see it before release.

Flag-only, by design, the same as the causality flag:

  - It never rewrites text. CITADEL rewrote three hard-coded phrases, which
    is brittle and can change meaning, so that rewrite is not ported.
  - It is not a gate. It adds no score penalty and does not change the verdict.
  - It is loose on purpose. The pattern matches a "to be" verb followed by any
    word ending in "ed" or "en", so "is often" also matches. The flag asks a
    question; it does not decide anything.

Which profiles raise it is set on the Profile (passive_review), following
CITADEL's rule: ops, exec, and legal, not default.
"""

from __future__ import annotations

from typing import Final

from . import patterns
from .result import Flag

CODE: Final = "PASSIVE_VOICE"
DETAIL: Final = "passive wording; check who or what performs the action"


def passive_flags(text: str) -> list[Flag]:
    """Return at most one passive-voice flag for `text`."""
    match = patterns.PASSIVE.search(text)
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


__all__ = ["CODE", "DETAIL", "passive_flags"]
