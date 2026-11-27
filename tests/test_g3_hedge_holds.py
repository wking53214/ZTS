"""A hedge holds the payload whatever else G3 changed in the same pass (P17).

Before this change, the sieve held an enforced finding only when its gate left the text
unchanged. G3 reports a hedge and leaves it in place, but it also removes puffery and
rewrites abstract verbs. When it did either, the gate counted as having repaired the
text, the score decided, and one hedge (5 points) passed: "The drug might cause liver
damage." was held on every profile while "Honestly the drug might cause liver damage."
passed as ADVISORY on default, ops and exec. A filler word disabled the hold.

Owner decision 1.4 (second part) = B: a hedge always holds. Accepted cost, recorded as a
follow-up: legitimate uncertainty is still held; relaxing that belongs to customer policy
or the Output Inspector, not to ZTS's word filters.

These cases pin:
  * a hedge holds on all four profiles, with or without puffery or a rewritten verb in
    the same sentence, and the hedge is still in the delivered text;
  * puffery alone is still removed and does not hold;
  * clean text is unchanged and passes;
  * G6, which repairs what it reports, still passes a removable pronoun on default.
"""

from __future__ import annotations

import pytest

from zts.gates import Gate
from zts.result import Verdict
from zts.sieve import ZeroTrustSieve

PROFILES = ("default", "ops", "exec", "legal")

# (text, the hedge that must survive)
HEDGED = (
    ("The drug might cause liver damage.", "might"),
    ("Honestly the drug might cause liver damage.", "might"),
    ("The drug very likely might cause liver damage.", "might"),
    ("Just so you know, the bridge may collapse.", "may"),
    ("The drug might cause liver damage, honestly.", "might"),
    ("Basically the fix seems to work.", "seems"),
)

PUFFERY_ONLY = (
    "Honestly the test passed.",
    "The build basically finished in four minutes.",
)


def _g3(result):
    return next(r for r in result.gates if r.gate is Gate.G3)


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize(("text", "hedge"), HEDGED)
def test_a_hedge_holds_whatever_else_g3_changed(profile: str, text: str, hedge: str) -> None:
    result = ZeroTrustSieve(profile=profile).run(text)
    assert _g3(result).verdict is Verdict.BREACH
    assert result.verdict is Verdict.BREACH
    assert hedge in result.payload_out


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("text", PUFFERY_ONLY)
def test_puffery_alone_is_removed_and_does_not_hold(profile: str, text: str) -> None:
    result = ZeroTrustSieve(profile=profile).run(text)
    assert _g3(result).verdict is Verdict.CLEAN
    assert result.verdict is not Verdict.BREACH
    assert result.payload_out != text


@pytest.mark.parametrize("profile", PROFILES)
def test_clean_text_passes_unchanged(profile: str) -> None:
    result = ZeroTrustSieve(profile=profile).run("The test passed.")
    assert result.verdict is Verdict.CLEAN
    assert result.payload_out == "The test passed."


def test_a_removable_pronoun_still_passes_on_default() -> None:
    result = ZeroTrustSieve().run("We shipped the fix.")
    assert result.verdict is Verdict.ADVISORY
    assert result.payload_out == "shipped the fix."
