"""G6 must not change what a sentence means and then let it pass.

Before this fix, the pronoun pattern matched words that are not pronouns ("US" the
country, the "me" in an email address, the "I" in "I/O") and the pronoun inside a
contraction ("I'm"). G6 deleted them, the sieve scored a single finding as ADVISORY, and
the changed text was delivered. These cases pin the corrected behavior:

  * a word that only looks like a pronoun is not a finding, and the text is untouched;
  * a real pronoun that cannot be deleted without breaking the sentence (a contraction,
    a pronoun-only slash pair, a possible Roman numeral, an all-caps "US" in shouted text)
    is reported and left in place, so the payload is held rather than changed;
  * a plain standalone pronoun is still removed, as before.
"""

from __future__ import annotations

import pytest

from zts.gates import Gate
from zts.profiles import get as get_profile
from zts.result import Verdict
from zts.sieve import GateContext, ZeroTrustSieve, gate_ppa

PROFILES = ("default", "ops", "exec", "legal")


@pytest.fixture
def ctx() -> GateContext:
    return GateContext(get_profile("default"))


def _g6(result):
    return next(r for r in result.gates if r.gate is Gate.G6)


# Words that only look like pronouns. G6 must not see them at all.
NOT_PRONOUNS = (
    "Sales in the US market rose 4%.",
    "The US Army filed the report.",
    "Contact me@example.com for access.",
    "Email help@us.example.com today.",
    "Disk 2 reported I/O errors.",
    "Region US-East-1 is down.",
    "Traffic on I-95 slowed.",
    "Read docs at https://example.com/my/page.",
    "Read docs at example.com/our/page today.",
    "Call 1-800-US-BANKS now.",
    "In the US, GDP rose 2%.",
    "The US's share fell.",
)


class TestLookalikesAreNotFindings:
    @pytest.mark.parametrize("text", NOT_PRONOUNS)
    def test_gate_reports_nothing_and_changes_nothing(self, ctx, text):
        out, findings = gate_ppa(text, ctx)
        assert findings == []
        assert out == text

    @pytest.mark.parametrize("profile", PROFILES)
    @pytest.mark.parametrize("text", NOT_PRONOUNS)
    def test_sieve_delivers_the_text_unchanged(self, profile, text):
        result = ZeroTrustSieve(profile).run(text)
        assert _g6(result).verdict is Verdict.CLEAN
        assert result.payload_out == text


# Real pronouns that cannot be deleted without breaking the sentence.
KEPT_AND_HELD = (
    "I'm unable to confirm the figure.",
    "I’m unable to confirm the figure.",  # curly apostrophe
    "We've shipped the fix.",
    "we're waiting on the vendor.",
    "I'd deploy it tonight.",
    "I'll deploy it tonight.",
    "I/we found the bug.",
    "Phase I trial results arrived.",
    "Results from the Phase I trial arrived.",
    "On Monday I deployed it.",
    "That was a type I error.",
    "Stage I cancer was found.",
    "we\u2014found it.",
    "I\u2014and only then\u2014checked.",
    "PLEASE TELL US NOW.",
)


class TestUnremovablePronounsAreHeldNotChanged:
    @pytest.mark.parametrize("text", KEPT_AND_HELD)
    def test_gate_reports_and_leaves_text_in_place(self, ctx, text):
        out, findings = gate_ppa(text, ctx)
        assert findings, "a real pronoun must still be reported"
        assert out == text

    @pytest.mark.parametrize("profile", PROFILES)
    @pytest.mark.parametrize("text", KEPT_AND_HELD)
    def test_sieve_holds_the_payload(self, profile, text):
        result = ZeroTrustSieve(profile).run(text)
        assert result.verdict is Verdict.BREACH
        assert not result.passed
        assert _g6(result).payload_out == _g6(result).payload_in

    def test_a_removable_pronoun_beside_a_kept_one_is_not_removed_either(self, ctx):
        # Held text goes back for a rewrite whole, not half-edited.
        text = "I'm sure my team checked."
        out, findings = gate_ppa(text, ctx)
        assert len(findings) == 2
        assert out == text


class TestStandalonePronounsStillRemoved:
    @pytest.mark.parametrize(
        "text, gone",
        [
            ("I built my own system myself.", ("I", "my", "myself")),
            ("We should review our results.", ("We", "our")),
            ("Then I ran the job.", ("I",)),
            ("Sam and I ran the job.", ("I",)),
            ("Paris, I think, is ready.", ("I",)),
            ("Us engineers reviewed it.", ("Us",)),
            ("Then I\u2014 checked.", ("I",)),
            ('Sam said "I checked."', ("I",)),
        ],
    )
    def test_removed(self, ctx, text, gone):
        out, findings = gate_ppa(text, ctx)
        assert [f.evidence for f in findings] == list(gone)
        for word in gone:
            assert word not in out.split()

    def test_pronoun_inside_quotes_or_brackets_is_still_standalone(self, ctx):
        out, findings = gate_ppa('"We shipped it" (my note).', ctx)
        assert [f.evidence for f in findings] == ["We", "my"]
        assert "We" not in out and "my" not in out

    def test_pronoun_hyphen_joined_to_prose_is_held_not_skipped(self, ctx):
        # Joining a pronoun to ordinary words must not hide it from G6.
        text = "we-found-the-bug yesterday."
        out, findings = gate_ppa(text, ctx)
        assert [f.evidence for f in findings] == ["we"]
        assert out == text

    def test_findings_are_capped_but_every_pronoun_is_removed(self, ctx):
        text = " ".join(["we"] * 14) + " checked."
        out, findings = gate_ppa(text, ctx)
        assert len(findings) == 12
        assert out == "checked."

    def test_finding_offsets_point_at_the_pronoun(self, ctx):
        text = "Contact me@example.com, or ask me."
        _, findings = gate_ppa(text, ctx)
        assert [(f.evidence, f.offset) for f in findings] == [("me", text.rindex("me"))]
