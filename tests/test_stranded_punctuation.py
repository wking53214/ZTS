"""A mark left behind by a removed phrase must not be pulled across a line break (P15).

Before this fix, the cleanup that runs after every gate moved any punctuation that
followed whitespace back onto the previous word, and it counted line breaks as
whitespace. When a gate removed a phrase at the start of a paragraph ("Honestly, the
test passed."), the comma that followed it was dragged to the end of the previous
paragraph and the paragraph break was deleted: "Results are in:\n\nHonestly, the test
passed." was delivered as "Results are in:, the test passed." with verdict CLEAN.

These cases pin the corrected behavior (owner decision 1.3 = A):

  * punctuation is pulled back over spaces or tabs only, never over a line break;
  * a comma stranded at the start of a line is dropped;
  * a comma, semicolon or colon stranded after other punctuation (". ,") is dropped;
  * the old tidy-ups still work: "word ," becomes "word,", ",," becomes ",", and a
    comma, semicolon or colon at the very start of the text is dropped;
  * text that was never touched keeps its punctuation ("e.g., the", a CSV row that
    starts with a comma, a "; comment" line).
"""

from __future__ import annotations

import pytest

from zts.normalizer import tidy
from zts.sieve import ZeroTrustSieve

PROFILES = ("default", "ops", "exec", "legal")

# (text as a gate leaves it, text after cleanup)
TIDY_CASES = (
    # A paragraph break survives; the stranded comma goes.
    ("Step one is done.\n\n, step two follows.", "Step one is done.\n\nstep two follows."),
    ("Results are in:\n\n, the test passed.", "Results are in:\n\nthe test passed."),
    # The gap a gate leaves usually holds a space before the comma.
    ("Step one is done.\n\n , step two follows.", "Step one is done.\n\nstep two follows."),
    # A single line break survives too.
    ("We shipped the fix.\n, the cache is gone.", "We shipped the fix.\nthe cache is gone."),
    ("Line one\n, and two", "Line one\nand two"),
    # A Windows line break is still a line break.
    ("Done.\r\n, next", "Done.\nnext"),
    # Other punctuation never crosses a line break either.
    ("A list:\n\n; item", "A list:\n\n; item"),
    ("First line\n. Second", "First line\n. Second"),
    # A mark stranded right after other punctuation on the same line is dropped.
    ("Step one is done. , step two follows.", "Step one is done. step two follows."),
    ("Results are in: , the test passed.", "Results are in: the test passed."),
    ("One, , two", "One, two"),
    # Unchanged behavior.
    ("Hello , world", "Hello, world"),
    ("Hello\t, world", "Hello, world"),
    ("Done .", "Done."),
    ("a,, b", "a, b"),
    (", leading comma", "leading comma"),
    ("; leading semicolon", "leading semicolon"),
    ("e.g., the cache", "e.g., the cache"),
    ("Header\n,b,c", "Header\n,b,c"),
    ("Config:\n; a comment line", "Config:\n; a comment line"),
)


@pytest.mark.parametrize(("raw", "expected"), TIDY_CASES)
def test_tidy_keeps_line_breaks_and_drops_stranded_marks(raw: str, expected: str) -> None:
    assert tidy(raw) == expected


# Whole-pipeline cases: a removable phrase opens a paragraph or a line.
PIPELINE_CASES = (
    ("Step one is done.\n\nHonestly, step two follows.", "Step one is done.\n\nstep two follows."),
    ("Results are in:\n\nHonestly, the test passed.", "Results are in:\n\nthe test passed."),
)


@pytest.mark.parametrize(("text", "expected"), PIPELINE_CASES)
def test_default_profile_delivers_the_break_intact(text: str, expected: str) -> None:
    result = ZeroTrustSieve().run(text)
    assert result.payload_out == expected


STRUCTURE_CASES = (
    "Step one is done.\n\nHonestly, step two follows.",
    "Results are in:\n\nHonestly, the test passed.",
    "We shipped the fix.\nBasically, the cache is gone.",
    "Summary:\n\nBasically, the rollout is finished.\n\nHonestly, no errors were logged.",
)


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("text", STRUCTURE_CASES)
def test_no_profile_glues_a_comma_onto_the_previous_line(profile: str, text: str) -> None:
    out = ZeroTrustSieve(profile=profile).run(text).payload_out
    for glued in (".,", ":,", "!,", "?,"):
        assert glued not in out
    assert out.count("\n\n") == text.count("\n\n")
    assert out.count("\n") == text.count("\n")
