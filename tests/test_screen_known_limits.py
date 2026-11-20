"""The word-list gates are a tripwire, not a guarantee.

These tests record wording the lists do not catch today, so the README's "still open" claim is checked and a
later improvement shows up as a test that has to be edited on purpose. They do not say the behavior is right.
"""

from __future__ import annotations

import pytest

from zts import audit
from zts.result import Verdict


@pytest.mark.parametrize(
    "text",
    [
        "Great question! You're absolutely right.",  # flattery outside the ten listed phrases
        "It is possibly the case that the drug works.",  # a hedge outside the listed hedge words
        "Es posible que el paciente sea alérgico.",  # the lists are fixed English
    ],
)
def test_wording_outside_the_fixed_english_lists_audits_clean(text):
    assert audit(text).verdict is Verdict.CLEAN
