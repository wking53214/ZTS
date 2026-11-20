from zts import audit, scrub


def test_a_hedge_is_not_deleted_into_a_claim():
    assert scrub("The patient might be allergic to penicillin.") == "The patient might be allergic to penicillin."
    assert scrub("It may not be safe to deploy.") == "It may not be safe to deploy."
    assert scrub("Perhaps the reactor should not be restarted.") == "Perhaps the reactor should not be restarted."


def test_a_zero_width_character_does_not_hide_a_hedge():
    plain = audit("The patient might be allergic.")
    hidden = audit("The patient mi​ght be allergic.")
    assert hidden.verdict == plain.verdict and hidden.score == plain.score


def test_a_lookalike_letter_does_not_hide_a_hedge():
    plain = audit("The patient might be allergic.")
    hidden = audit("The patient mіght be allergic.")
    assert hidden.verdict == plain.verdict and hidden.score == plain.score


def test_ordinary_cyrillic_text_is_left_alone():
    assert scrub("Привет, как дела?") == "Привет, как дела?"
