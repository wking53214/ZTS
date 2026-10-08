"""Evidence review flag: absolute claims with no cause and no measured number."""

from __future__ import annotations

from dataclasses import replace

from zts.evidence import CODE, MAX_FLAGS, evidence_flags
from zts.profiles import get as get_profile
from zts.sieve import ZeroTrustSieve


def codes(text: str) -> list[str]:
    return [f.code for f in evidence_flags(text)]


class TestDetection:
    def test_absolute_claim_with_nothing_behind_it_is_flagged(self):
        assert codes("This always works.") == [CODE]

    def test_superlative_without_evidence_is_flagged(self):
        assert codes("It is the best option we have.") == [CODE]

    def test_a_date_is_not_a_measured_number(self):
        assert codes("All nodes were patched on 2026-10-08.") == [CODE]

    def test_a_clock_time_is_not_a_measured_number(self):
        assert codes("Every job finished by 02:17 UTC.") == [CODE]

    def test_a_percentage_counts_as_evidence(self):
        assert codes("Latency fell 40% for every endpoint.") == []

    def test_a_count_with_a_unit_counts_as_evidence(self):
        assert codes("The job never failed in 12 nodes.") == []

    def test_a_currency_amount_counts_as_evidence(self):
        assert codes("Costs were always under $300.") == []

    def test_a_cause_counts_as_evidence(self):
        assert codes("Retries always succeed because the queue is idempotent.") == []

    def test_a_sentence_without_an_absolute_word_is_not_flagged(self):
        assert codes("The queue is usually fast.") == []

    def test_the_flag_points_at_the_trigger_word(self):
        text = "Fine. This always works."
        flag = evidence_flags(text)[0]
        assert flag.evidence.lower() == "always"
        assert text[flag.offset : flag.offset + len("always")].lower() == "always"

    def test_flags_are_capped(self):
        text = " ".join(f"Case {i} always works." for i in range(MAX_FLAGS + 5))
        assert len(evidence_flags(text)) == MAX_FLAGS


class TestProfiles:
    def test_ops_and_legal_raise_the_flag(self):
        assert get_profile("ops").evidence_review is True
        assert get_profile("legal").evidence_review is True

    def test_default_and_exec_do_not_raise_the_flag(self):
        assert get_profile("default").evidence_review is False
        assert get_profile("exec").evidence_review is False

    def test_flag_is_raised_in_the_sieve_on_ops(self):
        result = ZeroTrustSieve("ops").run("This always works.")
        assert "UNSUPPORTED_CLAIM" in [f.code for f in result.flags]

    def test_flag_is_not_raised_on_exec(self):
        result = ZeroTrustSieve("exec").run("This always works.")
        assert "UNSUPPORTED_CLAIM" not in [f.code for f in result.flags]


class TestFlagOnly:
    def test_flag_does_not_change_score_or_verdict(self):
        text = "This always works and is the best option."
        with_flag = ZeroTrustSieve("ops").run(text)
        without = ZeroTrustSieve(replace(get_profile("ops"), evidence_review=False)).run(text)
        assert "UNSUPPORTED_CLAIM" in [f.code for f in with_flag.flags]
        assert with_flag.score == without.score
        assert with_flag.verdict == without.verdict
