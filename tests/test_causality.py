"""Causality flag: fires on unstated outcomes, never changes a decision."""

from __future__ import annotations

import pytest

from zts import Flag
from zts.causality import causality_flags
from zts.result import Verdict
from zts.sieve import ZeroTrustSieve
from zts.tower import DeterministicIntegrityTower

FLAGGED = "Throughput increased to 94% on node 3 at 02:17 UTC."
EXPLAINED = "Throughput increased because the cache was warmed at 02:17 UTC."
PLAIN = "Disk utilization reached 94% on node 3 at 02:17 UTC."


class TestDetection:
    @pytest.mark.parametrize(
        "text, evidence",
        [
            ("Throughput increased to 94%.", "increased"),
            ("Latency will decrease next week.", "decrease"),
            ("The patch should improve recovery time.", "improve"),
            ("The outage had an impact on billing.", "impact"),
            ("The migration produced results overnight.", "results"),
        ],
    )
    def test_outcome_word_without_cause_is_flagged(self, text, evidence):
        flags = causality_flags(text)
        assert len(flags) == 1
        assert flags[0].evidence.lower() == evidence

    @pytest.mark.parametrize(
        "text",
        [
            "Throughput increased because the cache was warmed.",
            "Throughput increased due to the cache warm-up.",
            "Latency dropped, therefore we changed the pool size.",
        ],
    )
    def test_named_cause_suppresses_the_flag(self, text):
        assert causality_flags(text) == []

    @pytest.mark.parametrize(
        "text",
        [
            PLAIN,
            "Traffic was increasingly routed through the edge.",
            "The team shipped a documentation improvement.",
        ],
    )
    def test_no_outcome_word_or_longer_word_means_no_flag(self, text):
        assert causality_flags(text) == []

    def test_flag_offset_points_at_the_evidence(self):
        flag = causality_flags(FLAGGED)[0]
        assert FLAGGED[flag.offset : flag.offset + len(flag.evidence)] == flag.evidence

    def test_flag_is_one_per_payload(self):
        flags = causality_flags("Output increased and latency decreased and impact grew.")
        assert len(flags) == 1


class TestSieveWiring:
    def test_flag_reaches_the_sieve_result(self):
        result = ZeroTrustSieve("ops").run(FLAGGED)
        assert len(result.flags) == 1
        assert isinstance(result.flags[0], Flag)

    def test_flag_does_not_change_verdict_or_score(self):
        result = ZeroTrustSieve("ops").run(FLAGGED)
        assert result.flags
        assert result.verdict is Verdict.CLEAN
        assert result.score == 100
        assert not result.findings

    def test_flag_does_not_change_the_payload(self):
        for profile in ("default", "ops", "exec", "legal"):
            result = ZeroTrustSieve(profile).run(FLAGGED)
            assert result.payload_out == FLAGGED

    def test_flag_does_not_block_a_repair_pass(self):
        result = ZeroTrustSieve("default", mode="repair").run(FLAGGED)
        assert result.passed


class TestTowerRelease:
    def test_flagged_payload_is_released_unchanged(self):
        result = DeterministicIntegrityTower("ops", hmac_key=b"k" * 32).enforce(FLAGGED)
        assert result.released
        assert result.output == FLAGGED
        assert result.checksum

    def test_flagged_and_plain_payloads_release_the_same_way(self):
        tower = DeterministicIntegrityTower("ops", hmac_key=b"k" * 32)
        flagged = tower.enforce(FLAGGED)
        plain = tower.enforce(PLAIN)
        assert flagged.released and plain.released
        assert flagged.sieve.verdict is plain.sieve.verdict
        assert flagged.sieve.score == plain.sieve.score

    def test_explained_outcome_has_no_causality_flag(self):
        result = ZeroTrustSieve("ops").run(EXPLAINED)
        assert "CAUSAL_UNSTATED" not in [f.code for f in result.flags]
