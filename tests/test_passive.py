"""Passive-voice flag: profile gating, detection, and no effect on decisions."""

from __future__ import annotations

import pytest

from zts import Flag
from zts.passive import passive_flags
from zts.profiles import DEFAULT, EXEC, LEGAL, OPS
from zts.result import Verdict
from zts.sieve import ZeroTrustSieve
from zts.tower import DeterministicIntegrityTower

PASSIVE = "The nightly report was completed at 02:17 UTC."
ACTIVE = "The nightly job completed at 02:17 UTC."


class TestDetection:
    def test_passive_wording_is_flagged(self):
        flags = passive_flags(PASSIVE)
        assert len(flags) == 1
        assert flags[0].evidence == "was completed"

    def test_active_wording_is_not_flagged(self):
        assert passive_flags(ACTIVE) == []

    def test_one_flag_per_payload(self):
        assert len(passive_flags("It was done and was checked and is sent.")) == 1

    def test_flag_offset_points_at_the_evidence(self):
        flag = passive_flags(PASSIVE)[0]
        assert PASSIVE[flag.offset : flag.offset + len(flag.evidence)] == flag.evidence


class TestProfileGating:
    @pytest.mark.parametrize("profile", [OPS, EXEC, LEGAL])
    def test_enabled_on_ops_exec_legal(self, profile):
        assert profile.passive_review is True

    def test_disabled_on_default(self):
        assert DEFAULT.passive_review is False

    def test_flag_raised_on_ops(self):
        result = ZeroTrustSieve("ops").run(PASSIVE)
        assert [f.code for f in result.flags] == ["PASSIVE_VOICE"]

    def test_no_flag_on_default(self):
        assert ZeroTrustSieve("default").run(PASSIVE).flags == []


class TestNoEffectOnDecisions:
    def test_verdict_and_score_unchanged(self):
        result = ZeroTrustSieve("ops").run(PASSIVE)
        assert result.flags
        assert result.verdict is Verdict.CLEAN
        assert result.score == 100
        assert not result.findings

    def test_payload_unchanged_on_every_profile(self):
        for profile in ("default", "ops", "exec", "legal"):
            assert ZeroTrustSieve(profile).run(PASSIVE).payload_out == PASSIVE

    def test_tower_releases_passive_payload_unchanged(self):
        result = DeterministicIntegrityTower("ops", hmac_key=b"k" * 32).enforce(PASSIVE)
        assert result.released
        assert result.output == PASSIVE

    def test_causality_and_passive_flags_coexist(self):
        text = "Throughput increased because the cache was warmed."
        codes = [f.code for f in ZeroTrustSieve("ops").run(text).flags]
        # The causal connective suppresses the causality flag; passive still fires.
        assert codes == ["PASSIVE_VOICE"]

    def test_flags_are_flag_objects(self):
        flags = ZeroTrustSieve("ops").run(PASSIVE).flags
        assert all(isinstance(f, Flag) for f in flags)
