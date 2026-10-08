"""Leakage flag: card and credential detection, masking, and no effect on decisions."""

from __future__ import annotations

import pytest

from zts import Flag
from zts.leakage import MAX_FLAGS, leakage_flags, luhn_valid
from zts.result import Verdict
from zts.sieve import ZeroTrustSieve
from zts.tower import DeterministicIntegrityTower

CARD = "4111 1111 1111 1111"  # passes Luhn; a public test number
AWS = "AKIAIOSFODNN7EXAMPLE"  # the AWS documentation example key
GH = "ghp_" + "A" * 36
SK = "sk-" + "a" * 24
KEY_BLOCK = "-----BEGIN RSA PRIVATE KEY-----"
PLAIN = "Disk utilization reached 94% on node 3 at 02:17 UTC."


class TestLuhn:
    def test_known_valid_number(self):
        assert luhn_valid("4111111111111111")

    def test_known_invalid_number(self):
        assert not luhn_valid("4111111111111112")


class TestCards:
    def test_valid_card_is_flagged_with_masked_evidence(self):
        flags = leakage_flags(f"Charge to {CARD} today.")
        assert [f.code for f in flags] == ["CARD_NUMBER"]
        assert flags[0].evidence == "************1111"
        assert "4111" not in flags[0].evidence

    def test_card_without_separators_is_flagged(self):
        assert leakage_flags("card 4111111111111111") != []

    def test_card_failing_checksum_is_not_flagged(self):
        assert leakage_flags("order 4111 1111 1111 1112") == []

    def test_short_numbers_are_not_flagged(self):
        assert leakage_flags("call 555-123-4567 before 02:17") == []


class TestCredentials:
    @pytest.mark.parametrize(
        "text, label",
        [
            ("api_key = Zx9qLmN4pRt7WvBc", "api_key"),
            ("secretKey=AB12cd34ef56gh78", "secretKey"),
            ("password: hunter2hunter2", "password"),
        ],
    )
    def test_assignment_is_flagged_and_value_is_hidden(self, text, label):
        flags = leakage_flags(text)
        assert len(flags) == 1
        assert flags[0].code == "CREDENTIAL"
        assert flags[0].evidence == f"{label}=****"

    def test_prefixed_formats_are_flagged(self):
        for text, label in [
            (AWS, "aws_access_key_id"),
            (GH, "github_token"),
            (SK, "api_key_sk"),
            (KEY_BLOCK, "private_key_block"),
        ]:
            flags = leakage_flags(text)
            assert [f.evidence for f in flags] == [f"{label}=****"], text

    def test_prose_mentioning_secrets_is_not_flagged(self):
        assert leakage_flags("The unknown secret plan was never written down.") == []

    def test_plain_text_has_no_flags(self):
        assert leakage_flags(PLAIN) == []


class TestNoRawSecretInFlags:
    @pytest.mark.parametrize("secret", [CARD, AWS, GH, SK, "Zx9qLmN4pRt7WvBc"])
    def test_raw_value_never_appears_in_flags(self, secret):
        text = f"value {secret} here, password={secret}"
        for flag in leakage_flags(text):
            assert secret not in flag.evidence
            assert secret not in flag.detail


class TestCapAndOrder:
    def test_flags_are_capped(self):
        text = " ".join(f"AKIA{'A' * 12}{i:04d}"[:20] for i in range(MAX_FLAGS + 5))
        assert len(leakage_flags(text)) <= MAX_FLAGS

    def test_flags_are_in_offset_order(self):
        text = f"{GH} then {CARD}"
        offsets = [f.offset for f in leakage_flags(text)]
        assert offsets == sorted(offsets)


class TestSieveWiring:
    @pytest.mark.parametrize("profile", ["default", "ops", "exec", "legal"])
    def test_flag_raised_on_every_profile(self, profile):
        result = ZeroTrustSieve(profile).run(f"Charge {CARD}")
        assert "CARD_NUMBER" in [f.code for f in result.flags]

    def test_flag_does_not_change_verdict_score_or_payload(self):
        text = f"Use token={GH}"
        result = ZeroTrustSieve("ops").run(text)
        assert result.flags
        assert result.verdict is Verdict.CLEAN
        assert result.score == 100
        assert result.payload_out == text

    def test_tower_releases_flagged_payload_unchanged(self):
        text = f"Charge {CARD}"
        result = DeterministicIntegrityTower("ops", hmac_key=b"k" * 32).enforce(text)
        assert result.released
        assert result.output == text
        assert all(isinstance(f, Flag) for f in result.sieve.flags)
