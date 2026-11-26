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

    def test_leak_holds_payload_and_keeps_text_unchanged(self):
        text = f"Use token={GH}"
        result = ZeroTrustSieve("ops").run(text)
        assert result.flags
        assert result.verdict is Verdict.BREACH
        assert not result.passed
        assert result.payload_out == text

    def test_leak_holds_on_every_profile(self):
        for profile in ("default", "ops", "exec", "legal"):
            result = ZeroTrustSieve(profile).run(f"Charge {CARD}")
            assert result.verdict is Verdict.BREACH, profile

    def test_non_blocking_flags_still_release(self):
        # Causality and passive flags stay advisory: the payload still passes.
        result = ZeroTrustSieve("ops").run("Throughput increased; the report was completed.")
        assert result.flags
        assert result.passed

    def test_tower_holds_leaking_payload(self):
        text = f"Charge {CARD}"
        result = DeterministicIntegrityTower("ops", hmac_key=b"k" * 32).enforce(text)
        assert not result.released
        assert result.output == ""
        assert all(isinstance(f, Flag) for f in result.sieve.flags)

    def test_ledger_export_never_contains_the_card_digits(self):
        tower = DeterministicIntegrityTower("ops", hmac_key=b"k" * 32)
        tower.enforce(f"Charge {CARD}")
        assert len(tower.ledger) > 0
        assert "4111111111111111" not in tower.ledger.to_jsonl()


class TestFormatsMissedBefore13_0_1:
    """Each of these audited CLEAN at 9784786 (main, 2026-11-25). Each must now hold the payload."""

    CARD_DIGITS = "4111111111111111"

    @pytest.mark.parametrize(
        "text, evidence",
        [
            ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_access_key=****"),
            ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123", "authorization_header=****"),
            ("authorization: basic dXNlcjpwYXNzd29yZA==", "authorization_header=****"),
            ("curl -H 'Bearer 9f8e7d6c5b4a39281706f5e4d3c2b1a0'", "bearer_token=****"),
            ("-----BEGIN ENCRYPTED PRIVATE KEY-----", "private_key_block=****"),
            ("-----BEGIN PGP PRIVATE KEY BLOCK-----", "private_key_block=****"),
            ("\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44 = hunter2hunter2", "password=****"),
            ("password\uff1a hunter2hunter2", "password=****"),
            ('{"password": "hunter2hunter2"}', "password=****"),
            ("DB_PASSWORD=hunter2hunter2", "DB_PASSWORD=****"),
        ],
    )
    def test_credential_format_is_flagged_once_with_name_only(self, text, evidence):
        flags = leakage_flags(text)
        assert [f.evidence for f in flags] == [evidence]
        assert all(f.code == "CREDENTIAL" for f in flags)

    @pytest.mark.parametrize(
        "separator", [".", "/", "\u2013", "\n", "\r\n", "\u00a0", "\t", "\uff0d", "\u2212"],
    )
    def test_card_with_any_separator_is_flagged(self, separator):
        d = self.CARD_DIGITS
        text = f"card {separator.join([d[0:4], d[4:8], d[8:12], d[12:16]])} today"
        flags = leakage_flags(text)
        assert [f.evidence for f in flags] == ["************1111"]

    def test_fullwidth_card_digits_are_flagged(self):
        text = "".join(chr(ord(c) + 0xFEE0) for c in self.CARD_DIGITS)
        assert [f.code for f in leakage_flags(text)] == ["CARD_NUMBER"]

    def test_offset_points_into_the_text_as_given(self):
        text = "\ufb01le \u200bx password\uff1a hunter2hunter2"
        (flag,) = leakage_flags(text)
        assert text[flag.offset:].startswith("password")

    @pytest.mark.parametrize(
        "text",
        [
            "The bearer of this letter is a colleague.",
            "Bearer tokens expire after one hour.",
            "authorization: needed beforehand from the manager",
            "Use tokenizer = BertTokenizerFast here.",
            "max_tokens = 4096",
            "Version 10.0.19041.1234 was installed on 2026/11/25.",
            "Call +1.555.123.4567 or 555-123-4567.",
            "IP 192.168.100.200 and 10.0.0.1",
            "Order #2026-11-25-0001 shipped.",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----",
            "card 4111.1111.1111.1112",
        ],
    )
    def test_near_misses_are_not_flagged(self, text):
        assert leakage_flags(text) == []

    @pytest.mark.parametrize("profile", ["default", "ops", "exec", "legal"])
    @pytest.mark.parametrize(
        "text",
        [
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "4111.1111.1111.1111",
            "4111\n1111\n1111\n1111",
            "\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44 = hunter2hunter2",
        ],
    )
    def test_sieve_holds_each_format_on_every_profile(self, profile, text):
        assert ZeroTrustSieve(profile).run(text).verdict is Verdict.BREACH
