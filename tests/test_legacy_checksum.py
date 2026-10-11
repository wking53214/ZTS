"""LEGACY verify-only path for pre-HMAC-SHA256 (SHA-384) checksums."""

import hashlib
import hmac

from zts.ledger import checksum, signature_block, verify_legacy_checksum

KEY = b"0123456789abcdef0123456789abcdef"


def _sha384(payload: str, key: bytes = KEY) -> str:
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha384).hexdigest()


def test_legacy_sha384_checksum_still_verifies():
    assert verify_legacy_checksum("released text", KEY, _sha384("released text"))


def test_legacy_check_refuses_a_tampered_payload():
    assert not verify_legacy_checksum("released text.", KEY, _sha384("released text"))


def test_legacy_check_refuses_another_key():
    other = b"fedcba9876543210fedcba9876543210"
    assert not verify_legacy_checksum("released text", KEY, _sha384("released text", other))


def test_new_releases_are_not_sha384():
    block = signature_block("payload", KEY, "test-key")
    assert block["algorithm"] == "hmac-sha256"
    assert block["value"] == checksum("payload", KEY)
    assert not verify_legacy_checksum("payload", KEY, block["value"])
