"""Release signatures and ledger key IDs: HMAC-SHA256, with the key ID recorded."""

import hashlib
import hmac
import json

import pytest

from zts import DeterministicIntegrityTower
from zts.ledger import (
    GENESIS,
    SIGNATURE_ALGORITHM,
    LedgerEntry,
    ValLedger,
    checksum,
    signature_block,
)

KEY = b"0123456789abcdef0123456789abcdef"
CLEAN = "Latency fell 12% because batching landed."


def test_algorithm_is_hmac_sha256():
    assert SIGNATURE_ALGORITHM == "hmac-sha256"
    expected = hmac.new(KEY, CLEAN.encode(), hashlib.sha256).hexdigest()
    assert checksum(CLEAN, KEY) == expected


def test_signature_block_has_algorithm_key_id_and_value():
    block = signature_block(CLEAN, KEY, "prod-1")
    assert set(block) == {"algorithm", "key_id", "value"}
    assert block["algorithm"] == "hmac-sha256"
    assert block["key_id"] == "prod-1"
    assert block["value"] == checksum(CLEAN, KEY)


def test_signature_block_refuses_an_unnamed_key():
    with pytest.raises(ValueError, match="caller-named key_id"):
        signature_block(CLEAN, KEY, "")


def test_tower_with_a_key_needs_a_named_key_id():
    with pytest.raises(ValueError, match="caller-named key_id"):
        DeterministicIntegrityTower("ops", hmac_key=KEY)


def test_unconfigured_tower_labels_its_key_ephemeral():
    result = DeterministicIntegrityTower("ops").enforce(CLEAN)
    assert result.signature["key_id"].startswith("ephemeral-")


def test_released_result_carries_the_signature_block():
    tower = DeterministicIntegrityTower("ops", hmac_key=KEY, key_id="test-key")
    result = tower.enforce(CLEAN)
    assert result.released
    assert result.signature["algorithm"] == "hmac-sha256"
    assert result.signature["key_id"] == "test-key"
    assert result.checksum == result.signature["value"]
    assert result.checksum == checksum(result.output, KEY)


def test_refused_result_has_no_signature():
    result = DeterministicIntegrityTower("ops").enforce("I think this may work.")
    assert not result.released
    assert result.signature == {}
    assert result.checksum == ""


def test_ledger_entries_record_the_key_id():
    ledger = ValLedger(key=KEY, key_id="ledger-test")
    entry = ledger.log("LC", "PASS", "ok", CLEAN)
    assert entry.key_id == "ledger-test"
    assert ledger.verify()[0]


def test_entries_written_without_key_id_still_verify():
    """Digests of entries with no key_id must match the pre-key-ID formula."""
    entry = LedgerEntry(
        sequence=0,
        timestamp=1.0,
        layer="LC",
        status="PASS",
        detail="ok",
        payload_digest="ab" * 32,
        previous=GENESIS,
    )
    body = json.dumps(
        {
            "sequence": 0,
            "timestamp": 1.0,
            "layer": "LC",
            "status": "PASS",
            "detail": "ok",
            "payload_digest": "ab" * 32,
            "previous": GENESIS,
            "extra": {},
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    assert entry.compute_digest() == hashlib.sha256(body.encode()).hexdigest()


def test_changing_a_recorded_key_id_breaks_the_chain():
    ledger = ValLedger(key=KEY, key_id="ledger-test")
    ledger.log("LC", "PASS", "ok", CLEAN)
    assert ledger.verify()[0]
    next(iter(ledger)).key_id = "forged"  # iterating yields the stored entries
    ok, reason = ledger.verify()
    assert not ok and "digest mismatch" in reason
