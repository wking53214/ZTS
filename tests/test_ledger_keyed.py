"""Keyed ledger fingerprints: keyed, deterministic, matchable, and chain still verifies."""

from __future__ import annotations

from zts.ledger import ValLedger
from zts.tower import DeterministicIntegrityTower

CLEAN = "Disk utilization reached 94% on node 3 at 02:17 UTC."
CARD = "4111 1111 1111 1111"


class TestKeyedFingerprint:
    def test_same_payload_and_key_gives_same_fingerprint(self):
        a = ValLedger(key=b"k" * 32).log("X", "PASS", payload=CLEAN)
        b = ValLedger(key=b"k" * 32).log("X", "PASS", payload=CLEAN)
        assert a.payload_digest == b.payload_digest

    def test_different_keys_give_different_fingerprints(self):
        a = ValLedger(key=b"k" * 32).log("X", "PASS", payload=CARD)
        b = ValLedger(key=b"j" * 32).log("X", "PASS", payload=CARD)
        assert a.payload_digest != b.payload_digest

    def test_fingerprint_is_not_plain_sha256_of_the_payload(self):
        import hashlib

        entry = ValLedger(key=b"k" * 32).log("X", "PASS", payload=CARD)
        assert entry.payload_digest != hashlib.sha256(CARD.encode()).hexdigest()

    def test_payload_matches_only_the_right_text(self):
        ledger = ValLedger(key=b"k" * 32)
        entry = ledger.log("X", "PASS", payload=CLEAN)
        assert ledger.payload_matches(entry, CLEAN)
        assert not ledger.payload_matches(entry, CLEAN + " ")

    def test_payload_match_fails_under_another_key(self):
        entry = ValLedger(key=b"k" * 32).log("X", "PASS", payload=CLEAN)
        assert not ValLedger(key=b"j" * 32).payload_matches(entry, CLEAN)


class TestChainUnchanged:
    def test_chain_verifies_without_the_key(self):
        ledger = ValLedger(key=b"k" * 32)
        ledger.log("A", "PASS", payload=CLEAN)
        ledger.log("B", "PASS", payload=CARD)
        assert ledger.verify() == (True, "chain intact")

    def test_tampered_entry_still_breaks_the_chain(self):
        ledger = ValLedger(key=b"k" * 32)
        ledger.log("A", "PASS", payload=CLEAN)
        ledger.log("B", "PASS", payload=CLEAN)
        ledger._entries[0].detail = "edited"
        assert not ledger.verify()[0]


class TestTowerUsesItsKey:
    def test_tower_ledger_fingerprint_matches_released_output(self):
        key = b"t" * 32
        tower = DeterministicIntegrityTower("ops", hmac_key=key)
        result = tower.enforce(CLEAN)
        assert result.released
        last = tower.ledger.entries[-1]
        assert tower.ledger.payload_matches(last, result.output)

