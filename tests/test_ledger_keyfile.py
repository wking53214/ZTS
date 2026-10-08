"""Ledger key file: created owner-only, reused across restarts, refused when exposed."""

from __future__ import annotations

import os
import stat

import pytest

from zts.ledger import LedgerKeyError, load_or_create_ledger_key
from zts.tower import DeterministicIntegrityTower

CLEAN = "Disk utilization reached 94% on node 3 at 02:17 UTC."


class TestKeyFile:
    def test_first_use_creates_an_owner_only_file(self, tmp_path):
        path = tmp_path / "zts" / "ledger.key"
        key = load_or_create_ledger_key(path)
        assert len(key) == 32
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_later_calls_return_the_same_key(self, tmp_path):
        path = tmp_path / "ledger.key"
        assert load_or_create_ledger_key(path) == load_or_create_ledger_key(path)

    def test_refuses_a_file_readable_by_others(self, tmp_path):
        path = tmp_path / "ledger.key"
        path.write_bytes(os.urandom(32))
        os.chmod(path, 0o644)
        with pytest.raises(LedgerKeyError, match="readable by other users"):
            load_or_create_ledger_key(path)

    def test_refuses_a_file_with_the_wrong_length(self, tmp_path):
        path = tmp_path / "ledger.key"
        path.write_bytes(b"short")
        os.chmod(path, 0o600)
        with pytest.raises(LedgerKeyError, match="32-byte"):
            load_or_create_ledger_key(path)


class TestTowerWithKeyFile:
    def test_fingerprints_still_match_after_a_restart(self, tmp_path):
        path = tmp_path / "ledger.key"
        first = DeterministicIntegrityTower("ops", ledger_key_file=path)
        result = first.enforce(CLEAN)
        entry = first.ledger.entries[-1]

        restarted = DeterministicIntegrityTower("ops", ledger_key_file=path)
        assert restarted.ledger.payload_matches(entry, result.output)

    def test_without_a_key_file_fingerprints_do_not_survive_a_restart(self):
        first = DeterministicIntegrityTower("ops")
        result = first.enforce(CLEAN)
        entry = first.ledger.entries[-1]

        restarted = DeterministicIntegrityTower("ops")
        assert not restarted.ledger.payload_matches(entry, result.output)

    def test_ledger_key_is_separate_from_the_release_checksum_key(self, tmp_path):
        path = tmp_path / "ledger.key"
        tower = DeterministicIntegrityTower("ops", hmac_key=b"r" * 32, ledger_key_file=path)
        ledger_key = path.read_bytes()
        assert ledger_key != b"r" * 32
        assert tower.ledger._key == ledger_key
