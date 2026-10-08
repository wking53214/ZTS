"""Ledger key file: created owner-only, reused across restarts, refused when exposed."""

from __future__ import annotations

import os
import stat

import pytest

from zts.ledger import LedgerKeyError, default_key_path, load_or_create_ledger_key
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

    def test_default_path_follows_xdg_config_home(self, isolated_key_directory):
        assert default_key_path() == isolated_key_directory / "zts" / "ledger.key"


class TestTowerDefaultsToKeyFile:
    def test_a_tower_creates_the_key_at_the_default_path(self, isolated_key_directory):
        DeterministicIntegrityTower("ops")
        path = default_key_path()
        assert path.exists()
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

    def test_fingerprints_still_match_after_a_restart(self):
        first = DeterministicIntegrityTower("ops")
        result = first.enforce(CLEAN)
        entry = first.ledger.entries[-1]

        restarted = DeterministicIntegrityTower("ops")
        assert restarted.ledger.payload_matches(entry, result.output)

    def test_ledger_key_does_not_depend_on_the_release_key(self):
        a = DeterministicIntegrityTower("ops", hmac_key=b"a" * 32)
        b = DeterministicIntegrityTower("ops", hmac_key=b"b" * 32)
        out_a = a.enforce(CLEAN)
        out_b = b.enforce(CLEAN)
        assert out_a.output == out_b.output == CLEAN
        assert a.ledger.entries[-1].payload_digest == b.ledger.entries[-1].payload_digest


class TestTowerWithoutPersistence:
    def test_fingerprints_do_not_survive_a_restart_without_persistence(self):
        first = DeterministicIntegrityTower("ops", persist_ledger_key=False)
        result = first.enforce(CLEAN)
        entry = first.ledger.entries[-1]

        restarted = DeterministicIntegrityTower("ops", persist_ledger_key=False)
        assert not restarted.ledger.payload_matches(entry, result.output)

    def test_no_key_file_is_created_without_persistence(self, isolated_key_directory):
        DeterministicIntegrityTower("ops", persist_ledger_key=False)
        assert not default_key_path().exists()

    def test_explicit_key_file_is_used_when_given(self, tmp_path):
        path = tmp_path / "custom.key"
        DeterministicIntegrityTower("ops", ledger_key_file=path)
        assert path.exists()
        assert not default_key_path().exists()
