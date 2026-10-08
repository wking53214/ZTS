"""Telemetry dashboard: outcome counts, rolling window, and tower wiring."""

from __future__ import annotations

import pytest

from zts.capstone import ArchitectsProtocol, ReleaseMode
from zts.dashboard import HELD_BY_RELEASE, HELD_BY_SIEVE, RELEASED, TelemetryDashboard
from zts.tower import DeterministicIntegrityTower

CLEAN = "Disk utilization reached 94% on node 3 at 02:17 UTC."
DIRTY = "As an AI, I think we may be wrong."


class TestCounting:
    def test_empty_snapshot_is_all_zero(self):
        snap = TelemetryDashboard().snapshot()
        assert snap["total_runs"] == 0
        assert snap["release_rate"] == 0.0
        assert snap["avg_attempts"] == 0.0
        assert snap["avg_latency_ms"] == 0.0
        assert snap["p95_latency_ms"] == 0.0
        assert snap["breaches_by_gate"] == {}

    def test_released_run_is_counted(self):
        dash = TelemetryDashboard()
        DeterministicIntegrityTower("ops", dashboard=dash).enforce(CLEAN)
        snap = dash.snapshot()
        assert snap["total_runs"] == 1
        assert snap["released"] == 1
        assert snap["release_rate"] == 1.0

    def test_sieve_breach_is_held_and_gate_is_recorded(self):
        dash = TelemetryDashboard()
        result = DeterministicIntegrityTower("ops", dashboard=dash).enforce(DIRTY)
        assert not result.released
        snap = dash.snapshot()
        assert snap["held_by_sieve"] == 1
        assert snap["held_by_release"] == 0
        # One run, so each gate that fired is counted exactly once.
        assert snap["breaches_by_gate"]
        assert all(count == 1 for count in snap["breaches_by_gate"].values())

    def test_release_hold_is_distinct_from_sieve_breach(self):
        dash = TelemetryDashboard()
        sealed = ArchitectsProtocol(ReleaseMode.SEALED)
        tower = DeterministicIntegrityTower("ops", capstone=sealed, dashboard=dash)
        result = tower.enforce(CLEAN)
        assert not result.released
        snap = dash.snapshot()
        assert snap["held_by_release"] == 1
        assert snap["held_by_sieve"] == 0
        assert snap["breaches_by_gate"] == {}

    def test_average_attempts_for_single_pass_runs(self):
        dash = TelemetryDashboard()
        tower = DeterministicIntegrityTower("ops", dashboard=dash)
        tower.enforce(CLEAN)
        tower.enforce(CLEAN)
        assert dash.snapshot()["avg_attempts"] == 1.0


class TestWindow:
    def test_window_bounds_latency_samples_but_not_totals(self):
        dash = TelemetryDashboard(window=3)
        tower = DeterministicIntegrityTower("ops", dashboard=dash)
        for _ in range(5):
            tower.enforce(CLEAN)
        snap = dash.snapshot()
        assert snap["total_runs"] == 5
        assert snap["window_runs"] == 3

    def test_window_must_be_positive(self):
        with pytest.raises(ValueError):
            TelemetryDashboard(window=0)

    def test_p95_is_at_least_the_average(self):
        dash = TelemetryDashboard()
        tower = DeterministicIntegrityTower("ops", dashboard=dash)
        for _ in range(20):
            tower.enforce(CLEAN)
        snap = dash.snapshot()
        assert snap["p95_latency_ms"] >= snap["avg_latency_ms"]


class TestTowerWiring:
    def test_no_dashboard_by_default(self):
        assert DeterministicIntegrityTower("ops").dashboard is None

    def test_dashboard_never_changes_the_decision(self):
        plain = DeterministicIntegrityTower("ops", hmac_key=b"k" * 32)
        watched = DeterministicIntegrityTower(
            "ops", hmac_key=b"k" * 32, dashboard=TelemetryDashboard()
        )
        for text in (CLEAN, DIRTY):
            a = plain.enforce(text)
            b = watched.enforce(text)
            assert a.released == b.released
            assert a.output == b.output
            assert a.checksum == b.checksum

    def test_outcome_labels_are_stable(self):
        assert RELEASED == "released"
        assert HELD_BY_SIEVE == "held_by_sieve"
        assert HELD_BY_RELEASE == "held_by_release"
