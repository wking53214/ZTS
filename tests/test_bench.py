"""The benchmark must measure what it claims to measure."""

from __future__ import annotations

from zts.bench import run_bench, format_bench
from zts.gates import FAIL_FAST_ORDER


def test_reject_mode_executes_fewer_gates_under_fail_fast():
    results = run_bench(iterations=500, mode="reject")
    assert results["fail_fast"].gates_per_payload < results["worst_case"].gates_per_payload


def test_repair_mode_executes_every_gate_regardless_of_order():
    results = run_bench(iterations=500, mode="repair")
    total = len(FAIL_FAST_ORDER)
    assert results["fail_fast"].gates_per_payload == total
    assert results["worst_case"].gates_per_payload == total


def test_output_is_labelled_with_the_mode():
    assert "mode=reject" in format_bench(run_bench(iterations=200, mode="reject"))
    assert "mode=repair" in format_bench(run_bench(iterations=200, mode="repair"))


def test_repair_mode_output_states_the_historical_finding():
    text = format_bench(run_bench(iterations=200, mode="repair"))
    assert "214ms" in text
