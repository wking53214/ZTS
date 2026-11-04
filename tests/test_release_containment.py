"""Containment: what code can and cannot do to a production tower from inside the process.

What is claimed, precisely. An ordinary assignment cannot turn a production tower into
a development one, and a tower whose controls were forced past that still refuses to
fall back to a legacy release. What is NOT claimed: code that can run in this process
can read the sink out of the tower's constructor arguments, call it, or call anything
else. Against that the only control is process isolation, which is a deployment
requirement documented in docs/RELEASE_BOUNDARY.md and cannot be tested here.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from release_kit import TEXT, build, request
from zts import ArchitectsProtocol, DeterministicIntegrityTower, ReleaseMode, ReleaseState

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "zts"
CONTROLS = ["tap", "release_gate", "release_sink", "require_enforcer", "delivery_confirmer", "ledger", "profile"]


@pytest.mark.parametrize("name", CONTROLS)
def test_release_controls_cannot_be_reassigned_after_construction(tmp_path, name):
    s = build(tmp_path)
    before = getattr(s.tower, name)
    with pytest.raises(AttributeError):
        setattr(s.tower, name, None)
    assert getattr(s.tower, name) is before


def test_the_baseline_bypass_of_swapping_in_a_legacy_capstone_now_fails(tmp_path):
    """Probe P1 on main 53ddb10: two assignments released without consulting Enforcer."""
    s = build(tmp_path)
    with pytest.raises(AttributeError):
        s.tower.release_gate = None
    with pytest.raises(AttributeError):
        s.tower.tap = ArchitectsProtocol(ReleaseMode.AUTO)
    r = s.tower.enforce(TEXT, release=request(s))
    assert r.release_outcome == ReleaseState.DELIVERED and s.status.calls == 1


def test_even_a_forced_swap_cannot_make_a_production_tower_release_through_the_legacy_path(tmp_path):
    s = build(tmp_path)
    object.__setattr__(s.tower, "release_gate", None)  # code that bypasses __setattr__
    object.__setattr__(s.tower, "tap", ArchitectsProtocol(ReleaseMode.AUTO))
    r = s.tower.enforce(TEXT, release=request(s))
    assert r.released is False and r.output == "" and r.signature == {}
    assert r.reason_code == "PRODUCTION_INVARIANT_VIOLATED" and r.release_outcome == ReleaseState.DENIED
    assert s.sink.calls == [] and s.status.calls == 0
    assert tap_last(s).extra["reason_code"] == "PRODUCTION_INVARIANT_VIOLATED"


def tap_last(s):
    return [e for e in s.tower.ledger.entries if e.layer == "TAP"][-1]


def test_a_non_production_tower_can_still_be_a_development_tower(tmp_path):
    t = DeterministicIntegrityTower("ops", capstone=ArchitectsProtocol(ReleaseMode.AUTO), persist_ledger_key=False)
    assert t.enforce(TEXT).release_outcome == ReleaseState.RELEASED_LEGACY


def test_non_control_attributes_remain_assignable(tmp_path):
    s = build(tmp_path)
    s.tower.some_note = "ok"  # not a release control
    assert s.tower.some_note == "ok"


def _innermost_function_of_each_call(tree, attr):
    """Map each ``.attr(...)`` call to the innermost function that contains it."""
    found = []

    def visit(node, owner):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef):
                visit(child, child.name)
                continue
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == attr:
                found.append(owner)
            visit(child, owner)

    visit(tree, "<module>")
    return found


def test_the_release_sink_is_called_from_exactly_the_guarded_and_the_legacy_paths():
    tree = ast.parse((PACKAGE / "tower.py").read_text(encoding="utf-8"))
    assert sorted(_innermost_function_of_each_call(tree, "release_sink")) == ["_decide_legacy", "deliver"]


def test_every_module_that_can_build_a_released_result_is_the_tower():
    found = {}
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "released" and isinstance(node.value, ast.Constant) \
                    and node.value.value is True:
                found.setdefault(path.name, []).append(node.lineno)
    assert list(found) == ["tower.py"] and len(found["tower.py"]) == 2, found


def test_no_module_other_than_the_tower_calls_the_gate_or_the_legacy_capstone():
    for path in PACKAGE.rglob("*.py"):
        if path.name in ("tower.py", "release.py", "capstone.py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr != "authorize", (path.name, node.lineno)
                # Enforcer's guarded call is execute(envelope, proof, action). A SQLite
                # cursor's execute(sql) is not it, so only the three-argument shape counts.
                assert not (node.func.attr == "execute" and len(node.args) >= 3), (path.name, node.lineno)
