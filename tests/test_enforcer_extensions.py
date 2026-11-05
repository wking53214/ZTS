"""ZTS using Enforcer 0.1.1's additions, and still working with 0.1.0.

Skips when the installed Enforcer predates them, unless ZTS_REQUIRE_ENFORCER_011=1.
"""

from __future__ import annotations

import os

import pytest

from release_kit import build, enforcer, request, run

NEW = hasattr(enforcer.Enforcer, "describe")
if not NEW and os.environ.get("ZTS_REQUIRE_ENFORCER_011") == "1":
    raise RuntimeError("ZTS_REQUIRE_ENFORCER_011=1 but the installed Enforcer has no describe()")
needs_new = pytest.mark.skipif(not NEW, reason="needs Enforcer 0.1.1")


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


@needs_new
def test_an_aborted_release_keeps_its_enforcer_decision_record(tmp_path, mode):
    """Before 0.1.1 the decision was lost when the callback aborted after the grant was spent."""
    s = build(tmp_path)
    s.status.on_call = lambda: setattr(s.captured[-1], "payload_out", "changed in flight")
    r = run(s, mode, request(s))
    assert r.release_outcome == "failed_before_delivery" and r.reason_code == "ARTIFACT_CHANGED"
    d = r.authorization["decision"]
    assert d is not None and d["status"] == "ALLOW" and d["verifier_id"] == "tests/hmac-verifier"
    assert d["proof_sha256"] and d["evaluated_at"]


@needs_new
def test_a_failing_delivery_callback_keeps_the_decision_record_too(tmp_path, mode):
    class Boom:
        calls = []

        def __call__(self, output, signature):
            raise ConnectionResetError("dropped")

    s = build(tmp_path, sink=Boom())
    r = run(s, mode, request(s))
    assert r.release_outcome == "delivery_unknown"
    assert r.authorization["decision"]["status"] == "ALLOW"


@needs_new
def test_the_delivered_decision_record_is_unchanged_by_the_new_hook(tmp_path, mode):
    s = build(tmp_path)
    r = run(s, mode, request(s))
    assert r.release_outcome == "delivered" and r.authorization["decision"]["reason_code"] == "VERIFIED_ACTION_BOUND_GRANT"


@needs_new
def test_enforcer_describe_agrees_with_what_zts_probes(tmp_path):
    s = build(tmp_path)
    info = s.enforcer.describe()
    assert info["verifier_id"] == "tests/hmac-verifier" and info["revalidator_id"] == "tests/status-source"
    assert info["replay_store"]["kind"] == "sqlite" and info["replay_store"]["durable"] is True


def test_the_gate_reports_whether_it_can_use_on_allow(tmp_path):
    s = build(tmp_path)
    assert s.tower.release_gate._takes_on_allow() is NEW
