"""The optional identity-authentication hook. Fail closed; checked twice; never the grant."""

from __future__ import annotations

import time

import pytest

from release_kit import assert_not_released, build, make_identity, request, run
from zts import ReleaseState


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


def with_hook(tmp_path, hook):
    return build(tmp_path, identity_verifier=hook)


def test_an_authenticated_identity_releases_and_the_hook_sees_the_real_cns_identity(tmp_path, mode):
    seen = []
    s = with_hook(tmp_path, lambda identity: seen.append(identity) or True)
    assert run(s, mode, request(s)).release_outcome == ReleaseState.DELIVERED
    assert seen == [s.identity, s.identity], "checked before Enforcer and again just before delivery"


@pytest.mark.parametrize("answer", [False, None, "yes", 1, [], "true", 0])
def test_only_exactly_true_passes_and_a_no_never_reaches_the_grant_provider(tmp_path, mode, answer):
    s = with_hook(tmp_path, lambda identity: answer)
    r = run(s, mode, request(s))
    assert_not_released(s, r, "IDENTITY_NOT_AUTHENTICATED", outcome="denied")
    assert s.candidates == [] and s.status.calls == 0, "no grant requested, none spent"
    assert r.authorization["grant_state"] == "unspent"


def test_a_hook_that_raises_is_a_no(tmp_path, mode):
    def broken(identity):
        raise ConnectionError("identity provider down")

    s = with_hook(tmp_path, broken)
    assert_not_released(s, run(s, mode, request(s)), "IDENTITY_NOT_AUTHENTICATED", outcome="denied")


def test_a_hook_that_hangs_is_bounded_by_the_gate_timeout(tmp_path, mode):
    s = build(tmp_path, gate_timeout=0.2, identity_verifier=lambda identity: time.sleep(3) or True)
    started = time.perf_counter()
    r = run(s, mode, request(s))
    assert time.perf_counter() - started < 1.5
    assert_not_released(s, r, "IDENTITY_NOT_AUTHENTICATED", outcome="denied")


def test_an_identity_that_stops_being_authenticated_mid_release_stops_delivery(tmp_path, mode):
    state = {"calls": 0}

    def first_yes_then_no(identity):
        state["calls"] += 1
        return state["calls"] == 1  # the session is revoked after the first check

    s = with_hook(tmp_path, first_yes_then_no)
    r = run(s, mode, request(s))
    assert_not_released(s, r, "IDENTITY_NOT_AUTHENTICATED", outcome="failed_before_delivery")
    assert r.authorization["authorized"] is True and r.authorization["action_started"] is False


def test_the_hook_decides_per_identity(tmp_path, mode):
    allowed = make_identity(subject_id="subject-1")
    s = with_hook(tmp_path, lambda identity: identity.subject_id == allowed.subject_id)
    assert run(s, mode, request(s)).released
    other = make_identity(subject_id="subject-2")
    from zts.cns import CNSDock
    r = run(s, mode, request(s, "rel-2", identity=other, artifact=CNSDock().to_zts_artifact(other)))
    assert r.released is False and r.reason_code in ("IDENTITY_NOT_AUTHENTICATED", "SCOPE_MISMATCH")


def test_a_hook_that_is_not_callable_is_refused_at_construction(tmp_path):
    from zts import EnforcerReleaseGate
    s = build(tmp_path)
    with pytest.raises(TypeError):
        EnforcerReleaseGate(s.enforcer, policy_version="p", identity_verifier="not callable")


@pytest.mark.parametrize("name", ["timeout", "identity_verifier"])
def test_the_gates_bound_and_identity_check_cannot_be_removed_after_construction(tmp_path, name):
    s = with_hook(tmp_path, lambda identity: True)
    before = getattr(s.tower.release_gate, name)
    with pytest.raises(AttributeError):
        setattr(s.tower.release_gate, name, None)
    assert getattr(s.tower.release_gate, name) is before
