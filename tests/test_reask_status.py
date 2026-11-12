"""The status source is asked a second time just before delivery (Enforcer 0.1.2 and later).

Enforcer asks once, inside `authorize`. Between that answer and the delivery callback come the replay
consume, the audit write and the callback chain, so a revocation that lands in that gap used to be
invisible. `reask_status=True` asks again with the same verifier and status source. It narrows the
window; it cannot close it, and one test says so.
"""

from __future__ import annotations

import os
import time

import pytest

from release_kit import TEXT, build, enforcer, request, run, static_grant, assert_not_released
from zts import EnforcerReleaseGate, ReleaseReason

NEW = hasattr(enforcer.Enforcer, "verifier")
if not NEW and os.environ.get("ZTS_REQUIRE_ENFORCER_012") == "1":
    raise RuntimeError("ZTS_REQUIRE_ENFORCER_012=1 but the installed Enforcer exposes no adapters")
needs_accessors = pytest.mark.skipif(not NEW, reason="needs Enforcer 0.1.2 or later")


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


class RevokeDuringConsume:
    """A replay store whose consume is the moment the revocation lands: after Enforcer's status check."""

    def __init__(self, inner, status):
        self.inner, self.status = inner, status

    def consume(self, issuer_id, nonce, request_id, **kwargs):
        self.status.mode = "revoked"
        return self.inner.consume(issuer_id, nonce, request_id, **kwargs)

    def describe(self):
        return self.inner.describe()


@needs_accessors
def test_off_by_default_the_status_source_is_asked_once(tmp_path, mode):
    s = build(tmp_path)
    assert s.tower.release_gate.reask_status is False
    assert run(s, mode, request(s, proof=static_grant(s), provider=None)).released
    assert s.status.calls == 1


@needs_accessors
def test_on_it_is_asked_twice_and_a_current_grant_is_delivered_once(tmp_path, mode):
    s = build(tmp_path, reask_status=True)
    assert s.tower.release_gate.reask_status is True
    result = run(s, mode, request(s, proof=static_grant(s), provider=None))
    assert result.released and len(s.sink.calls) == 1
    assert s.status.calls == 2


@needs_accessors
def test_a_revocation_that_lands_after_the_first_answer_blocks_delivery(tmp_path, mode):
    s = build(tmp_path, reask_status=True)
    s.store = RevokeDuringConsume(s.store, s.status)
    s.enforcer._replay_store = s.store  # the test double sits where the real store was
    result = run(s, mode, request(s, proof=static_grant(s), provider=None))
    assert_not_released(s, result, ReleaseReason.REVOKED_BEFORE_DELIVERY, outcome="failed_before_delivery")
    assert result.authorization["authorized"] is True and result.authorization["action_started"] is False
    assert s.status.calls == 2


@needs_accessors
def test_known_limit_without_the_second_ask_the_same_revocation_is_delivered(tmp_path):
    """The window this feature narrows. Asserted so that a change to it is noticed, not as a claim it is fine."""
    s = build(tmp_path)
    s.enforcer._replay_store = RevokeDuringConsume(s.store, s.status)
    assert run(s, "sync", request(s, proof=static_grant(s), provider=None)).released


@needs_accessors
@pytest.mark.parametrize("second,reason", [
    ("revoked", ReleaseReason.REVOKED_BEFORE_DELIVERY),
    ("unavailable", ReleaseReason.STATUS_RECHECK_FAILED),
    ("unknown", ReleaseReason.STATUS_RECHECK_FAILED),
    ("not-status", ReleaseReason.STATUS_RECHECK_FAILED),
])
def test_any_second_answer_that_is_not_current_blocks_delivery(tmp_path, mode, second, reason):
    s = build(tmp_path, reask_status=True)
    s.status.on_call = lambda: setattr(s.status, "mode", second) if s.status.calls == 2 else None
    result = run(s, mode, request(s, proof=static_grant(s), provider=None))
    assert_not_released(s, result, reason, outcome="failed_before_delivery")


@needs_accessors
@pytest.mark.parametrize("field", ["policy", "envelope_sha256"])
def test_a_second_answer_for_another_envelope_or_policy_blocks_delivery(tmp_path, field):
    s = build(tmp_path, reask_status=True)
    s.status.on_call = lambda: setattr(s.status, field, "f" * 64 if field == "envelope_sha256" else "other") \
        if s.status.calls == 2 else None
    result = run(s, "sync", request(s, proof=static_grant(s), provider=None))
    assert_not_released(s, result, ReleaseReason.STATUS_RECHECK_FAILED, outcome="failed_before_delivery")


@needs_accessors
def test_a_second_answer_with_naive_or_backwards_times_blocks_delivery(tmp_path):
    from datetime import datetime
    s = build(tmp_path, reask_status=True)
    real = s.status.revalidate

    def second_naive(envelope, claims):
        status = real(envelope, claims)
        if s.status.calls == 2:
            return enforcer.AuthorizationStatus(
                status=status.status, envelope_sha256=status.envelope_sha256, policy_version=status.policy_version,
                checked_at=datetime(2030, 1, 1), valid_until=status.valid_until)
        return status
    s.status.revalidate = second_naive
    s.enforcer._revalidator = s.status
    result = run(s, "sync", request(s, proof=static_grant(s), provider=None))
    assert_not_released(s, result, ReleaseReason.STATUS_RECHECK_FAILED, outcome="failed_before_delivery")


@needs_accessors
def test_a_second_ask_that_outlives_the_gate_timeout_cannot_deliver(tmp_path):
    s = build(tmp_path, reask_status=True, gate_timeout=0.4)
    s.status.on_call = lambda: time.sleep(1.0) if s.status.calls == 2 else None
    result = run(s, "sync", request(s, proof=static_grant(s), provider=None))
    time.sleep(1.2)  # let the abandoned thread finish; it must still not deliver
    assert result.released is False and s.sink.calls == []
    assert result.reason_code == ReleaseReason.ENFORCER_TIMEOUT


@needs_accessors
def test_the_grant_is_spent_by_a_refused_second_ask(tmp_path):
    s = build(tmp_path, reask_status=True)
    s.status.on_call = lambda: setattr(s.status, "mode", "revoked") if s.status.calls == 2 else None
    grant = static_grant(s)
    first = run(s, "sync", request(s, proof=grant, provider=None))
    assert first.released is False
    s.status.on_call, s.status.mode = None, "current"
    again = run(s, "sync", request(s, proof=grant, provider=None))
    assert again.reason_code == "GRANT_REPLAYED" and s.sink.calls == []


def test_an_enforcer_that_hides_its_adapters_cannot_be_asked_to_reask():
    class Plain:
        def execute(self, *a, **k):
            raise AssertionError("not used")

    with pytest.raises(ValueError, match="0.1.2 or later"):
        EnforcerReleaseGate(Plain(), policy_version="p1", reask_status=True)


@needs_accessors
def test_the_setting_cannot_be_changed_on_a_built_gate(tmp_path):
    gate = build(tmp_path, reask_status=True).tower.release_gate
    with pytest.raises(AttributeError):
        gate.reask_status = False
    assert gate.reask_status is True


@needs_accessors
def test_the_new_reasons_are_classified_so_neither_is_an_unclassified_denial():
    from zts.ops import AVAILABILITY_REASONS, SECURITY_REASONS
    assert ReleaseReason.REVOKED_BEFORE_DELIVERY in SECURITY_REASONS
    assert ReleaseReason.STATUS_RECHECK_FAILED in AVAILABILITY_REASONS
