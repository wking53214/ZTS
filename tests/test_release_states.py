"""The release states, and independent confirmation of delivery.

Each state is a different fact and none may be collapsed into another. These tests
make every state reachable through the real tower and check the facts that define
it: whether the callback ran, whether the output was returned, whether the grant is
spent, whether the receiving side confirmed, and whether the audit record is durable.
"""

from __future__ import annotations

import time

import pytest

from release_kit import (
    TEXT,
    build,
    request,
    run,
    tap_entries,
)
from zts import ReleaseState
from zts.ledger import ValLedger


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


# ------------------------------------------------------------ the success state


def test_delivered_means_released_confirmed_by_the_receiver_and_durably_recorded(tmp_path, mode):
    s = build(tmp_path)
    r = run(s, mode, request(s))
    assert r.release_outcome == ReleaseState.DELIVERED
    assert r.released and r.output == TEXT and r.delivery_verified and r.audit_durable
    assert s.tower.ledger.durable
    assert tap_entries(s)[-1].extra["delivery_verified"] is True
    assert tap_entries(s)[-1].extra["ledger_durable"] is True


# ------------------------------------------------------ independent confirmation


def test_a_sink_that_returns_without_delivering_is_not_a_success(tmp_path, mode):
    """The old behavior: the callback returned, so ZTS said released. Now the receiver is asked."""
    ran = []

    def lying_sink(output, signature):
        ran.append(output)  # returns normally and delivers nothing the receiver can see

    s = build(tmp_path, sink=lying_sink)
    r = run(s, mode, request(s))
    assert ran == [TEXT], "the callback did run"
    assert r.released is False and r.output == "" and r.signature == {}
    assert r.release_outcome == ReleaseState.DELIVERY_UNKNOWN
    assert r.reason_code == "DELIVERY_UNCONFIRMED" and r.delivery_verified is False
    assert tap_entries(s)[-1].status == "UNCONFIRMED"
    extra = tap_entries(s)[-1].extra
    assert extra["released"] is False, "the ledger must not say released next to an unconfirmed delivery"
    assert extra["callback_completed"] is True and extra["delivery_verified"] is False


@pytest.mark.parametrize("answer", [False, None, "yes", 1, [], "true"])
def test_only_exactly_true_from_the_confirmer_counts(tmp_path, mode, answer):
    s = build(tmp_path, confirmer=lambda release_id, digest: answer)
    r = run(s, mode, request(s))
    assert r.released is False and r.release_outcome == ReleaseState.DELIVERY_UNKNOWN


def test_a_confirmer_that_raises_means_delivery_is_unknown(tmp_path, mode):
    def down(release_id, digest):
        raise ConnectionError("receiver unreachable")

    s = build(tmp_path, confirmer=down)
    r = run(s, mode, request(s))
    assert r.released is False and r.release_outcome == ReleaseState.DELIVERY_UNKNOWN
    assert r.reason_code == "DELIVERY_UNCONFIRMED"


def test_a_confirmer_that_hangs_is_bounded_by_the_timeout(tmp_path, mode):
    s = build(tmp_path, confirmer=lambda release_id, digest: time.sleep(5) or True, confirm_timeout=0.2)
    started = time.perf_counter()
    r = run(s, mode, request(s))
    assert time.perf_counter() - started < 2.0
    assert r.released is False and r.release_outcome == ReleaseState.DELIVERY_UNKNOWN


def test_the_confirmer_is_asked_about_this_release_and_this_artifact(tmp_path, mode):
    asked = []

    def spy(release_id, digest):
        asked.append((release_id, digest))
        return True

    s = build(tmp_path, confirmer=spy)
    run(s, mode, request(s, "rel-77"))
    import hashlib
    assert asked == [("rel-77", hashlib.sha256(TEXT.encode()).hexdigest())]


def test_an_unknown_delivery_cannot_be_retried_into_a_second_one(tmp_path, mode):
    s = build(tmp_path, confirmer=lambda release_id, digest: False)
    first = run(s, mode, request(s))
    assert first.release_outcome == ReleaseState.DELIVERY_UNKNOWN
    retry = run(s, mode, request(s))
    assert retry.reason_code == "GRANT_REPLAYED" and retry.released is False
    assert len(s.sink.calls) == 1, "the retry must not deliver a second time"


# ------------------------------------------------------ the weaker success states


def test_without_a_confirmer_the_best_state_is_delivered_unverified(tmp_path, mode):
    s = build(tmp_path, confirmer=None)
    r = run(s, mode, request(s))
    assert r.released is True and r.release_outcome == ReleaseState.DELIVERED_UNVERIFIED
    assert r.delivery_verified is False and r.audit_durable is True


def test_an_in_memory_ledger_can_never_yield_delivered(tmp_path, mode):
    s = build(tmp_path, ledger=ValLedger(key=b"l" * 32))
    r = run(s, mode, request(s))
    assert r.released is True and r.delivery_verified is True
    assert r.release_outcome == ReleaseState.DELIVERED_AUDIT_INCOMPLETE and r.audit_durable is False


# ------------------------------------------------------ every state, reached for real


def test_each_state_is_reachable_and_distinct(tmp_path):
    seen = {}

    (tmp_path / "a").mkdir()
    s = build(tmp_path / "a")
    s.status.mode = "revoked"
    seen["denied"] = s.tower.enforce(TEXT, release=request(s)).release_outcome

    (tmp_path / "b").mkdir()
    s = build(tmp_path / "b")
    seen["not_attempted"] = s.tower.enforce(TEXT, release=None).release_outcome

    (tmp_path / "c").mkdir()
    s = build(tmp_path / "c")
    s.status.on_call = lambda: setattr(s.captured[-1], "payload_out", "changed")
    seen["failed_before_delivery"] = s.tower.enforce(TEXT, release=request(s)).release_outcome

    (tmp_path / "d").mkdir()
    s = build(tmp_path / "d", confirmer=lambda r, d: False)
    seen["delivery_unknown"] = s.tower.enforce(TEXT, release=request(s)).release_outcome

    (tmp_path / "e").mkdir()
    s = build(tmp_path / "e", ledger=ValLedger(key=b"l" * 32))
    seen["delivered_audit_incomplete"] = s.tower.enforce(TEXT, release=request(s)).release_outcome

    (tmp_path / "f").mkdir()
    s = build(tmp_path / "f", confirmer=None)
    seen["delivered_unverified"] = s.tower.enforce(TEXT, release=request(s)).release_outcome

    (tmp_path / "g").mkdir()
    s = build(tmp_path / "g")
    seen["delivered"] = s.tower.enforce(TEXT, release=request(s)).release_outcome

    assert seen == {name: name for name in seen}, seen
    assert len(set(seen.values())) == 7


def test_released_is_true_for_exactly_the_delivered_states():
    assert ReleaseState.DELIVERED_STATES == {"delivered", "delivered_unverified", "delivered_audit_incomplete"}
