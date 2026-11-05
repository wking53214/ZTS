"""The remaining adversarial cases, including the ones that are known limits and not blocks.

A test named ``known_limit`` asserts the behavior that exists, so that a change to it is
noticed. It is not a claim that the behavior is acceptable.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from release_kit import (
    OTHER_TEXT, TEXT, Sink, build, request, run, static_grant, tap_entries, enforcer,
    assert_not_released,
)
from zts import ReleaseState
from zts.ledger_store import LedgerCorruptionError
from zts.ledger import ValLedger
from zts.ledger_store import FileLedgerAnchor, FileLedgerStore


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


# ----------------------------------------------------------------- replay


def test_the_same_release_id_with_an_altered_artifact_is_still_a_replay(tmp_path, mode):
    s = build(tmp_path)
    assert run(s, mode, request(s, "rel-1")).released
    altered = run(s, mode, request(s, "rel-1", text=OTHER_TEXT), text=OTHER_TEXT)
    assert_not_released(s, altered, "GRANT_REPLAYED", outcome="denied", deliveries=1)


def test_several_writers_on_one_host_sharing_the_replay_file_release_exactly_once(tmp_path):
    """Two Enforcer instances, two towers, one replay database file: the cross-process case on one host."""
    from release_kit import Clock
    db = tmp_path / "shared-replay.db"
    clock = Clock()
    stacks = []
    for n in range(3):
        (tmp_path / f"w{n}").mkdir()
        stacks.append(build(tmp_path / f"w{n}", store=enforcer.SQLiteReplayStore(db), clock=clock))
    grant = static_grant(stacks[0])
    barrier = threading.Barrier(len(stacks) * 3)

    def attempt(stack):
        barrier.wait()
        return stack.tower.enforce(TEXT, release=request(stack, proof=grant, provider=None))

    with ThreadPoolExecutor(max_workers=len(stacks) * 3) as pool:
        results = list(pool.map(attempt, [st for st in stacks for _ in range(3)]))
    assert sum(r.released for r in results) == 1
    assert sum(len(st.sink.calls) for st in stacks) == 1
    assert all(r.reason_code == "GRANT_REPLAYED" for r in results if not r.released)


# ------------------------------------------------------------------ delivery


def test_a_partial_delivery_that_then_fails_is_reported_as_unknown_never_as_delivered(tmp_path, mode):
    class PartialSink(Sink):
        def __call__(self, output, signature):
            super().__call__(output[: len(output) // 2], signature)  # half of it arrives
            raise ConnectionResetError("connection dropped mid-transfer")

    sink = PartialSink()
    s = build(tmp_path, sink=sink)
    r = run(s, mode, request(s))
    assert r.released is False and r.output == "" and r.signature == {}
    assert r.release_outcome == ReleaseState.DELIVERY_UNKNOWN and r.reason_code == "RELEASE_ACTION_FAILED"
    assert len(sink.calls) == 1, "something did reach the receiver, which is why this is not 'denied'"
    assert tap_entries(s)[-1].status == "UNCONFIRMED"
    retry = run(s, mode, request(s))
    assert retry.reason_code == "GRANT_REPLAYED" and len(sink.calls) == 1


def test_an_exception_after_authorization_and_before_delivery_delivers_nothing(tmp_path, mode):
    s = build(tmp_path)
    s.status.on_call = lambda: setattr(s.captured[-1], "payload_out", "x")
    r = run(s, mode, request(s))
    assert r.release_outcome == ReleaseState.FAILED_BEFORE_DELIVERY and s.sink.calls == []


# --------------------------------------------------------------------- audit


def test_an_anchor_that_fails_exactly_at_the_release_decision_blocks_the_release(tmp_path, mode):
    (tmp_path / "probe").mkdir()
    probe = build(tmp_path / "probe")
    probe.tower.enforce(TEXT, release=request(probe))
    attempt_at = [e.status for e in probe.tower.ledger.entries].index("ATTEMPT")

    class FailsFrom:
        def __init__(self, sequence):
            self.sequence, self.heads = sequence, []

        def publish(self, sequence, head):
            if sequence >= self.sequence:
                raise OSError("anchor service down")
            self.heads.append((sequence, head))

        def latest(self):
            return self.heads[-1] if self.heads else None

    (tmp_path / "real").mkdir()
    anchor = FailsFrom(attempt_at)
    ledger = ValLedger(key=b"l" * 32, store=FileLedgerStore(tmp_path / "real" / "l.jsonl"), anchor=anchor)
    s = build(tmp_path / "real", ledger=ledger)
    r = run(s, mode, request(s))
    assert r.released is False and r.output == "" and r.signature == {}
    assert r.reason_code == "LEDGER_UNAVAILABLE" and r.release_outcome == ReleaseState.NOT_ATTEMPTED
    assert s.sink.calls == [] and s.candidates == [] and s.status.calls == 0, "no grant was requested or spent"


def test_a_durable_anchored_ledger_verifies_after_a_real_release_and_a_restart(tmp_path, mode):
    anchor_path, ledger_path = tmp_path / "anchor.jsonl", tmp_path / "ledger.jsonl"
    ledger = ValLedger(key=b"l" * 32, store=FileLedgerStore(ledger_path), anchor=FileLedgerAnchor(anchor_path))
    s = build(tmp_path, ledger=ledger)
    assert run(s, mode, request(s)).release_outcome == ReleaseState.DELIVERED
    assert ledger.verify_anchored()[0]

    reopened = ValLedger(key=b"l" * 32, store=FileLedgerStore(ledger_path), anchor=FileLedgerAnchor(anchor_path))
    assert reopened.verify_anchored()[0]
    final = [e for e in reopened.entries if e.layer == "TAP"][-1]
    assert final.status == "RELEASED" and final.extra["release_id"] == "rel-1"


def test_truncating_the_durable_ledger_after_a_release_is_detected(tmp_path, mode):
    anchor_path, ledger_path = tmp_path / "anchor.jsonl", tmp_path / "ledger.jsonl"
    ledger = ValLedger(key=b"l" * 32, store=FileLedgerStore(ledger_path), anchor=FileLedgerAnchor(anchor_path))
    s = build(tmp_path, ledger=ledger)
    run(s, mode, request(s))
    rows = open(ledger_path, "rb").read().splitlines(keepends=True)
    open(ledger_path, "wb").write(b"".join(rows[:-1]))  # remove the RELEASED record
    victim = ValLedger(key=b"l" * 32, store=FileLedgerStore(ledger_path), anchor=FileLedgerAnchor(anchor_path))
    assert victim.verify()[0] is True
    ok, reason = victim.verify_anchored()
    assert ok is False and "truncated" in reason


# --------------------------------------------------------------- known limits


def test_known_limit_authorization_revoked_after_enforcers_check_but_before_delivery_is_not_caught(tmp_path, mode):
    """The residual time-of-check/time-of-use window. Enforcer checks status once, inside its call.

    ZTS does not ask again, because asking again would mean re-implementing Enforcer's
    revalidation inside ZTS. The window is the time between Enforcer's last status check and the
    start of the delivery callback; it is bounded by the gate's timeout (Enforcer's freshness limit is checked
    once, before the grant is consumed, so it does not bound this), and it is not eliminated.
    """
    s = build(tmp_path)
    original = s.status.revalidate

    def current_then_revoked(envelope, claims):
        answer = original(envelope, claims)
        s.status.mode = "revoked"  # revoked immediately after this "current" answer
        return answer

    s.status.revalidate = current_then_revoked
    r = run(s, mode, request(s))
    assert r.release_outcome == ReleaseState.DELIVERED, "the revocation arrived too late to matter"
    assert s.status.calls == 1, "ZTS did not ask a second time"
    again = run(s, mode, request(s, "rel-2"))
    assert again.reason_code == "GRANT_REVOKED", "the next release does see it"


def test_known_limit_a_replay_store_that_is_in_memory_forgets_across_restart(tmp_path, mode):
    """Characterized in test_release_boundary; production validation refuses this store (test_ops)."""
    first = build(tmp_path, store=enforcer.SQLiteReplayStore(":memory:"))
    grant = static_grant(first)
    assert run(first, mode, request(first, proof=grant, provider=None)).released
    (tmp_path / "again").mkdir()
    restarted = build(tmp_path / "again", store=enforcer.SQLiteReplayStore(":memory:"), clock=first.clock)
    assert run(restarted, mode, request(restarted, proof=grant, provider=None)).released is True


def test_a_release_is_not_attempted_once_the_ledger_file_has_been_truncated(tmp_path):
    s = build(tmp_path)
    s.tower.enforce(TEXT, release=request(s, "rel-1"))
    path = tmp_path / "ledger.jsonl"
    rows = open(path, "rb").read().splitlines(keepends=True)
    open(path, "wb").write(b"".join(rows[:3]))
    with pytest.raises(LedgerCorruptionError):
        s.tower.enforce(TEXT, release=request(s, "rel-2"))
    assert len(s.sink.calls) == 1, "no second delivery after the audit trail was cut"
