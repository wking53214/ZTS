"""Cancellation, timeouts, shutdown and concurrency at the release boundary.

The rule under test: cancelling, timing out or retrying must never produce a second
consequential release, and must never let a release happen after the caller was told
it had not. Real tower, real Enforcer, real CNS, real durable ledger; the only
stand-ins are the two test trust adapters described in release_kit.py.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from release_kit import ActionEnvelope, Sink, TEXT, build, mint, request, run, tap_entries
from zts import ReleaseState, TowerClosedError


class SlowSink(Sink):
    def __init__(self, delay):
        super().__init__()
        self.delay = delay
        self.began = threading.Event()

    def __call__(self, output, signature):
        self.began.set()
        time.sleep(self.delay)
        super().__call__(output, signature)


def slow_provider(stack, delay, **overrides):
    def provide(candidate):
        stack.candidates.append(candidate)
        time.sleep(delay)
        return mint(ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes), stack.clock, **overrides)
    return provide


class HeldSink(Sink):
    """A delivery that signals `began` when it starts and finishes only once `go` is set."""

    def __init__(self):
        super().__init__()
        self.began, self.go = threading.Event(), threading.Event()

    def __call__(self, output, signature):
        self.began.set()
        self.go.wait(10)
        super().__call__(output, signature)


def held_provider(stack, began, go):
    """A grant source that signals `began` when the fetch starts and answers only once `go` is set."""
    def provide(candidate):
        stack.candidates.append(candidate)
        began.set()
        go.wait(10)
        return mint(ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes), stack.clock)
    return provide


async def gen(prompt):
    return TEXT


async def slow_generator(prompt):
    """A generator slower than the old fixed cancel delays (0.1 s and 0.2 s) to hand over its text."""
    await asyncio.sleep(0.3)
    return TEXT


async def cancel_once(stack, began, go, req, generator=None):
    """Cancel only after a held step has begun, and let that step finish only after the cancel landed.

    The held step is revalidation (`hold_revalidation`), the grant fetch (`held_provider`) or delivery
    (`HeldSink`). No wall-clock guess: `began` is set by the held step when it starts, so a slow machine
    cannot make the cancel arrive before the release is attempted (which wrote nothing to the ledger and
    failed CI with IndexError). The held step then waits on `go`. Delivering a cancel takes the
    cancelled task one turn of the event loop, where the tower sets its cancel flag; `go` is released
    only after several more turns, so the flag is set before the held step returns.
    """
    task = asyncio.create_task(stack.tower.run("p", generator or gen, release=req))
    assert await asyncio.to_thread(began.wait, 10), "revalidation never started"
    task.cancel()
    for _ in range(10):
        await asyncio.sleep(0)
    go.set()
    try:
        await task
    except asyncio.CancelledError:
        return "cancelled"
    return task.result()


def hold_revalidation(stack):
    began, go = threading.Event(), threading.Event()

    def on_call():
        began.set()
        go.wait(10)

    stack.status.on_call = on_call
    return began, go


# -------------------------------------------------------- the loop is not blocked


@pytest.mark.parametrize("where", ["provider", "sink", "status-source"])
def test_a_slow_dependency_does_not_freeze_the_event_loop(tmp_path, where):
    sink = SlowSink(0.5) if where == "sink" else None
    s = build(tmp_path, sink=sink) if sink else build(tmp_path)
    req = request(s, provider=slow_provider(s, 0.5)) if where == "provider" else request(s)
    if where == "status-source":
        s.status.on_call = lambda: time.sleep(0.5)

    async def main():
        ticks = []

        async def ticker():
            for _ in range(14):
                ticks.append(time.perf_counter())
                await asyncio.sleep(0.05)

        t = asyncio.create_task(ticker())
        result = await s.tower.run("p", gen, release=req)
        await t
        return result, max(b - a for a, b in zip(ticks, ticks[1:], strict=False))

    result, worst_gap = asyncio.run(main())
    assert result.release_outcome == ReleaseState.DELIVERED
    assert worst_gap < 0.3, f"the loop stalled for {worst_gap:.2f}s"


# -------------------------------------------------------------- cancellation


@pytest.mark.parametrize("generator", [gen, slow_generator], ids=["prompt", "slow-to-start"])
def test_cancelling_while_the_grant_is_being_fetched_spends_nothing_and_delivers_nothing(tmp_path, generator):
    # The cancel lands while the grant fetch is held open, never on a fixed delay. The slow-to-start case is the
    # regression: with the old fixed 0.1 s delay the cancel landed during generation, before any release attempt,
    # and the ledger had no entry to check (IndexError).
    s = build(tmp_path)
    began, go = threading.Event(), threading.Event()
    req = request(s, provider=held_provider(s, began, go))
    outcome = asyncio.run(cancel_once(s, began, go, req, generator=generator))
    assert outcome == "cancelled"
    assert s.sink.calls == []
    last = tap_entries(s)[-1]
    assert last.status == "HELD" and last.extra["reason_code"] == "RELEASE_CANCELLED"
    assert last.extra["grant_state"] == "unspent" and last.extra["authorized"] is False
    # The cancelled attempt spent nothing, so an honest retry of the same release works.
    retry = run(s, "sync", request(s))
    assert retry.release_outcome == ReleaseState.DELIVERED and len(s.sink.calls) == 1


def test_cancelling_during_revalidation_stops_before_delivery_and_the_grant_is_spent(tmp_path):
    s = build(tmp_path)
    began, go = hold_revalidation(s)
    outcome = asyncio.run(cancel_once(s, began, go, request(s)))
    assert outcome == "cancelled"
    assert s.sink.calls == [], "cancelled before the callback: nothing may be delivered"
    last = tap_entries(s)[-1]
    assert last.extra["reason_code"] == "RELEASE_CANCELLED" and last.extra["authorized"] is True
    assert last.extra["grant_state"] == "spent" and last.extra["action_started"] is False
    s.status.on_call = None
    retry = run(s, "sync", request(s))
    assert retry.reason_code == "GRANT_REPLAYED" and retry.released is False
    assert s.sink.calls == []


def test_cancelling_during_revalidation_holds_when_the_run_is_slow_to_get_there(tmp_path):
    # Regression for the CI flake: a run slower than the old fixed 0.1 s cancel delay to reach revalidation.
    # With that delay the cancel landed before any release attempt and the ledger had no entry to check.
    s = build(tmp_path)
    began, go = hold_revalidation(s)

    async def slow_to_start(prompt):
        await asyncio.sleep(0.3)
        return TEXT

    outcome = asyncio.run(cancel_once(s, began, go, request(s), generator=slow_to_start))
    assert outcome == "cancelled" and s.sink.calls == []
    last = tap_entries(s)[-1]
    assert last.extra["reason_code"] == "RELEASE_CANCELLED" and last.extra["grant_state"] == "spent"
    assert last.extra["authorized"] is True and last.extra["action_started"] is False


@pytest.mark.parametrize("generator", [gen, slow_generator], ids=["prompt", "slow-to-start"])
def test_cancelling_during_delivery_cannot_be_undone_and_cannot_be_repeated(tmp_path, generator):
    # The cancel lands while delivery is held open, never on a fixed delay. The slow-to-start case is the
    # regression: with the old fixed 0.2 s delay the cancel landed during generation and nothing was delivered.
    sink = HeldSink()
    s = build(tmp_path, sink=sink)
    outcome = asyncio.run(cancel_once(s, sink.began, sink.go, request(s), generator=generator))
    assert outcome == "cancelled", "the caller is told the outcome was not returned"
    assert len(sink.calls) == 1, "delivery had begun and ran to completion"
    final = tap_entries(s)[-1]
    assert final.status == "RELEASED", "the ledger, not the cancelled task, holds the outcome"
    assert final.extra["delivery_verified"] is True
    retry = run(s, "sync", request(s))
    assert retry.reason_code == "GRANT_REPLAYED" and len(sink.calls) == 1


def test_a_run_cancelled_before_the_release_starts_never_attempts_it(tmp_path):
    s = build(tmp_path)

    async def slow_generator(prompt):
        await asyncio.sleep(1)
        return TEXT

    async def main():
        task = asyncio.create_task(s.tower.run("p", slow_generator, release=request(s)))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert s.sink.calls == [] and s.candidates == [] and s.status.calls == 0


# ------------------------------------------------------------------- timeouts


def test_a_hung_grant_provider_is_bounded_and_spends_nothing(tmp_path, mode="sync"):
    # No wall-clock bound: the provider blocks on an event, so "bounded" means the call
    # returned while the provider had still not finished. A slow CI machine cannot flip that.
    s = build(tmp_path, gate_timeout=0.2)
    let_go, finished = threading.Event(), threading.Event()

    def hung(candidate):
        s.candidates.append(candidate)
        let_go.wait(30)
        try:
            return mint(ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes), s.clock)
        finally:
            finished.set()

    r = run(s, mode, request(s, provider=hung))
    assert not finished.is_set(), "the gate waited for the hung provider instead of timing out"
    assert r.released is False and r.reason_code == "PROOF_PROVIDER_TIMEOUT"
    assert r.release_outcome == ReleaseState.DENIED and r.authorization["grant_state"] == "unspent"
    assert s.sink.calls == []
    let_go.set()  # the abandoned provider finally returns; it must change nothing
    assert finished.wait(10)
    assert s.sink.calls == [] and s.status.calls == 0


def test_a_hung_status_source_times_out_and_a_late_allow_cannot_deliver(tmp_path):
    """The hazard in any timeout: the abandoned call wakes up later and finishes the job."""
    s = build(tmp_path, gate_timeout=0.2)
    s.status.on_call = lambda: time.sleep(0.8)
    r = run(s, "sync", request(s))
    assert r.released is False and r.reason_code == "ENFORCER_TIMEOUT"
    assert r.release_outcome == ReleaseState.DENIED
    assert r.authorization["grant_state"] == "unknown", "the late call may still spend the grant"
    assert s.sink.calls == []
    time.sleep(1.2)  # Enforcer's abandoned call now allows, consumes the grant and reaches our callback
    assert s.sink.calls == [], "an abandoned release must refuse to deliver"
    assert [e.status for e in tap_entries(s)].count("RELEASING") == 0
    s.status.on_call = None
    retry = run(s, "sync", request(s))
    assert retry.reason_code == "GRANT_REPLAYED", "the late call spent the grant, so a retry is replay"
    assert s.sink.calls == []


def test_a_timeout_that_fires_during_delivery_waits_for_the_delivery_instead_of_abandoning_it(tmp_path):
    sink = SlowSink(0.6)
    s = build(tmp_path, sink=sink, gate_timeout=0.2)
    r = run(s, "sync", request(s))
    assert len(sink.calls) == 1, "delivery had begun, so it was waited for"
    assert r.release_outcome == ReleaseState.DELIVERED and r.released


def test_gate_timeouts_must_be_positive_numbers(tmp_path):
    from zts import EnforcerReleaseGate
    for bad in (0, -1, "5"):
        with pytest.raises(ValueError):
            EnforcerReleaseGate(object_with_execute(), policy_version="p", timeout=bad)


def object_with_execute():
    class E:
        def execute(self, *a):
            raise AssertionError

    return E()


# ---------------------------------------------------- state changed after authorization


def test_the_policy_version_changing_after_authorization_aborts_delivery(tmp_path, mode="sync"):
    s = build(tmp_path)
    gate = s.tower.release_gate
    s.status.on_call = lambda: setattr(gate, "_policy_version", "policy-v2")  # in-process tamper
    r = run(s, mode, request(s))
    assert r.released is False and r.reason_code == "POLICY_CHANGED"
    assert r.release_outcome == ReleaseState.FAILED_BEFORE_DELIVERY and s.sink.calls == []


def test_the_subject_changing_after_authorization_aborts_delivery(tmp_path, mode="sync"):
    s = build(tmp_path)
    s.status.on_call = lambda: object.__setattr__(s.identity, "subject_id", "someone-else")  # frozen; forced
    r = run(s, mode, request(s))
    assert r.released is False and r.reason_code == "CNS_VERIFICATION_FAILED"
    assert r.release_outcome == ReleaseState.FAILED_BEFORE_DELIVERY and s.sink.calls == []


def test_the_scope_and_operation_of_a_request_cannot_be_edited_after_it_is_made(tmp_path):
    import dataclasses
    s = build(tmp_path)
    req = request(s)
    for field_name, value in (("scope", "elsewhere"), ("operation", "zts.export"), ("release_id", "other")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(req, field_name, value)


# -------------------------------------------------------------------- shutdown


def test_close_waits_for_a_release_in_flight_and_then_refuses_new_ones(tmp_path):
    sink = SlowSink(0.5)
    s = build(tmp_path, sink=sink)
    results = []
    worker = threading.Thread(target=lambda: results.append(s.tower.enforce(TEXT, release=request(s))))
    worker.start()
    assert sink.began.wait(2)
    assert s.tower.inflight == 1
    assert s.tower.close(timeout=5) is True, "close drains the release that was mid-delivery"
    worker.join()
    assert results[0].release_outcome == ReleaseState.DELIVERED and len(sink.calls) == 1
    with pytest.raises(TowerClosedError):
        s.tower.enforce(TEXT, release=request(s, "rel-after"))
    with pytest.raises(TowerClosedError):
        asyncio.run(s.tower.run("p", gen, release=request(s, "rel-after")))
    assert len(sink.calls) == 1 and s.status.calls == 1
    assert s.tower.close(timeout=1) is True, "closing twice is harmless"


def test_a_call_that_passed_the_front_door_as_shutdown_began_is_not_released(tmp_path):
    """The race: the closing flag flips between the entry check and the release decision."""
    s = build(tmp_path)
    original = s.tower.zts.run

    def flip_closing(*args, **kwargs):
        result = original(*args, **kwargs)
        s.tower._closing = True
        return result

    s.tower.zts.run = flip_closing
    r = s.tower.enforce(TEXT, release=request(s))
    assert r.released is False and r.reason_code == "SHUTTING_DOWN"
    assert r.release_outcome == ReleaseState.NOT_ATTEMPTED
    assert s.sink.calls == [] and s.candidates == [] and s.status.calls == 0


def test_close_reports_when_something_would_not_drain(tmp_path):
    sink = SlowSink(1.0)
    s = build(tmp_path, sink=sink)
    worker = threading.Thread(target=lambda: s.tower.enforce(TEXT, release=request(s)))
    worker.start()
    assert sink.began.wait(2)
    assert s.tower.close(timeout=0.1) is False
    worker.join()


# ------------------------------------------------------------------ concurrency


def test_many_distinct_concurrent_releases_all_deliver_once_and_the_ledger_stays_one_chain(tmp_path):
    s = build(tmp_path)

    async def main():
        return await asyncio.gather(
            *(s.tower.run("p", gen, release=request(s, f"rel-{i}")) for i in range(12))
        )

    results = asyncio.run(main())
    assert all(r.release_outcome == ReleaseState.DELIVERED for r in results)
    assert len(s.sink.calls) == 12
    ledger = s.tower.ledger
    assert ledger.verify() == (True, "chain intact")
    assert [e.status for e in tap_entries(s)].count("RELEASED") == 12
    assert {e.extra["release_id"] for e in tap_entries(s) if e.status == "RELEASED"} == {f"rel-{i}" for i in range(12)}


# ------------------------------------------- the gate on its own, without the tower


def test_a_gate_called_with_a_cancelled_release_never_consults_an_authority(tmp_path):
    s = build(tmp_path)
    delivered = []
    r = s.tower.release_gate.release(
        request(s, proof=b"x", provider=None), TEXT, profile="ops",
        action=lambda payload: delivered.append(payload), cancelled=lambda: True,
    )
    assert r.released is False and r.reason_code == "RELEASE_CANCELLED"
    assert delivered == [] and s.status.calls == 0 and r.grant_state == "unspent"


def test_a_cancel_arriving_while_enforcer_decides_stops_the_callback_directly(tmp_path):
    s = build(tmp_path)
    flag = {"cancel": False}
    s.status.on_call = lambda: flag.update(cancel=True)
    delivered = []
    r = s.tower.release_gate.release(
        request(s), TEXT, profile="ops",
        action=lambda payload: delivered.append(payload), cancelled=lambda: flag["cancel"],
    )
    assert r.released is False and r.reason_code == "RELEASE_CANCELLED"
    assert delivered == [] and r.authorized is True and r.grant_state == "spent"
