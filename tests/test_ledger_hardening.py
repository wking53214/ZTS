"""Ledger: concurrent writes, anchoring and truncation. No CNS or Enforcer needed.

What these do and do not show. They show that two threads cannot fork the chain,
that a truncated or replaced chain is caught against an anchor the writer does
not control, and that an anchor refusing a head stops the write. They do not show
tamper-proofing, durability or external anchoring in production: the ledger is
in memory and no real anchor ships.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from zts.ledger import GENESIS, LedgerAnchorError, ValLedger


class MemoryAnchor:
    """A test anchor that stands outside the ledger object. Not an operational anchor."""

    def __init__(self):
        self.heads: list[tuple[int, str]] = []

    def publish(self, sequence, head):
        self.heads.append((sequence, head))

    def latest(self):
        return self.heads[-1] if self.heads else None


def test_concurrent_writers_cannot_fork_the_chain():
    ledger = ValLedger(key=b"k" * 32)
    n_threads, per_thread = 16, 40
    barrier = threading.Barrier(n_threads)

    def writer(i):
        barrier.wait()
        for j in range(per_thread):
            ledger.log("T", "OK", f"{i}-{j}", f"p{i}-{j}")

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        list(pool.map(writer, range(n_threads)))

    entries = ledger.entries
    assert len(entries) == n_threads * per_thread
    assert [e.sequence for e in entries] == list(range(len(entries)))
    assert len({e.previous for e in entries}) == len(entries), "two entries share a predecessor"
    assert ledger.verify() == (True, "chain intact")


def test_an_expected_head_catches_truncation_that_a_walk_alone_cannot():
    ledger = ValLedger(key=b"k" * 32)
    for i in range(5):
        ledger.log("T", "OK", str(i))
    head = ledger.head
    del ledger._entries[-2:]
    assert ledger.verify()[0] is True, "a walk alone sees nothing wrong with a shortened chain"
    assert ledger.verify(expected_head=head) == (False, "head mismatch: chain truncated or replaced")


def test_the_anchor_catches_truncation_and_replacement():
    anchor = MemoryAnchor()
    ledger = ValLedger(key=b"k" * 32, anchor=anchor)
    for i in range(5):
        ledger.log("T", "OK", str(i))
    assert ledger.verify_anchored()[0] is True
    assert anchor.latest() == (4, ledger.head)

    kept = list(ledger._entries)
    del ledger._entries[-1:]
    ok, reason = ledger.verify_anchored()
    assert ok is False and "truncated" in reason

    # Replace the tail with a different, internally consistent entry.
    forged = ValLedger(key=b"k" * 32)
    for i in range(4):
        forged.log("T", "OK", str(i))
    forged.log("T", "OK", "something else")
    ledger._entries[:] = forged.entries
    ok, reason = ledger.verify_anchored()
    assert ok is False and "replaced" in reason
    ledger._entries[:] = kept
    assert ledger.verify_anchored()[0] is True


def test_an_anchor_that_refuses_a_head_stops_the_write():
    class Refusing(MemoryAnchor):
        def publish(self, sequence, head):
            raise OSError("anchor down")

    ledger = ValLedger(key=b"k" * 32, anchor=Refusing())
    with pytest.raises(LedgerAnchorError):
        ledger.log("T", "OK", "x")
    assert len(ledger) == 0 and ledger.head == GENESIS


def test_the_ledger_never_holds_an_entry_the_anchor_has_not_seen():
    anchor = MemoryAnchor()
    ledger = ValLedger(key=b"k" * 32, anchor=anchor)
    for i in range(3):
        ledger.log("T", "OK", str(i))
    assert [(e.sequence, e.digest) for e in ledger.entries] == anchor.heads


def test_verify_anchored_fails_closed_without_an_anchor_or_a_head():
    assert ValLedger(key=b"k" * 32).verify_anchored() == (False, "no anchor configured")
    anchor = MemoryAnchor()
    ledger = ValLedger(key=b"k" * 32, anchor=anchor)
    assert ledger.verify_anchored()[0] is True  # empty ledger, empty anchor
    ledger.log("T", "OK", "x")
    anchor.heads.clear()
    assert ledger.verify_anchored() == (False, "anchor holds no head")


def test_an_unreachable_anchor_fails_verification_rather_than_passing():
    class Broken(MemoryAnchor):
        def latest(self):
            raise OSError("down")

    ledger = ValLedger(key=b"k" * 32, anchor=Broken())
    ledger.log("T", "OK", "x")
    assert ledger.verify_anchored() == (False, "anchor unavailable")


def test_an_edit_is_still_caught_by_the_walk():
    ledger = ValLedger(key=b"k" * 32)
    for i in range(3):
        ledger.log("T", "OK", str(i))
    ledger._entries[1].detail = "edited"
    assert ledger.verify()[0] is False
