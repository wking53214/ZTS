"""The durable ledger: persistence, recovery, tamper detection, and multi-process writes.

Needs neither CNS nor Enforcer. The anchor used here is the real file-backed
anchor. Whether such an anchor is *independent* of the ledger's writer is a
deployment fact these tests cannot establish: in them both files sit in one
temporary directory, so they show the mechanism, not the independence.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from zts.ledger import GENESIS, LedgerAnchorError, ValLedger
from zts.ledger_store import (
    FileLedgerAnchor,
    FileLedgerStore,
    LedgerCorruptionError,
    LedgerStoreError,
)

KEY = b"k" * 32


def open_ledger(path, anchor=None):
    return ValLedger(key=KEY, store=FileLedgerStore(path), anchor=anchor)


def fill(ledger, n=5):
    for i in range(n):
        ledger.log("T", "OK", f"entry {i}", f"payload {i}", n=i)
    return ledger


# ------------------------------------------------------------ persistence


def test_entries_survive_a_restart_and_the_chain_still_verifies(tmp_path):
    path = tmp_path / "ledger.jsonl"
    first = fill(open_ledger(path), 6)
    head, digests = first.head, [e.digest for e in first.entries]
    assert first.durable is True

    restarted = open_ledger(path)
    assert [e.digest for e in restarted.entries] == digests
    assert restarted.head == head and restarted.verify() == (True, "chain intact")
    assert restarted.recovery.entries == 6 and restarted.recovery.torn_tail_bytes == 0

    restarted.log("T", "OK", "after restart")
    assert restarted.entries[-1].previous == head and restarted.entries[-1].sequence == 6
    assert open_ledger(path).verify()[0]


def test_an_in_memory_ledger_says_it_is_not_durable():
    ledger = ValLedger(key=KEY)
    assert ledger.durable is False and ledger.anchored is False


def test_every_append_is_fsynced_before_it_is_acknowledged(tmp_path, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd))[1])
    ledger = open_ledger(tmp_path / "ledger.jsonl")
    before = len(synced)
    ledger.log("T", "OK", "x")
    assert len(synced) > before


def test_the_file_is_owner_only_and_a_world_writable_file_is_refused(tmp_path):
    path = tmp_path / "ledger.jsonl"
    open_ledger(path).log("T", "OK", "x")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    os.chmod(path, 0o666)
    with pytest.raises(LedgerStoreError):
        FileLedgerStore(path)


def test_a_failed_write_is_not_acknowledged_and_leaves_the_chain_usable(tmp_path, monkeypatch):
    ledger = fill(open_ledger(tmp_path / "ledger.jsonl"), 3)
    head = ledger.head

    def refuse(entry):
        raise LedgerStoreError("disk full")

    monkeypatch.setattr(ledger._store, "append", refuse)
    with pytest.raises(LedgerStoreError):
        ledger.log("T", "OK", "lost")
    assert len(ledger) == 3 and ledger.head == head
    monkeypatch.undo()
    ledger.log("T", "OK", "ok again")
    assert len(ledger) == 4 and ledger.verify()[0]


# ------------------------------------------------------------ recovery


def test_an_unacknowledged_torn_tail_is_removed_reported_and_kept_for_inspection(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = fill(open_ledger(path), 4)
    with open(path, "ab") as handle:
        handle.write(b'{"sequence": 4, "layer": "T", "sta')  # crash mid-write, no newline

    recovered = open_ledger(path)
    assert len(recovered) == 4 and recovered.verify()[0]
    assert recovered.recovery.torn_tail_bytes > 0
    assert open(recovered.recovery.torn_copy, "rb").read().startswith(b'{"sequence": 4')
    assert recovered.head == ledger.head
    recovered.log("T", "OK", "continues")
    assert open_ledger(path).verify()[0]


def test_repair_can_be_refused(tmp_path):
    path = tmp_path / "ledger.jsonl"
    fill(open_ledger(path), 2)
    with open(path, "ab") as handle:
        handle.write(b"{unfinished")
    with pytest.raises(LedgerCorruptionError):
        ValLedger(key=KEY, store=FileLedgerStore(path, repair_torn_tail=False))


def lines(path):
    return open(path, "rb").read().splitlines(keepends=True)


def test_a_mutated_line_refuses_to_open_and_is_not_repaired(tmp_path):
    path = tmp_path / "ledger.jsonl"
    fill(open_ledger(path), 4)
    rows = lines(path)
    doc = json.loads(rows[1])
    doc["detail"] = "edited"
    rows[1] = (json.dumps(doc, sort_keys=True) + "\n").encode()
    open(path, "wb").write(b"".join(rows))
    with pytest.raises(LedgerCorruptionError, match="digest mismatch"):
        open_ledger(path)
    assert b"edited" in open(path, "rb").read(), "corruption must be left in place, not healed"


def test_a_deleted_middle_line_refuses_to_open(tmp_path):
    path = tmp_path / "ledger.jsonl"
    fill(open_ledger(path), 5)
    rows = lines(path)
    del rows[2]
    open(path, "wb").write(b"".join(rows))
    with pytest.raises(LedgerCorruptionError):
        open_ledger(path)


def test_a_garbage_line_refuses_to_open(tmp_path):
    path = tmp_path / "ledger.jsonl"
    fill(open_ledger(path), 3)
    open(path, "ab").write(b"this is not json\n")
    with pytest.raises(LedgerCorruptionError):
        open_ledger(path)


# --------------------------------- truncation, rollback and replacement against the anchor


def anchored(tmp_path, n=6):
    anchor = FileLedgerAnchor(tmp_path / "anchor.jsonl")
    ledger = fill(open_ledger(tmp_path / "ledger.jsonl", anchor), n)
    return ledger, anchor


def test_a_clean_anchored_ledger_verifies_across_a_restart(tmp_path):
    ledger, anchor = anchored(tmp_path)
    assert ledger.verify_anchored()[0]
    restarted = open_ledger(tmp_path / "ledger.jsonl", FileLedgerAnchor(tmp_path / "anchor.jsonl"))
    assert restarted.verify_anchored()[0]


@pytest.mark.parametrize("dropped", [1, 2, 4])
def test_truncating_the_tail_of_the_file_is_caught_by_the_anchor(tmp_path, dropped):
    ledger, anchor = anchored(tmp_path)
    path = tmp_path / "ledger.jsonl"
    rows = lines(path)
    open(path, "wb").write(b"".join(rows[:-dropped]))
    victim = open_ledger(path, FileLedgerAnchor(tmp_path / "anchor.jsonl"))
    assert victim.verify()[0] is True, "a walk alone sees nothing wrong with a shortened chain"
    ok, reason = victim.verify_anchored()
    assert ok is False and "truncated" in reason


def test_rolling_the_whole_file_back_to_an_older_copy_is_caught(tmp_path):
    ledger, anchor = anchored(tmp_path, 3)
    path = tmp_path / "ledger.jsonl"
    old = open(path, "rb").read()
    fill(ledger, 4)
    open(path, "wb").write(old)
    ok, reason = open_ledger(path, FileLedgerAnchor(tmp_path / "anchor.jsonl")).verify_anchored()
    assert ok is False and "truncated" in reason


def test_rewriting_the_tail_into_another_valid_chain_is_caught(tmp_path):
    ledger, anchor = anchored(tmp_path, 5)
    path = tmp_path / "ledger.jsonl"
    keep = lines(path)[:4]
    forged = ValLedger(key=KEY)
    for row in keep:  # rebuild the first four, then a different fifth
        forged._entries.append(__import__("zts.ledger_store", fromlist=["x"]).entry_from_line(row))
    forged.log("T", "OK", "a different fifth entry")
    open(path, "wb").write(b"".join(keep) + (json.dumps(
        __import__("dataclasses").asdict(forged.entries[-1]), sort_keys=True) + "\n").encode())
    victim = open_ledger(path, FileLedgerAnchor(tmp_path / "anchor.jsonl"))
    assert victim.verify()[0] is True
    ok, reason = victim.verify_anchored()
    assert ok is False and "replaced" in reason


def test_an_anchor_that_is_missing_or_empty_for_a_nonempty_ledger_fails(tmp_path):
    ledger, anchor = anchored(tmp_path)
    open(tmp_path / "anchor.jsonl", "wb").close()
    ok, reason = open_ledger(tmp_path / "ledger.jsonl", FileLedgerAnchor(tmp_path / "anchor.jsonl")).verify_anchored()
    assert ok is False and reason == "anchor holds no head"


def test_a_corrupt_anchor_fails_verification_instead_of_passing(tmp_path):
    ledger, anchor = anchored(tmp_path)
    open(tmp_path / "anchor.jsonl", "ab").write(b"garbage\n")
    assert ledger.verify_anchored() == (False, "anchor unavailable")


def test_a_torn_anchor_line_was_never_acknowledged_and_is_ignored(tmp_path):
    ledger, anchor = anchored(tmp_path)
    open(tmp_path / "anchor.jsonl", "ab").write(b'{"head": "abc", "sequ')
    assert ledger.verify_anchored()[0] is True


def test_the_anchor_one_ahead_after_an_interrupted_write_is_reported_not_healed(tmp_path, monkeypatch):
    ledger, anchor = anchored(tmp_path, 3)

    def die(entry):
        raise LedgerStoreError("crash after the anchor published")

    monkeypatch.setattr(ledger._store, "append", die)
    with pytest.raises(LedgerStoreError):
        ledger.log("T", "OK", "interrupted")
    monkeypatch.undo()
    ok, reason = ledger.verify_anchored()
    assert ok is False and "one entry ahead" in reason


def test_an_anchor_that_refuses_stops_the_durable_write(tmp_path):
    class Down:
        def publish(self, sequence, head):
            raise OSError("down")

        def latest(self):
            return None

    ledger = ValLedger(key=KEY, store=FileLedgerStore(tmp_path / "ledger.jsonl"), anchor=Down())
    with pytest.raises(LedgerAnchorError):
        ledger.log("T", "OK", "x")
    assert len(ledger) == 0 and open(tmp_path / "ledger.jsonl", "rb").read() == b""


# ------------------------------------------------------------ concurrency


def test_threads_sharing_one_durable_ledger_cannot_fork_it(tmp_path):
    ledger = open_ledger(tmp_path / "ledger.jsonl")
    n_threads, per = 8, 25
    barrier = threading.Barrier(n_threads)

    def work(i):
        barrier.wait()
        for j in range(per):
            ledger.log("T", "OK", f"{i}-{j}")

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        list(pool.map(work, range(n_threads)))
    assert len(ledger) == n_threads * per
    assert open_ledger(tmp_path / "ledger.jsonl").verify() == (True, "chain intact")


def test_two_ledger_objects_on_one_file_keep_one_chain(tmp_path):
    path = tmp_path / "ledger.jsonl"
    a, b = open_ledger(path), open_ledger(path)
    for i in range(10):
        (a if i % 2 else b).log("T", "OK", f"w{i}")
    assert [e.sequence for e in open_ledger(path).entries] == list(range(10))
    assert open_ledger(path).verify()[0]


def _writer(path, tag, count):
    ledger = ValLedger(key=KEY, store=FileLedgerStore(path))
    for i in range(count):
        ledger.log("P", "OK", f"{tag}-{i}")


def test_separate_processes_writing_one_ledger_keep_one_chain(tmp_path):
    path = tmp_path / "ledger.jsonl"
    open_ledger(path).log("T", "OK", "genesis entry")
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(path, f"p{n}", 20)) for n in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    final = open_ledger(path)
    assert len(final) == 1 + 4 * 20
    assert [e.sequence for e in final.entries] == list(range(len(final)))
    assert final.verify() == (True, "chain intact")
    assert final.entries[0].previous == GENESIS


def test_an_entry_spliced_in_from_another_chain_is_caught_by_the_link_check(tmp_path):
    """Right sequence number, valid self-digest, wrong predecessor: only the link check sees it."""
    path = tmp_path / "ledger.jsonl"
    fill(open_ledger(path), 4)
    other = ValLedger(key=KEY)
    for i in range(4):
        other.log("T", "OK", f"other chain {i}")
    rows = lines(path)
    import dataclasses
    rows[2] = (json.dumps(dataclasses.asdict(other.entries[2]), sort_keys=True) + "\n").encode()
    open(path, "wb").write(b"".join(rows))
    with pytest.raises(LedgerCorruptionError, match="broken link"):
        open_ledger(path)


def test_a_running_ledger_refuses_to_append_after_the_file_was_truncated_under_it(tmp_path):
    """Found in final inspection: it used to accept the append and corrupt the chain."""
    path = tmp_path / "ledger.jsonl"
    ledger = fill(open_ledger(path), 5)
    rows = lines(path)
    open(path, "wb").write(b"".join(rows[:2]))
    with pytest.raises(LedgerCorruptionError, match="truncated"):
        ledger.log("T", "OK", "after truncation")
    assert len(lines(path)) == 2, "nothing was appended to the truncated file"
