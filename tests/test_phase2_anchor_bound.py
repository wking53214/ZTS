"""Phase 2 audit, package B: the unanchored tail is bounded, and receipts can leave the box.

The audit's finding: while the timestamp authority is unreachable, entries written after the last
stamped head can be deleted and `verify_anchored` still says the chain is intact. Now the tail has
a bound; past it, new releases are refused (nothing attempted, no grant spent, no entry written)
until the TSA stamps again.
"""

from __future__ import annotations

import time

import pytest

from release_kit import build, request, run
from tsa_kit import Tsa
from zts.anchor_tsa import Rfc3161Anchor, http_post
from zts.ledger import ValLedger
from zts.ledger_store import FileLedgerStore
from zts.ops import _probe_anchor

BOUND = 15  # a release writes 11 ledger entries; so one more release fits, a second does not


class Reachable:
    """A transport to the real (OpenSSL) TSA that can be cut and restored."""

    def __init__(self):
        self.up = True

    def __call__(self, url, body, timeout):
        if not self.up:
            raise OSError("network down")
        return http_post(url, body, timeout)


@pytest.fixture
def tsa(tmp_path):
    t = Tsa(tmp_path)
    yield t
    t.close()


def make(tsa, tmp_path, net=None, **kw):
    kw.setdefault("min_interval", 0)
    kw.setdefault("timeout", 2.0)
    anchor = Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "receipts.jsonl",
                           transport=net or Reachable(), **kw)
    ledger = ValLedger(key=b"l" * 32, store=FileLedgerStore(tmp_path / "ledger.jsonl"), anchor=anchor)
    return build(tmp_path, ledger=ledger), anchor, ledger


def release(s, n, mode="sync"):
    return run(s, mode, request(s, f"rel-{n}"))


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


def test_an_outage_stops_new_releases_once_the_unstamped_tail_passes_its_bound(tsa, tmp_path, mode):
    net = Reachable()
    s, anchor, ledger = make(tsa, tmp_path, net, max_unanchored_entries=BOUND, max_unanchored_age=None)
    first = release(s, 1, mode)
    per_release = len(ledger)
    assert first.audit_anchored and per_release <= BOUND < 2 * per_release, per_release

    net.up = False
    second, third = release(s, 2, mode), release(s, 3, mode)
    assert [second.release_outcome, third.release_outcome] == ["delivered", "delivered"]
    assert not second.audit_anchored and not third.audit_anchored, "reported as not anchored, never as anchored"

    before = len(ledger)
    refused = release(s, 4, mode)
    assert refused.release_outcome == "not_attempted" and refused.reason_code == "ANCHOR_BEHIND"
    assert refused.authorization.get("grant_state", "unspent") == "unspent"
    assert len(s.sink.calls) == 3, "nothing was delivered for the refused release"
    assert len(ledger) == before, "a refusal writes nothing, so the gap cannot keep growing"
    assert s.tower.metrics.snapshot()["availability_failures"] >= 1

    # The most an attacker with the ledger file can remove undetected is now bounded by the bound.
    ok, _ = ledger.verify_anchored()
    assert ok and (len(ledger) - per_release) <= 2 * per_release


def test_the_hold_lifts_by_itself_when_the_tsa_answers_again(tsa, tmp_path, mode):
    net = Reachable()
    s, anchor, ledger = make(tsa, tmp_path, net, max_unanchored_entries=BOUND, max_unanchored_age=None)
    release(s, 1, mode)
    net.up = False
    release(s, 2, mode), release(s, 3, mode)
    assert release(s, 4, mode).reason_code == "ANCHOR_BEHIND"

    net.up = True  # no operator action: the refused attempt itself asks the TSA
    again = release(s, 5, mode)
    assert again.release_outcome == "delivered" and again.audit_anchored
    assert ledger.verify_anchored()[0] is True
    assert anchor.latest()[0] == len(ledger) - 1, "everything written so far is covered by a timestamp"


def test_an_age_bound_also_holds_back_releases(tsa, tmp_path):
    net = Reachable()
    s, anchor, ledger = make(tsa, tmp_path, net, max_unanchored_entries=None, max_unanchored_age=0.4)
    release(s, 1)
    net.up = False
    assert release(s, 2).release_outcome == "delivered"
    time.sleep(0.6)
    held = release(s, 3)
    assert held.release_outcome == "not_attempted" and held.reason_code == "ANCHOR_BEHIND"


def test_a_backlog_found_at_restart_counts_from_the_start(tsa, tmp_path):
    net = Reachable()
    s, anchor, ledger = make(tsa, tmp_path, net, max_unanchored_entries=BOUND, max_unanchored_age=None)
    release(s, 1)
    net.up = False
    release(s, 2), release(s, 3)
    anchor.close()

    net2 = Reachable()
    net2.up = False
    anchor2 = Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "receipts.jsonl", transport=net2,
                            min_interval=0, timeout=2.0, max_unanchored_entries=BOUND, max_unanchored_age=None)
    reopened = ValLedger(key=b"l" * 32, store=FileLedgerStore(tmp_path / "ledger.jsonl"), anchor=anchor2)
    assert reopened.anchor_behind() == "entries", "a new process cannot start clean over an unstamped tail"
    net2.up = True
    assert reopened.anchor_behind() is None, "and it recovers when the TSA does"


def test_health_and_readiness_say_so(tsa, tmp_path):
    net = Reachable()
    s, anchor, ledger = make(tsa, tmp_path, net, max_unanchored_entries=BOUND, max_unanchored_age=None)
    release(s, 1)
    assert s.tower.health()["status"] == "ok"
    net.up = False
    release(s, 2), release(s, 3)
    health = s.tower.health()
    assert health["status"] == "degraded" and "anchor_backlog" in health["failed"]
    assert {c.name: c.status for c in _probe_anchor(ledger)}["anchor_backlog_bound"] == "PASS"


def test_an_anchor_with_no_bound_at_all_fails_readiness(tsa, tmp_path):
    s, anchor, ledger = make(tsa, tmp_path, max_unanchored_entries=None, max_unanchored_age=None)
    states = {c.name: c.status for c in _probe_anchor(ledger)}
    assert states["anchor_backlog_bound"] == "FAIL"


@pytest.mark.parametrize("kw", [{"max_unanchored_entries": 0}, {"max_unanchored_entries": True},
                                {"max_unanchored_entries": 1.5}, {"max_unanchored_age": 0},
                                {"max_unanchored_age": -1}, {"max_unanchored_age": True}, {"on_receipt": "not callable"}])
def test_unusable_bounds_and_hooks_are_refused_at_construction(tsa, tmp_path, kw):
    with pytest.raises((ValueError, TypeError)):
        Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "r.jsonl", **kw)


# ----------------------------------------------------------------- receipt export


def test_every_receipt_is_handed_to_the_export_hook_as_written(tsa, tmp_path):
    got = []
    s, anchor, ledger = make(tsa, tmp_path, on_receipt=got.append)
    release(s, 1), release(s, 2)
    stored = anchor.receipts()
    assert got == stored and len(got) >= 2
    assert {"gen_time", "head", "sequence", "token"} == set(got[0])
    got[0]["head"] = "tampered"  # the hook got a copy: editing it changes nothing here
    assert anchor.receipts()[0]["head"] != "tampered"
    assert len(anchor.verify_all()) == len(stored), "the exported copy matches tokens that verify"


def test_a_failing_export_never_undoes_a_release_and_is_visible_until_it_recovers(tsa, tmp_path):
    state = {"fail": True, "got": []}

    def hook(receipt):
        if state["fail"]:
            raise RuntimeError("sink unreachable")
        state["got"].append(receipt)
    s, anchor, ledger = make(tsa, tmp_path, on_receipt=hook)
    r = release(s, 1)
    assert r.release_outcome == "delivered" and r.audit_anchored, "the receipt is durable here either way"
    assert anchor.export_failures >= 1
    health = s.tower.health()
    assert "receipt_export_live" in health["failed"]

    state["fail"] = False
    release(s, 2)
    assert "receipt_export_live" not in s.tower.health()["failed"]
    missing = [r for r in anchor.receipts() if r not in state["got"]]
    assert missing, "the receipt that failed is still there to re-export from receipts()"
    assert all(r in anchor.receipts() for r in state["got"])


def test_an_anchor_that_cannot_be_asked_counts_as_behind_not_as_fine():
    class Broken:
        def publish(self, sequence, head):
            pass

        def latest(self):
            return None

        def behind(self, head_sequence):
            raise RuntimeError("cannot tell")

    ledger = ValLedger(key=b"l" * 32, anchor=Broken())
    assert ledger.anchor_behind() is None, "an empty ledger has nothing to be behind on"
    ledger.log("T", "OK", "one entry")
    assert ledger.anchor_behind() == "unverifiable"


def test_an_eager_anchor_has_no_backlog_to_bound():
    class Eager:
        def publish(self, sequence, head):
            pass

        def latest(self):
            return None

    ledger = ValLedger(key=b"l" * 32, anchor=Eager())
    ledger.log("T", "OK", "x")
    assert ledger.anchor_behind() is None
