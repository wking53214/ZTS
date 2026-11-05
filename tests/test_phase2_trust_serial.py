"""Phase 2 audit, package D: an older copy of the trust root cannot bring a revoked key back.

The audit's finding: putting the previous trust-root file back un-revoked a key, and the only
defence (a pinned digest) made every rotation need a restart. A serial store lets rotation stay
hot while refusing to go backwards.

What it does NOT do, tested below as a known limit: someone who can write the trust-root file can
author a NEW file with a higher serial. Stopping that is file permission or a signed trust root.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from issuer_kit import IssuerKey, trust_doc
from pg_kit import cluster  # noqa: F401  (session fixture)
from release_kit import Clock, build, request, run
from test_trust_ed25519 import issuer_provider
from zts.ops import _probe_rollback
from zts.replay_postgres import PostgresSerialStore
from zts.trust import Ed25519GrantVerifier, FileSerialStore, FileTrustRoot, TrustRoot, TrustRootError

CLOCK = Clock()


def doc(key, serial=None, **entry_kw):
    d = trust_doc(key.entry(CLOCK, **entry_kw))
    if serial is not None:
        d["serial"] = serial
    return d


def put(path, document):
    time.sleep(0.01)  # a distinct mtime/ctime, so the file is seen as changed
    path.write_text(json.dumps(document))
    os.chmod(path, 0o644)


@pytest.fixture
def key():
    return IssuerKey("issuer-a")


# ------------------------------------------------------------------ the document


def test_a_serial_is_optional_and_part_of_the_digest(key):
    plain = TrustRoot.from_dict(doc(key))
    one, two = TrustRoot.from_dict(doc(key, 1)), TrustRoot.from_dict(doc(key, 2))
    assert plain.serial is None and one.serial == 1 and two.serial == 2
    assert len({plain.digest, one.digest, two.digest}) == 3, "the serial cannot be changed without changing the digest"


@pytest.mark.parametrize("bad", [0, -1, True, False, 1.5, "7", None, [1]])
def test_a_serial_that_is_not_a_positive_integer_is_refused(key, bad):
    d = doc(key)
    d["serial"] = bad
    with pytest.raises(TrustRootError):
        TrustRoot.from_dict(d)


# ------------------------------------------------------------------ the file store


def test_the_file_store_only_moves_forward(tmp_path):
    store = FileSerialStore(tmp_path / "serial.json")
    store.record(5, "d5")
    store.record(5, "d5")  # asking again is harmless
    store.record(6, "d6")
    with pytest.raises(TrustRootError, match="rollback"):
        store.record(5, "d5")
    with pytest.raises(TrustRootError, match="two different trust roots"):
        store.record(6, "other")
    assert oct(os.stat(tmp_path / "serial.json").st_mode & 0o777) == "0o600"
    # a fresh object over the same file remembers: the mark survives a restart
    with pytest.raises(TrustRootError, match="rollback"):
        FileSerialStore(tmp_path / "serial.json").record(3, "d3")


def test_a_damaged_serial_file_refuses_instead_of_resetting(tmp_path):
    p = tmp_path / "serial.json"
    store = FileSerialStore(p)
    store.record(2, "d")
    for junk in ("{ nope", "[]", json.dumps({"serial": 0, "digest": "d"}), json.dumps({"serial": 2}),
                 json.dumps({"serial": True, "digest": "d"})):
        p.write_text(junk)
        with pytest.raises(TrustRootError, match="damaged"):
            store.record(9, "d9")


def test_concurrent_writers_never_leave_the_mark_lower_than_any_accepted_serial(tmp_path):
    store = FileSerialStore(tmp_path / "serial.json")

    def push(n):
        try:
            store.record(n, f"d{n}")
        except TrustRootError:
            pass  # lost the race to a higher serial: that is allowed
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(push, range(1, 41)))
    assert json.loads((tmp_path / "serial.json").read_text())["serial"] == 40


# --------------------------------------------- the attack, end to end, with hot rotation


def stack(tmp_path, key, path, **root_kw):
    root = FileTrustRoot(path, **root_kw)
    return build(tmp_path, clock=CLOCK, verifier=Ed25519GrantVerifier(root, clock=CLOCK)), root


def release(s, key, n):
    return run(s, "sync", request(s, f"rel-{n}", provider=issuer_provider(s, key, nonce=f"n-{n}")))


def test_putting_an_older_trust_root_back_is_refused_and_rotation_stays_hot(tmp_path, key):
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    s, root = stack(tmp_path, key, path, serial_store=FileSerialStore(tmp_path / "hw.json"))
    assert release(s, key, 1).release_outcome == "delivered"

    put(path, doc(key, 2, status="revoked"))  # a revocation, picked up with no restart
    revoked = release(s, key, 2)
    assert revoked.release_outcome == "denied" and revoked.reason_code == "PROOF_INVALID"

    put(path, doc(key, 1))  # the attack: restore the older file in which the key is active again
    rolled_back = release(s, key, 3)
    assert rolled_back.release_outcome == "denied" and not s.sink.calls[1:], "the revoked key does not come back"
    with pytest.raises(TrustRootError, match="rollback"):
        root.current()

    put(path, doc(key, 3))  # a genuine later edit (say, a replacement key) works again at once
    assert release(s, key, 4).release_outcome == "delivered"


def test_without_a_serial_store_the_same_attack_works_which_is_why_readiness_says_unknown(tmp_path, key):
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    s, root = stack(tmp_path, key, path)
    put(path, doc(key, 2, status="revoked"))
    assert release(s, key, 1).release_outcome == "denied"
    put(path, doc(key, 1))
    assert release(s, key, 2).release_outcome == "delivered", "documented: no rollback protection configured"
    check = _probe_rollback(s.enforcer._verifier)
    assert check.status == "UNKNOWN" and "un-revoke" in check.detail


def test_known_limit_a_writer_of_the_file_can_author_a_newer_serial(tmp_path, key):
    """The serial store stops an OLD file being restored. It cannot stop a NEW forged one."""
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    s, root = stack(tmp_path, key, path, serial_store=FileSerialStore(tmp_path / "hw.json"))
    put(path, doc(key, 2, status="revoked"))
    assert release(s, key, 1).release_outcome == "denied"
    put(path, doc(key, 3))  # same content as the old file but a higher serial
    assert release(s, key, 2).release_outcome == "delivered"


def test_a_pinned_digest_and_a_serial_store_each_report_pass_and_neither_reports_unknown(tmp_path, key):
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    import hashlib
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    pinned = Ed25519GrantVerifier(FileTrustRoot(path, expected_sha256=pin))
    serial = Ed25519GrantVerifier(FileTrustRoot(path, serial_store=FileSerialStore(tmp_path / "hw.json")))
    assert _probe_rollback(pinned).status == "PASS" and "restart" in _probe_rollback(pinned).detail
    assert _probe_rollback(serial).status == "PASS" and "newer" in _probe_rollback(serial).detail
    assert _probe_rollback(Ed25519GrantVerifier(TrustRoot.from_dict(doc(key)))).status == "UNKNOWN"


def test_a_serial_store_needs_a_serial_in_the_file(tmp_path, key):
    path = tmp_path / "trust.json"
    put(path, doc(key))
    with pytest.raises(TrustRootError, match="no serial"):
        FileTrustRoot(path, serial_store=FileSerialStore(tmp_path / "hw.json"))


def test_a_store_that_cannot_answer_refuses_everything_and_recovers(tmp_path, key):
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    inner = FileSerialStore(tmp_path / "hw.json")
    state = {"down": False}

    class Flaky:
        def record(self, serial, digest):
            if state["down"]:
                raise ConnectionError("database down")
            inner.record(serial, digest)
    s, root = stack(tmp_path, key, path, serial_store=Flaky(), recheck_interval=0)
    assert release(s, key, 1).release_outcome == "delivered"
    state["down"] = True
    down = release(s, key, 2)
    assert down.release_outcome == "denied" and down.reason_code == "PROOF_INVALID"
    state["down"] = False
    assert release(s, key, 3).release_outcome == "delivered"


def test_a_host_whose_file_fell_behind_is_refused_instead_of_using_stale_keys(tmp_path, key):
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    shared = FileSerialStore(tmp_path / "hw.json")
    s, root = stack(tmp_path, key, path, serial_store=shared, recheck_interval=0)
    assert release(s, key, 1).release_outcome == "delivered"
    shared.record(2, "digest-of-a-newer-root-another-host-accepted")  # a revocation reached another host first
    stale = release(s, key, 2)
    assert stale.release_outcome == "denied", "this host still holds serial 1; it must not keep releasing on it"
    put(path, doc(key, 2))
    with pytest.raises(TrustRootError, match="two different trust roots"):
        root.current()  # same serial, different content than the one recorded: also refused


def test_the_recheck_interval_bounds_how_long_a_stale_host_keeps_going(tmp_path, key):
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    shared = FileSerialStore(tmp_path / "hw.json")
    s, root = stack(tmp_path, key, path, serial_store=shared, recheck_interval=0.3)
    assert release(s, key, 1).release_outcome == "delivered"
    shared.record(2, "newer")
    assert release(s, key, 2).release_outcome == "delivered", "inside the interval: not rechecked yet (documented)"
    time.sleep(0.4)
    assert release(s, key, 3).release_outcome == "denied"


@pytest.mark.parametrize("bad", [-1, True, "30"])
def test_recheck_interval_and_store_are_validated(tmp_path, key, bad):
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    with pytest.raises(ValueError):
        FileTrustRoot(path, serial_store=FileSerialStore(tmp_path / "hw.json"), recheck_interval=bad)
    with pytest.raises(TypeError):
        FileTrustRoot(path, serial_store=object())


# ------------------------------------------------------------- the shared PostgreSQL store


@pytest.fixture
def pg_store(cluster):
    s = PostgresSerialStore(cluster.dsn, name="n" + uuid.uuid4().hex[:8], table="s_" + uuid.uuid4().hex[:10])
    yield s
    s.close()


def test_the_database_store_only_moves_forward_and_survives_a_new_client(cluster, pg_store):
    pg_store.record(5, "d5")
    pg_store.record(5, "d5")
    pg_store.record(7, "d7")
    with pytest.raises(TrustRootError, match="not accepted"):
        pg_store.record(6, "d6")
    with pytest.raises(TrustRootError, match="two different trust roots"):
        pg_store.record(7, "other")
    again = PostgresSerialStore(cluster.dsn, name=pg_store._name, table=pg_store._table)
    with pytest.raises(TrustRootError):
        again.record(1, "d1")
    again.close()


def test_two_hosts_racing_with_different_roots_under_one_serial_produce_one_winner(cluster, pg_store):
    other = PostgresSerialStore(cluster.dsn, name=pg_store._name, table=pg_store._table)
    barrier = threading.Barrier(2)
    results = []

    def go(store, digest):
        barrier.wait()
        try:
            store.record(9, digest)
            results.append(("ok", digest))
        except TrustRootError:
            results.append(("refused", digest))
    ts = [threading.Thread(target=go, args=(pg_store, "A")), threading.Thread(target=go, args=(other, "B"))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(r[0] for r in results) == ["ok", "refused"], results
    other.close()


def test_two_hosts_loading_the_same_new_root_both_succeed(cluster, pg_store):
    other = PostgresSerialStore(cluster.dsn, name=pg_store._name, table=pg_store._table)
    barrier = threading.Barrier(2)
    outcomes = []

    def go(store):
        barrier.wait()
        store.record(4, "same")
        outcomes.append("ok")
    ts = [threading.Thread(target=go, args=(x,)) for x in (pg_store, other)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert outcomes == ["ok", "ok"]
    other.close()


def test_an_unreachable_database_refuses_the_trust_root(tmp_path, key):
    store = PostgresSerialStore(connect=lambda: (_ for _ in ()).throw(OSError("down")), create=False)
    with pytest.raises(TrustRootError, match="did not answer"):
        store.record(1, "d")
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    with pytest.raises(TrustRootError):
        FileTrustRoot(path, serial_store=store)


def test_the_end_to_end_attack_is_refused_through_the_database_store(cluster, tmp_path, key, pg_store):
    path = tmp_path / "trust.json"
    put(path, doc(key, 1))
    s, root = stack(tmp_path, key, path, serial_store=pg_store)
    assert release(s, key, 1).release_outcome == "delivered"
    put(path, doc(key, 2, status="revoked"))
    assert release(s, key, 2).release_outcome == "denied"
    put(path, doc(key, 1))
    assert release(s, key, 3).release_outcome == "denied"
    assert len(s.sink.calls) == 1


def test_names_and_tables_are_validated(cluster):
    with pytest.raises(ValueError):
        PostgresSerialStore(cluster.dsn, name=" ")
    with pytest.raises(ValueError):
        PostgresSerialStore(cluster.dsn, table="x; DROP TABLE y")
