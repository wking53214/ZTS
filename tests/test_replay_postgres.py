"""The PostgreSQL replay store against a real PostgreSQL server.

Includes the multi-host attack: two full towers, each with its own Enforcer and its own
database connections, racing to release one grant. That is the case local SQLite cannot
cover.
"""

from __future__ import annotations

import multiprocessing
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from pg_kit import cluster  # noqa: F401  (session fixture)
from release_kit import TEXT, assert_not_released, build, request, run, static_grant
from zts.replay_postgres import PostgresReplayStore, ReplayStoreError


@pytest.fixture
def table():
    return "t_" + uuid.uuid4().hex[:12]


@pytest.fixture
def store(cluster, table):
    s = PostgresReplayStore(cluster.dsn, table=table)
    yield s
    s.close()


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


# ------------------------------------------------------------------- semantics


def test_a_grant_is_consumed_exactly_once(store):
    assert store.consume("iss", "n1", "r1") is True
    assert store.consume("iss", "n1", "r1") is False


def test_either_uniqueness_constraint_blocks_a_second_use(store):
    assert store.consume("iss", "n1", "r1") is True
    assert store.consume("iss", "n1", "r2") is False, "same issuer and nonce, new request id"
    assert store.consume("iss", "n2", "r1") is False, "new nonce, same request id"
    assert store.consume("other-iss", "n1", "r3") is True, "nonces are scoped to the issuer"


def test_the_state_survives_a_restart_of_the_client(cluster, table):
    first = PostgresReplayStore(cluster.dsn, table=table)
    assert first.consume("iss", "n1", "r1") is True
    first.close()
    second = PostgresReplayStore(cluster.dsn, table=table)
    assert second.consume("iss", "n1", "r1") is False
    second.close()


def test_threads_racing_for_one_grant_produce_exactly_one_winner(store):
    barrier = threading.Barrier(16)

    def attempt(_):
        barrier.wait()
        return store.consume("iss", "n1", "r1")

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))
    assert results.count(True) == 1


def _race(dsn, table, keys, out):
    s = PostgresReplayStore(dsn, table=table, create=False)
    out.put(sum(1 for k in keys if s.consume("iss", k, "req-" + k)))
    s.close()


def test_separate_processes_racing_for_the_same_grants_win_each_one_once(cluster, table):
    PostgresReplayStore(cluster.dsn, table=table).close()
    keys = [f"k{i}" for i in range(40)]
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    procs = [ctx.Process(target=_race, args=(cluster.dsn, table, keys, out)) for _ in range(4)]
    for p in procs:
        p.start()
    wins = [out.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(30)
    assert sum(wins) == len(keys), wins


def test_expires_at_must_be_timezone_aware(store):
    with pytest.raises(ReplayStoreError):
        store.consume("iss", "n1", "r1", datetime(2026, 1, 1))


# --------------------------------------------------------------------- outages


def test_an_unreachable_database_raises_so_enforcer_denies(table):
    with pytest.raises(ReplayStoreError):
        PostgresReplayStore("host=127.0.0.1 port=1 user=zts dbname=postgres connect_timeout=1", table=table)


def test_a_dropped_connection_fails_that_call_and_the_next_one_recovers(cluster, store):
    assert store.consume("iss", "n1", "r1") is True
    cluster.terminate_backends()
    with pytest.raises(ReplayStoreError):
        store.consume("iss", "n2", "r2")
    assert store.consume("iss", "n2", "r2") is True, "a fresh connection; the failed call consumed nothing"
    assert store.consume("iss", "n1", "r1") is False, "earlier state is intact"


# ------------------------------------------------------------ retention and health


def test_prune_removes_only_rows_whose_grant_expired_long_ago(store):
    now = datetime.now(timezone.utc)
    store.consume("iss", "old", "r-old", now - timedelta(hours=1))
    store.consume("iss", "recent", "r-recent", now - timedelta(seconds=10))
    store.consume("iss", "future", "r-future", now + timedelta(minutes=5))
    store.consume("iss", "unknown", "r-unknown")  # no recorded expiry: never pruned
    assert store.prune(timedelta(minutes=1)) == 1
    assert store.consume("iss", "old", "r-old") is True, "the pruned row is gone (that grant has long expired)"
    for nonce, rid in (("recent", "r-recent"), ("future", "r-future"), ("unknown", "r-unknown")):
        assert store.consume("iss", nonce, rid) is False


def test_health_checks_that_the_constraints_that_make_it_safe_exist(cluster, store, table):
    assert store.health() is True
    import psycopg
    with psycopg.connect(cluster.dsn, autocommit=True) as c:
        c.execute(f"ALTER TABLE {table} DROP CONSTRAINT {table}_request_id_key")
    assert store.health() is False, "without UNIQUE(request_id) the store is not safe, and must say so"


def test_describe_reports_what_it_is(store):
    info = store.describe()
    assert info["kind"] == "postgresql" and info["durable"] and info["shared"]


@pytest.mark.parametrize("bad", ["x; drop table y", "Upper", "1abc", "a" * 70, "a-b", ""])
def test_table_names_cannot_inject_sql(cluster, bad):
    with pytest.raises(ValueError):
        PostgresReplayStore(cluster.dsn, table=bad)


def test_exactly_one_of_dsn_or_connect_is_required(cluster):
    with pytest.raises(ValueError):
        PostgresReplayStore()
    with pytest.raises(ValueError):
        PostgresReplayStore(cluster.dsn, connect=lambda: None)


# ----------------------------------------- the multi-host attack through full towers


def test_two_hosts_racing_to_release_one_grant_release_it_once(cluster, table, tmp_path):
    """Each 'host' has its own Enforcer, tower, ledger and database connections; only PostgreSQL is shared."""
    from release_kit import Clock
    clock = Clock()
    hosts = []
    for n in range(2):
        (tmp_path / f"h{n}").mkdir()
        st = PostgresReplayStore(cluster.dsn, table=table)
        hosts.append(build(tmp_path / f"h{n}", store=st, clock=clock))
    grant = static_grant(hosts[0])
    barrier = threading.Barrier(8)

    def attempt(host):
        barrier.wait()
        return host.tower.enforce(TEXT, release=request(host, proof=grant, provider=None))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, [hosts[i % 2] for i in range(8)]))
    assert sum(r.released for r in results) == 1
    assert sum(len(h.sink.calls) for h in hosts) == 1, "one delivery across both hosts"
    assert all(r.reason_code == "GRANT_REPLAYED" for r in results if not r.released)


def test_a_replay_on_a_different_host_after_the_first_released_is_denied(cluster, table, tmp_path, mode):
    from release_kit import Clock
    clock = Clock()
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = build(tmp_path / "a", store=PostgresReplayStore(cluster.dsn, table=table), clock=clock)
    b = build(tmp_path / "b", store=PostgresReplayStore(cluster.dsn, table=table), clock=clock)
    grant = static_grant(a)
    assert run(a, mode, request(a, proof=grant, provider=None)).released
    replay = run(b, mode, request(b, proof=grant, provider=None))
    assert_not_released(b, replay, "GRANT_REPLAYED", outcome="denied")


def test_a_database_outage_during_release_is_a_denial_with_nothing_delivered(cluster, table, tmp_path, mode):
    dead = PostgresReplayStore(cluster.dsn, table=table)
    s = build(tmp_path, store=dead)
    dead.close()
    dead._dsn = "host=127.0.0.1 port=1 user=zts dbname=postgres connect_timeout=1"  # now unreachable
    assert_not_released(s, run(s, mode, request(s)), "REPLAY_STORE_ERROR", outcome="denied")
