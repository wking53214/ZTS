"""Phase 2 audit, package C: the replay store checks its constraints where they are used.

The audit's finding: the two uniqueness constraints that make replay protection safe were verified
at startup only, so dropping one silently let a grant be released again; and `prune()` trusted the
pruning host's clock, so a fast one could delete a grant that was still valid.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from pg_kit import cluster  # noqa: F401  (session fixture)
from zts.ops import _probe_replay_store
from zts.replay_postgres import PostgresReplayStore


def real_now():
    return dt.datetime.now(dt.timezone.utc)

def test_a_table_that_loses_a_constraint_after_startup_denies_instead_of_replaying(cluster):
    import psycopg

    from zts.replay_postgres import ReplayStoreError

    table = "t_" + uuid.uuid4().hex[:12]
    store = PostgresReplayStore(cluster.dsn, table=table)
    exp = real_now() + dt.timedelta(minutes=5)
    assert store.consume("i", "n1", "r1", expires_at=exp) is True
    with psycopg.connect(cluster.dsn, autocommit=True) as c:
        for (name,) in c.execute("SELECT conname FROM pg_constraint WHERE conrelid = to_regclass(%s)", (table,)).fetchall():
            c.execute(f'ALTER TABLE {table} DROP CONSTRAINT "{name}"')
    for _ in range(2):  # before this change both calls returned True: the same grant, released twice
        with pytest.raises(ReplayStoreError, match="uniqueness constraint"):
            store.consume("i", "n1", "r1", expires_at=exp)
    assert store.health() is False


def test_a_table_that_already_exists_without_its_constraints_is_refused_at_construction(cluster):
    import psycopg

    from zts.replay_postgres import ReplayStoreError

    table = "t_" + uuid.uuid4().hex[:12]
    with psycopg.connect(cluster.dsn, autocommit=True) as c:
        c.execute(f"CREATE TABLE {table} (issuer_id text, nonce text, request_id text, "
                  "consumed_at timestamptz DEFAULT now(), expires_at timestamptz)")
    with pytest.raises(ReplayStoreError, match="without its uniqueness constraints"):
        PostgresReplayStore(cluster.dsn, table=table)
    # create=False skips the schema step; the per-call check still refuses, and readiness says FAIL.
    lax = PostgresReplayStore(cluster.dsn, table=table, create=False)
    with pytest.raises(ReplayStoreError):
        lax.consume("i", "n", "r")
    assert [c.status for c in _probe_replay_store(lax) if c.name == "replay_store"] == ["FAIL"]


def test_prune_uses_the_database_clock_so_a_fast_host_cannot_delete_a_live_grant(cluster):
    table = "t_" + uuid.uuid4().hex[:12]
    store = PostgresReplayStore(cluster.dsn, table=table)
    live = real_now() + dt.timedelta(minutes=4)
    assert store.consume("i", "n1", "r1", expires_at=live) is True
    assert store.prune() == 0, "default: judged by the database, where this grant is still valid"
    assert store.consume("i", "n1", "r1", expires_at=live) is False, "and it is still spent"
    long_gone = real_now() - dt.timedelta(minutes=10)
    assert store.consume("i", "n2", "r2", expires_at=long_gone) is True
    assert store.prune() == 1, "an expired grant is still pruned"


@pytest.mark.parametrize("grace", [dt.timedelta(0), dt.timedelta(seconds=29), dt.timedelta(seconds=-1)])
def test_prune_refuses_a_grace_period_shorter_than_the_floor(cluster, grace):
    store = PostgresReplayStore(cluster.dsn, table="t_" + uuid.uuid4().hex[:12])
    with pytest.raises(ValueError, match="shorter than"):
        store.prune(grace)
    with pytest.raises(ValueError, match="timezone-aware"):
        store.prune(now=dt.datetime(2030, 1, 1))
