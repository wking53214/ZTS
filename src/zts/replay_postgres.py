"""A shared, durable replay store on PostgreSQL, for Enforcer's ``ReplayStore`` seam.

Enforcer's own SQLite store is atomic on one host. When several hosts can release, they
must consume grants from one place. This store uses a single table with two uniqueness
constraints, ``(issuer_id, nonce)`` and ``request_id``, and one statement::

    INSERT ... ON CONFLICT DO NOTHING

The database serializes concurrent inserts of the same key, so exactly one caller sees
``rowcount == 1``. That caller is the one allowed to release. Every other caller gets
False, whichever constraint they collided on.

Failure semantics. Any database error closes the connection and is re-raised, so Enforcer
denies the release (``REPLAY_STORE_ERROR``). There is deliberately no retry: if an INSERT
committed and its answer was lost, a retry would see a conflict and answer False, which
denies a release that may be legitimate, and that is the safe direction. The next call
opens a fresh connection.

What this does not provide, so nothing downstream claims more:

  * Durability beyond the database's own. A commit that is acknowledged by a primary and
    lost in a failover to an asynchronous replica forgets a spent grant. Use synchronous
    replication (or no failover) if that matters; this module cannot see your topology.
  * Protection of the database. Anyone who can delete rows can re-open grants. Give the
    release hosts INSERT and SELECT (and DELETE only for the pruning role).
  * Transport security. Put ``sslmode=verify-full`` in the DSN. ``describe()`` reports it.

Constraints are checked where they are used. The two uniqueness constraints are the whole safety
argument, so ``consume`` confirms on every call that the table it is about to write to still has
them, and refuses (a denial, ``REPLAY_STORE_ERROR``) if not. A table that already exists without them is
refused when the store is built. The check and the insert are two statements, so someone who drops a
constraint in the microseconds between them still wins one race; that needs database DDL rights, which
is the same power as deleting the rows. Give release hosts no such rights.

Retention. ``prune()`` deletes only rows whose recorded grant expiry is older than a grace
period, judged by the DATABASE's clock, so a pruning host with a fast clock cannot delete a live
grant. The grace period has a floor (``MIN_GRACE``). It must still exceed the clock difference between
the database and every release host, so keep clocks within seconds. Rows with no recorded expiry
are never pruned. Enforcer passes the expiry only from the release that adds it; older Enforcer
releases leave it empty.

Needs ``pip install zts[replay-postgres]``.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

# The table name is interpolated into SQL (identifiers cannot be bound). It is accepted only if it matches
# this strict pattern, checked once in the constructor, so no caller-supplied text reaches a query.
_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
#: The shortest grace period ``prune`` accepts: well above Enforcer's clock-skew allowance (5 s by default).
MIN_GRACE = timedelta(seconds=30)


class ReplayStoreError(RuntimeError):
    """The replay store could not be reached or did not answer. Enforcer treats it as a denial."""


def _psycopg() -> Any:
    try:
        import psycopg
    except ImportError as exc:
        raise ReplayStoreError("psycopg is required for the PostgreSQL replay store") from exc
    return psycopg


class PostgresReplayStore:
    """Enforcer ``ReplayStore`` over PostgreSQL. One connection per thread, autocommit."""

    durable = True
    shared = True

    def __init__(
        self,
        dsn: str | None = None,
        *,
        connect: Callable[[], Any] | None = None,
        table: str = "zts_consumed_grants",
        statement_timeout: float = 5.0,
        create: bool = True,
    ) -> None:
        if (dsn is None) == (connect is None):
            raise ValueError("give exactly one of dsn or connect")
        if not _IDENT.fullmatch(table):
            raise ValueError("table must be a lowercase SQL identifier")
        if not isinstance(statement_timeout, (int, float)) or statement_timeout <= 0:
            raise ValueError("statement_timeout must be a positive number of seconds")
        self._dsn, self._connect_fn, self._table = dsn, connect, table
        self._timeout_ms = int(statement_timeout * 1000)
        self._local = threading.local()
        if create:
            self.ensure_schema()

    # ------------------------------------------------------------------ connections

    def _conn(self) -> Any:
        conn = getattr(self._local, "conn", None)
        if conn is not None and not conn.closed:
            return conn
        psycopg = _psycopg()
        try:
            conn = self._connect_fn() if self._connect_fn else psycopg.connect(
                self._dsn, autocommit=True, connect_timeout=max(1, self._timeout_ms // 1000))
            conn.autocommit = True
            conn.execute(f"SET statement_timeout = {self._timeout_ms}")
        except Exception as exc:
            raise ReplayStoreError(f"cannot connect to the replay database: {type(exc).__name__}") from None
        self._local.conn = conn
        return conn

    def _drop(self) -> None:
        conn = getattr(self._local, "conn", None)
        self._local.conn = None
        if conn is not None:
            try:
                conn.close()
            except Exception:  # nosec B110
                pass  # closing a dead connection may fail; nothing depends on it

    def close(self) -> None:
        self._drop()

    # ---------------------------------------------------------------------- schema

    def ensure_schema(self) -> None:
        t = self._table
        try:
            conn = self._conn()
            with conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"zts-replay:{t}",))
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {t} ("
                    "issuer_id text NOT NULL, nonce text NOT NULL, request_id text NOT NULL, "
                    "consumed_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz, "
                    "PRIMARY KEY (issuer_id, nonce), UNIQUE (request_id))")
                if not self._constraints_present(conn):
                    # CREATE ... IF NOT EXISTS keeps whatever was already there, constraints or not.
                    raise ReplayStoreError(f"table {t} exists without its uniqueness constraints; refusing to use it")
        except ReplayStoreError:
            raise
        except Exception as exc:
            self._drop()
            raise ReplayStoreError(f"cannot create the replay table: {type(exc).__name__}") from None

    # ----------------------------------------------------------------------- the seam

    def consume(self, issuer_id: str, nonce: str, request_id: str, expires_at: datetime | None = None) -> bool:
        """True exactly once per key; False if the nonce or the request id was already consumed."""
        if expires_at is not None and (expires_at.tzinfo is None or expires_at.utcoffset() is None):
            raise ReplayStoreError("expires_at must be timezone-aware")
        try:
            conn = self._conn()
            if not self._constraints_present(conn):
                raise ReplayStoreError("the replay table is missing a uniqueness constraint; every release is denied")
            cur = conn.execute(
                f"INSERT INTO {self._table} (issuer_id, nonce, request_id, expires_at) "  # nosec B608
                "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (issuer_id, nonce, request_id, expires_at))
            return cur.rowcount == 1
        except ReplayStoreError:
            raise
        except Exception as exc:
            self._drop()
            raise ReplayStoreError(f"the replay database did not answer: {type(exc).__name__}") from None

    # ---------------------------------------------------------- retention and health

    def prune(self, grace: timedelta = timedelta(minutes=1), *, now: datetime | None = None) -> int:
        """Delete rows whose grant expired more than ``grace`` ago. Never touches rows without an expiry.

        "Ago" is by the database's clock unless ``now`` is given. ``now`` is for tests and for a pruning job
        that deliberately runs against a restored copy; a host clock is not trusted by default, because a
        fast one would delete grants that are still valid and let them be used again.
        """
        if grace < MIN_GRACE:
            raise ValueError(f"grace cannot be shorter than {MIN_GRACE.total_seconds():.0f} seconds")
        if now is not None and (now.tzinfo is None or now.utcoffset() is None):
            raise ValueError("now must be timezone-aware")
        try:
            if now is None:
                cur = self._conn().execute(
                    f"DELETE FROM {self._table} WHERE expires_at IS NOT NULL AND expires_at < now() - %s",  # nosec B608
                    (grace,))
            else:
                cur = self._conn().execute(
                    f"DELETE FROM {self._table} WHERE expires_at IS NOT NULL AND expires_at < %s",  # nosec B608
                    (now - grace,))
            return cur.rowcount
        except ReplayStoreError:
            raise
        except Exception as exc:
            self._drop()
            raise ReplayStoreError(f"prune failed: {type(exc).__name__}") from None

    def _constraints_present(self, conn: Any) -> bool:
        """Do the two uniqueness constraints exist on the table this connection resolves the name to?"""
        rows = conn.execute(
            "SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c "
            "WHERE c.conrelid = to_regclass(%s) AND c.contype IN ('p', 'u')", (self._table,)).fetchall()
        defs = {row[0].replace('"', "") for row in rows}
        return "PRIMARY KEY (issuer_id, nonce)" in defs and "UNIQUE (request_id)" in defs

    def health(self) -> bool:
        """Reachable, and the two uniqueness constraints this store depends on are really there."""
        try:
            return self._constraints_present(self._conn())
        except Exception:
            self._drop()
            return False

    def describe(self) -> dict[str, Any]:
        info: dict[str, Any] = {"kind": "postgresql", "durable": True, "shared": True, "table": self._table,
                                "constraints_checked_each_consume": True}
        if self._dsn:
            try:
                parsed = _psycopg().conninfo.conninfo_to_dict(self._dsn)
            except Exception:
                parsed = {}
            info["host"] = parsed.get("host") or parsed.get("hostaddr") or "(default)"
            info["sslmode"] = parsed.get("sslmode", "prefer")
        return info


__all__ = ["PostgresReplayStore", "ReplayStoreError"]
