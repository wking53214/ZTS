"""What a test opens is closed when it ends.

Regression for the ~510 "unclosed database" warnings per full run: every Enforcer SQLiteReplayStore
the test helpers opened stayed open. pyproject.toml now turns a leaked SQLite connection into a
failure, so a new leak anywhere in the suite fails CI; these tests pin down the mechanism itself.
"""

from __future__ import annotations

import sqlite3

import pytest

import cleanup_kit


class Closable:
    def __init__(self, log, name):
        self.log, self.name = log, name

    def close(self):
        self.log.append(self.name)


def test_registered_resources_are_closed_newest_first_and_only_once():
    log = []
    first, second = Closable(log, "first"), Closable(log, "second")
    assert cleanup_kit.closed_after_test(first) is first
    cleanup_kit.closed_after_test(second)
    cleanup_kit.closed_after_test(first)  # registering twice does not close twice
    cleanup_kit.close_all()
    assert log == ["second", "first"]
    assert cleanup_kit.still_open() == 0


def test_nothing_is_left_registered_from_an_earlier_test():
    assert cleanup_kit.still_open() == 0


def test_the_store_a_built_stack_opens_is_closed_when_the_test_ends(tmp_path):
    release_kit = pytest.importorskip("release_kit")
    s = release_kit.build(tmp_path)
    assert cleanup_kit.still_open() == 1
    s.store._connection.execute("SELECT 1")  # open while the test runs
    cleanup_kit.close_all()  # what the autouse fixture in conftest.py does at teardown
    with pytest.raises(sqlite3.ProgrammingError):
        s.store._connection.execute("SELECT 1")


def test_a_store_passed_in_is_closed_too(tmp_path):
    release_kit = pytest.importorskip("release_kit")
    store = release_kit.enforcer.SQLiteReplayStore(":memory:")
    release_kit.build(tmp_path, store=store)
    cleanup_kit.close_all()
    with pytest.raises(sqlite3.ProgrammingError):
        store._connection.execute("SELECT 1")
