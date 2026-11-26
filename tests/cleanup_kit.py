"""Close what a test opened, after the test.

Enforcer's SQLiteReplayStore holds an open SQLite connection until close() is called. The test
helpers used to leave every store open, which showed up as hundreds of "unclosed database"
warnings per run. Anything handed to closed_after_test() is closed when the current test ends,
by the autouse fixture in conftest.py. This module imports nothing optional, so it loads in a
dev-only install too.
"""

from __future__ import annotations

from typing import Any, TypeVar

T = TypeVar("T")

_open: list[Any] = []


def closed_after_test(resource: T) -> T:
    """Register a resource with a close() method; it is closed when the current test ends."""
    if not any(r is resource for r in _open):
        _open.append(resource)
    return resource


def close_all() -> None:
    """Close every registered resource, newest first, and forget them all."""
    while _open:
        _open.pop().close()


def still_open() -> int:
    return len(_open)
