"""Test isolation: the default ledger key must never touch the real home directory, and what a test
opened is closed when it ends."""

from __future__ import annotations

import pytest

from cleanup_kit import close_all


@pytest.fixture(autouse=True)
def isolated_key_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    return tmp_path / "config"


@pytest.fixture(autouse=True)
def close_registered_resources():
    """Close every store a test registered with cleanup_kit. Set up first, so torn down last."""
    yield
    close_all()
