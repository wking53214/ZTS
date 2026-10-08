"""Test isolation: the default ledger key must never touch the real home directory."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_key_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    return tmp_path / "config"
