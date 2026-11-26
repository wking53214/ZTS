"""The CNS pin and the oldest accepted release are written down as two different things (P3, 2026-11-25).

At 9784786 a comment in src/zts/cns/adapter.py, the cns-3 job in .github/workflows/tests.yml and
docs/RELEASE_BOUNDARY.md all called 2.3.0 the release ZTS pins. The pin is 4.1.0; 2.3.0 is the oldest release the
dock accepts. These tests read the real pin from pyproject.toml, so a stale note fails when the pin moves again.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from zts.cns import CNS_CONTRACT_VERSION

ROOT = Path(__file__).resolve().parent.parent


def pinned_cns() -> str:
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]
    (spec,) = extras["cns"]
    match = re.search(r"CNS\.git@v([0-9]+\.[0-9]+\.[0-9]+)$", spec)
    assert match, spec
    return match.group(1)


NOTES = [
    ROOT / "src" / "zts" / "cns" / "adapter.py",
    ROOT / ".github" / "workflows" / "tests.yml",
    ROOT / "docs" / "RELEASE_BOUNDARY.md",
]


def test_the_pin_is_not_the_floor():
    assert pinned_cns() != CNS_CONTRACT_VERSION


def test_no_note_calls_the_floor_the_pin():
    floor = re.escape(CNS_CONTRACT_VERSION)
    stale = re.compile(rf"pinned {floor}|release ZTS pins[^.]*v?{floor}|pins\s+(?:CNS\s+)?v?{floor}", re.IGNORECASE)
    for path in NOTES:
        text = " ".join(path.read_text().split())
        assert not stale.search(text), f"{path.name} calls {CNS_CONTRACT_VERSION} the pin"


def test_each_note_names_the_real_pin():
    pin = pinned_cns()
    for path in NOTES:
        assert pin in path.read_text(), f"{path.name} does not name the pin {pin}"


def test_readme_states_who_checks_the_subject():
    text = " ".join((ROOT / "README.md").read_text().split())
    assert "Unless an identity verifier is configured, Enforcer's grant is the only check on who the subject is" in text
    assert "ZTS does not authenticate people by itself" in text
