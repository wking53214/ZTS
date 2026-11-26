"""Fail-closed consistency (P2, 2026-11-25).

At 9784786 the legacy CALLBACK capstone released on any truthy return ("no", "False", a list, 1), and a profile
with max_retries below 1 built a tower whose run() crashed (AssertionError, or AttributeError under python -O).
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from dataclasses import replace

import pytest

from zts.capstone import ArchitectsProtocol, ReleaseMode
from zts.profiles import OPS, PROFILES
from zts.tower import DeterministicIntegrityTower


class TestCallbackNeedsExactlyTrue:
    @pytest.mark.parametrize("answer", ["no", "False", "true", "yes", [0], [], 1, 1.0, object(), None, 0])
    def test_anything_but_true_holds(self, answer):
        decision = ArchitectsProtocol(ReleaseMode.CALLBACK, approver=lambda p: answer).authorize("x")
        assert decision.released is False

    def test_true_releases(self):
        decision = ArchitectsProtocol(ReleaseMode.CALLBACK, approver=lambda p: True).authorize("x")
        assert decision.released is True
        assert decision.reason == "approver granted"

    def test_false_is_a_decline(self):
        decision = ArchitectsProtocol(ReleaseMode.CALLBACK, approver=lambda p: False).authorize("x")
        assert decision.reason == "approver declined"

    def test_non_bool_answer_is_reported_as_held(self):
        decision = ArchitectsProtocol(ReleaseMode.CALLBACK, approver=lambda p: "no").authorize("x")
        assert "other than True" in decision.reason

    def test_tower_withholds_on_a_truthy_non_true_answer(self):
        tower = DeterministicIntegrityTower(
            "ops", capstone=ArchitectsProtocol(ReleaseMode.CALLBACK, approver=lambda p: "no")
        )
        result = tower.enforce("Disk utilization reached 94% on node 3.")
        assert result.released is False
        assert result.output == ""


class TestMaxRetriesCheckedAtBuild:
    @pytest.mark.parametrize("retries", [0, -1, -100, True, False, 1.5, "3", None])
    def test_bad_value_is_refused_when_the_tower_is_built(self, retries):
        with pytest.raises(ValueError, match="max_retries"):
            DeterministicIntegrityTower(replace(OPS, max_retries=retries))

    @pytest.mark.parametrize("name", sorted(PROFILES))
    def test_shipped_profiles_build(self, name):
        DeterministicIntegrityTower(name)

    def test_one_retry_runs(self):
        tower = DeterministicIntegrityTower(
            replace(OPS, max_retries=1), capstone=ArchitectsProtocol(ReleaseMode.SEALED)
        )

        async def generator(prompt):
            return "Disk utilization reached 94% on node 3."

        result = asyncio.run(tower.run("x", generator))
        assert result.attempts == 1
        assert result.released is False

    def test_refused_under_python_dash_o_too(self):
        code = (
            "from dataclasses import replace\n"
            "from zts.profiles import OPS\n"
            "from zts.tower import DeterministicIntegrityTower\n"
            "try:\n"
            "    DeterministicIntegrityTower(replace(OPS, max_retries=0))\n"
            "except ValueError:\n"
            "    print('refused')\n"
        )
        out = subprocess.run([sys.executable, "-O", "-c", code], capture_output=True, text=True, check=True)
        assert out.stdout.strip() == "refused"
