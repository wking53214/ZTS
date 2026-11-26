"""The static checks stay wired in (P4, 2026-11-26).

The type checker and the coverage floor run as CI jobs (typecheck, coverage). These tests need neither tool, so
they never skip: they hold the configuration in place, and they hold the rule that every "type: ignore" in src
is a spot guarded at runtime and says how.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())
WORKFLOW = (ROOT / ".github" / "workflows" / "tests.yml").read_text()


def test_mypy_is_configured_for_src_and_reports_stale_ignores():
    mypy = PYPROJECT["tool"]["mypy"]
    assert mypy["files"] == ["src/zts"]
    assert mypy["warn_unused_ignores"] is True


def test_static_tools_are_pinned_exactly():
    static = PYPROJECT["project"]["optional-dependencies"]["static"]
    assert static and all("==" in spec for spec in static)
    assert any(spec.startswith("mypy==") for spec in static)


def test_coverage_floor_is_branch_coverage_at_or_above_the_baseline():
    coverage = PYPROJECT["tool"]["coverage"]
    assert coverage["run"]["branch"] is True
    assert coverage["report"]["fail_under"] >= 94.0


def test_ci_runs_both_checks():
    assert re.search(r"^  typecheck:\n(?:    .*\n|\n)*?        run: mypy$", WORKFLOW, re.M)
    assert re.search(r"^  coverage:\n(?:    .*\n|\n)*?        run: python -m pytest tests/ .*--cov=zts", WORKFLOW, re.M)


def test_every_type_ignore_is_a_documented_runtime_guard():
    undocumented = []
    for path in sorted((ROOT / "src" / "zts").rglob("*.py")):
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines):
            if "type: ignore" not in line:
                continue
            assert re.search(r"type: ignore\[[a-z-]+(?:, ?[a-z-]+)*\]", line), f"{path.name}:{number + 1} has a bare ignore"
            window = "\n".join(lines[max(0, number - 10) : number + 1])
            if "Guarded:" not in window:
                undocumented.append(f"{path.relative_to(ROOT)}:{number + 1}")
    assert undocumented == []
