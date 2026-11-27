"""ARCHITECTURE.md and the README must describe G3 the way the code behaves.

G3 reports a hedge and leaves it in place (deleting "might" turns a doubt into a claim);
it removes puffery and runs the normalizer. The documents used to say G3 strips hedges.
These checks fail if that description comes back, and pin the behavior the text promises.
"""

from __future__ import annotations

import re
from pathlib import Path

from zts.profiles import get as get_profile
from zts.sieve import GateContext, gate_sbf

ROOT = Path(__file__).resolve().parent.parent


def _flat(text: str) -> str:
    return " ".join(text.split())


def _g3_section() -> str:
    text = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
    start = text.index("### G3")
    end = text.index("\n### ", start + 1)
    return _flat(text[start:end])


def test_g3_section_does_not_say_hedges_are_stripped():
    section = _g3_section().lower()
    assert not re.search(r"\b(strips?|removes?|deletes?)\b[^.]*\bhedges?\b", section)


def test_g3_section_says_hedges_are_reported_and_left_in_place():
    section = _g3_section().lower()
    assert "reports" in section and "left in place" in section


def test_g3_section_still_says_puffery_is_removed():
    assert "puffery" in _g3_section().lower()


def test_design_thesis_no_longer_claims_a_regex_removes_hedges():
    for name in ("ARCHITECTURE.md", "PROVENANCE.md"):
        text = _flat((ROOT / name).read_text(encoding="utf-8")).lower()
        assert "a regex that removes hedges" not in text, name


def test_readme_gate_table_does_not_list_g3_as_plain_strip():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    row = next(line for line in readme.splitlines() if line.startswith("| G3 |"))
    action = row.rstrip(" |").rsplit("|", 1)[-1].strip()
    assert action != "strip"
    assert "hedge" in action


def test_the_documented_example_keeps_its_hedge():
    ctx = GateContext(get_profile("default"))
    text = "The patient might be allergic to penicillin."
    out, findings = gate_sbf(text, ctx)
    assert [f.evidence for f in findings] == ["might"]
    assert out == text
