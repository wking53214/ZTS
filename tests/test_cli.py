"""CLI surface."""

from __future__ import annotations

import json

import pytest

from zts.cli import main


def run(argv, capsys):
    code = main(argv)
    return code, capsys.readouterr()


def test_scrub_prints_cleaned_payload(capsys):
    code, out = run(["scrub", "I", "think", "this", "works."], capsys)
    assert code == 0
    assert "I think" not in out.out


def test_scrub_strict_exits_nonzero_on_breach(capsys):
    code, _ = run(
        ["scrub", "--strict", "-p", "ops", "As an AI, I think we may be wrong."],
        capsys,
    )
    assert code == 1


def test_single_minor_finding_does_not_fail_a_lenient_profile(capsys):
    # One pronoun costs 10 points. ops requires 90. 90 >= 90, so the payload
    # passes with the finding recorded. The threshold is the decision, not the
    # presence of a finding.
    code, _ = run(["scrub", "--strict", "-p", "ops", "I think so."], capsys)
    assert code == 0


def test_scrub_strict_exits_zero_on_clean(capsys):
    code, _ = run(["scrub", "--strict", "-p", "ops", "Disk hit 94%."], capsys)
    assert code == 0


def test_audit_json_is_valid(capsys):
    code, out = run(["audit", "--json", "-p", "ops", "As an AI, I agree."], capsys)
    payload = json.loads(out.out)
    assert payload["verdict"] == "breach"
    assert payload["findings"]
    assert payload["score"] < 100


def test_audit_human_output_names_every_gate(capsys):
    _, out = run(["audit", "-p", "ops", "I think so."], capsys)
    for gate_id in ("G1", "G2", "G3", "G4", "G5", "G6"):
        assert gate_id in out.out


def test_gates_fail_fast_order_leads_with_ppa(capsys):
    _, out = run(["gates"], capsys)
    assert out.out.index("PPA") < out.out.index("HCA")


def test_gates_canonical_order_leads_with_ab(capsys):
    _, out = run(["gates", "--order", "canonical"], capsys)
    assert out.out.index("G1/AB") < out.out.index("G6/PPA")


def test_profiles_lists_all_four(capsys):
    _, out = run(["profiles"], capsys)
    for name in ("default", "ops", "exec", "legal"):
        assert name in out.out


def test_unknown_profile_is_rejected_by_argparse(capsys):
    with pytest.raises(SystemExit):
        main(["scrub", "-p", "enterprise", "text"])
