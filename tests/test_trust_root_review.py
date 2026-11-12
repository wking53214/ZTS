"""scripts/trust_root_review.py: the second person's tool for a trust-root edit."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from issuer_kit import IssuerKey, trust_doc
from release_kit import Clock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "trust_root_review.py"
spec = importlib.util.spec_from_file_location("trust_root_review", SCRIPT)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

CLOCK = Clock()


def write(path, entries, serial=None):
    doc = trust_doc(*entries)
    if serial is not None:
        doc["serial"] = serial
    path.write_text(json.dumps(doc))
    return path


@pytest.fixture
def keys():
    return IssuerKey("a", "grant"), IssuerKey("a", "status")


def run(capsys, *args):
    code = tool.main([str(a) for a in args])
    return code, capsys.readouterr().out


def test_a_good_file_is_accepted_and_the_pin_is_the_sha256_of_its_bytes(tmp_path, keys, capsys):
    g, s = keys
    p = write(tmp_path / "new.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=3)
    code, out = run(capsys, p)
    assert code == 0 and "RESULT: OK" in out
    assert hashlib.sha256(p.read_bytes()).hexdigest() in out
    assert g.kid in out and s.kid in out and "serial        3" in out


@pytest.mark.parametrize("text", ["{ nope", "[]", "{}", '{"version":1,"keys":[],"keys":[]}', '{"version":1,"keys":[],"x":NaN}'])
def test_a_file_zts_would_refuse_is_refused_here(tmp_path, capsys, text):
    p = tmp_path / "bad.json"
    p.write_text(text)
    code, out = run(capsys, p)
    assert code == 1 and "REFUSED" in out


def test_a_role_with_no_usable_key_and_a_missing_serial_are_warned(tmp_path, keys, capsys):
    g, _ = keys
    p = write(tmp_path / "new.json", [g.entry(CLOCK)])
    code, out = run(capsys, p)
    assert code == 0
    assert "no usable status key" in out and "no serial" in out


def test_keys_expiring_soon_and_active_keys_past_their_end_are_warned(tmp_path, keys):
    """Uses review() with the test clock as 'now': the entries are dated against that clock, not the real one."""
    g, s = keys
    p = write(tmp_path / "new.json", [g.entry(CLOCK, after=86400 * 5), s.entry(CLOCK, before=-86400 * 3, after=-86400)],
              serial=1)
    _, problems, warnings = tool.review(p, None, CLOCK(), 30)
    assert problems == []
    assert any("expires in under 30 days" in w and g.kid in w for w in warnings)
    assert any("marked active but its window ended" in w and s.kid in w for w in warnings)


def test_an_edit_must_raise_the_serial(tmp_path, keys, capsys):
    g, s = keys
    old = write(tmp_path / "old.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=5)
    for serial in (5, 4, None):
        new = write(tmp_path / "new.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=serial)
        code, out = run(capsys, new, "--previous", old)
        assert code == 1 and "serial must rise" in out, serial
    new = write(tmp_path / "new.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=6)
    assert run(capsys, new, "--previous", old)[0] == 0


def test_bringing_back_a_revoked_key_fails_the_review(tmp_path, keys, capsys):
    g, s = keys
    old = write(tmp_path / "old.json", [g.entry(CLOCK, status="revoked"), s.entry(CLOCK)], serial=1)
    new = write(tmp_path / "new.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=2)
    code, out = run(capsys, new, "--previous", old)
    assert code == 1 and "REVOKED and is ACTIVE again" in out


def test_added_removed_and_changed_keys_are_shown(tmp_path, keys, capsys):
    g, s = keys
    extra = IssuerKey("a", "grant")
    old = write(tmp_path / "old.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=1)
    new = write(tmp_path / "new.json", [g.entry(CLOCK, status="revoked"), extra.entry(CLOCK)], serial=2)
    code, out = run(capsys, new, "--previous", old)
    assert code == 0
    assert f"+ {extra.kid}" in out
    assert f"- {s.kid}" in out
    assert "status active -> revoked" in out


def test_a_longer_window_than_before_is_warned(tmp_path, keys, capsys):
    g, s = keys
    old = write(tmp_path / "old.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=1)
    new = write(tmp_path / "new.json", [g.entry(CLOCK, after=86400 * 400), s.entry(CLOCK)], serial=2)
    code, out = run(capsys, new, "--previous", old)
    assert code == 0 and "longer window than before" in out


def test_an_identical_file_with_a_higher_serial_reports_no_key_change(tmp_path, keys, capsys):
    g, s = keys
    old = write(tmp_path / "old.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=1)
    new = write(tmp_path / "new.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=2)
    code, out = run(capsys, new, "--previous", old)
    assert code == 0 and "no key changed" in out


@pytest.mark.parametrize("field,value", [("role", "status"), ("issuer_id", "someone-else")])
def test_the_same_key_id_under_another_role_or_issuer_fails_the_review(tmp_path, keys, capsys, field, value):
    """A key id is derived from the key alone, so an honest edit never changes who a key belongs to or what it may sign."""
    g, s = keys
    changed = dict(g.entry(CLOCK), **{field: value})
    old = write(tmp_path / "old.json", [g.entry(CLOCK), s.entry(CLOCK)], serial=1)
    new = write(tmp_path / "new.json", [changed, s.entry(CLOCK)], serial=2)
    code, out = run(capsys, new, "--previous", old)
    assert code == 1 and "changed its role, issuer or key" in out


def test_an_identity_role_key_is_shown_and_accepted_by_the_review(tmp_path, keys, capsys):
    g, s = keys
    idp = IssuerKey("idp", "identity")
    p = write(tmp_path / "new.json", [g.entry(CLOCK), s.entry(CLOCK), idp.entry(CLOCK)], serial=1)
    _, out = run(capsys, p)
    assert idp.kid in out and "identity" in out
    _, problems, _ = tool.review(p, None, CLOCK(), 30)
    assert problems == []
