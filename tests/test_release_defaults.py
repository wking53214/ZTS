"""The release default, the legacy modes, and the structure around the boundary.

None of this needs CNS or Enforcer installed, and none of it skips. It proves the
negative space: what a tower does when nobody configured a release authority,
that the legacy modes cannot be reached by accident, and that no second release
path has been added next to the guarded one.
"""

from __future__ import annotations

import ast
import asyncio
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from zts import (
    ArchitectsProtocol,
    DeterministicIntegrityTower,
    EnforcerReleaseGate,
    KineticGovernor,
    ReleaseMode,
    ReleaseReason,
    ReleaseRequest,
)
from zts.cns import CNSDock
from zts.release import enforcer_version_supported

CLEAN = "Disk utilization reached 94% on node 3 at 02:17 UTC."
DIRTY = "As an AI, I may be wrong."
ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "zts"


class Sink:
    def __init__(self):
        self.calls = []

    def __call__(self, output, signature):
        self.calls.append((output, signature))


class StubEnforcer:
    """Counts calls. Used only where the test asserts it must NOT be reached."""

    def __init__(self):
        self.calls = 0

    def execute(self, envelope, proof, action):
        self.calls += 1
        raise AssertionError("the gate must not reach Enforcer here")


def tower(**kwargs):
    kwargs.setdefault("persist_ledger_key", False)
    kwargs.setdefault("governor", KineticGovernor(ceiling_seconds=0.001))
    return DeterministicIntegrityTower("ops", **kwargs)


def run(t, mode, text=CLEAN, **kwargs):
    if mode == "sync":
        return t.enforce(text, **kwargs)

    async def generator(prompt):
        return text

    return asyncio.run(t.run("p", generator, **kwargs))


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


# ------------------------------------------------------------------ the safe default


def test_a_tower_with_no_release_authority_holds_everything(mode):
    sink = Sink()
    t = tower(release_sink=sink)
    result = run(t, mode)
    assert result.released is False and result.output == "" and result.signature == {}
    assert result.release_outcome == "held"
    assert result.reason_code == ReleaseReason.NOT_CONFIGURED
    assert sink.calls == []
    assert result.sieve.payload_in == "" and result.sieve.payload_out == ""
    assert all(g.payload_out == "" and g.payload_in == "" for g in result.sieve.gates)
    assert CLEAN not in repr(result)
    last = t.ledger.entries[-1]
    assert (last.layer, last.status) == ("TAP", "HELD")
    assert last.extra["reason_code"] == ReleaseReason.NOT_CONFIGURED


def test_attack_20_nothing_in_the_default_configuration_is_auto(mode):
    t = tower()
    assert t.tap is None and t.release_gate is None
    assert ArchitectsProtocol().mode is ReleaseMode.SEALED
    assert run(t, mode).released is False


def test_a_default_capstone_releases_nothing():
    assert ArchitectsProtocol().authorize("anything").released is False


def test_a_signature_alone_does_not_release_under_the_default(mode):
    kwargs = {"signature": "let-me-in"}
    assert run(tower(), mode, **kwargs).released is False


# --------------------------------------------------------- legacy modes are explicit only


def test_legacy_auto_still_works_when_chosen_and_says_it_authorized_nothing(mode):
    sink = Sink()
    t = tower(capstone=ArchitectsProtocol(ReleaseMode.AUTO), release_sink=sink)
    result = run(t, mode)
    assert result.released and result.output == CLEAN and len(sink.calls) == 1
    assert result.authorization == {"kind": "legacy-capstone", "mode": "auto", "enforcer_authorized": False}
    assert result.release_outcome == "released"
    tap = [e for e in t.ledger.entries if e.layer == "TAP"][-1]
    assert tap.extra["release_authority"] == "legacy-capstone:auto"
    assert tap.extra["enforcer_authorized"] is False
    assert "no authorization performed" in tap.detail


def test_legacy_sealed_and_handshake_still_hold_without_their_signal(mode):
    assert run(tower(capstone=ArchitectsProtocol(ReleaseMode.SEALED)), mode).released is False
    handshake = ArchitectsProtocol(ReleaseMode.HANDSHAKE, authority="s3cret")
    assert run(tower(capstone=handshake), mode).released is False


def test_a_legacy_sink_failure_is_unconfirmed_and_returns_no_output(mode):
    def explode(output, signature):
        raise RuntimeError("downstream failed")

    t = tower(capstone=ArchitectsProtocol(ReleaseMode.AUTO), release_sink=explode)
    result = run(t, mode)
    assert result.released is False and result.output == ""
    assert result.release_outcome == "unconfirmed"
    assert result.reason_code == ReleaseReason.ACTION_FAILED


def test_production_configuration_cannot_be_a_development_mode():
    gate = EnforcerReleaseGate(StubEnforcer(), policy_version="p1")
    auto = ArchitectsProtocol(ReleaseMode.AUTO)
    with pytest.raises(ValueError):
        DeterministicIntegrityTower("ops", release_gate=gate, capstone=auto)
    with pytest.raises(ValueError):
        DeterministicIntegrityTower("ops", require_enforcer=True, capstone=auto)
    with pytest.raises(ValueError):
        DeterministicIntegrityTower("ops", require_enforcer=True)
    DeterministicIntegrityTower("ops", release_gate=gate, require_enforcer=True, persist_ledger_key=False)


def test_the_gate_demands_its_own_configuration():
    with pytest.raises(ValueError):
        EnforcerReleaseGate(StubEnforcer(), policy_version="")
    with pytest.raises(ValueError):
        EnforcerReleaseGate(StubEnforcer(), policy_version="   ")
    with pytest.raises(TypeError):
        EnforcerReleaseGate(object(), policy_version="p1")


# ---------------------------------------------- the gate denies before touching Enforcer


def test_a_gate_with_no_release_request_denies_without_reaching_enforcer(mode):
    stub = StubEnforcer()
    sink = Sink()
    t = tower(release_gate=EnforcerReleaseGate(stub, policy_version="p1"), release_sink=sink)
    result = run(t, mode)
    assert result.released is False and result.reason_code == ReleaseReason.REQUEST_MISSING
    assert stub.calls == 0 and sink.calls == []


def test_a_sieve_breach_never_reaches_the_gate_or_the_sink(mode):
    stub = StubEnforcer()
    sink = Sink()
    t = tower(release_gate=EnforcerReleaseGate(stub, policy_version="p1"), release_sink=sink)
    result = run(t, mode, DIRTY)
    assert result.released is False and result.reason_code == ReleaseReason.SIEVE_BREACH
    assert stub.calls == 0 and sink.calls == []


def test_without_enforcer_installed_the_gate_denies(mode, monkeypatch):
    stub = StubEnforcer()
    sink = Sink()
    t = tower(release_gate=EnforcerReleaseGate(stub, policy_version="p1"), release_sink=sink)
    request = ReleaseRequest(identity=None, artifact=CNSDock().unavailable(), release_id="r1", scope="s")
    with monkeypatch.context() as m:
        m.setitem(sys.modules, "enforcer", None)
        result = run(t, mode, release=request)
    assert result.released is False and result.reason_code == ReleaseReason.ENFORCER_UNAVAILABLE
    assert stub.calls == 0 and sink.calls == []


def test_a_request_cannot_carry_both_a_proof_and_a_provider():
    with pytest.raises(ValueError):
        ReleaseRequest(identity=None, artifact=CNSDock().unavailable(), release_id="r", scope="s",
                       proof=b"x", proof_provider=lambda candidate: b"y")


@pytest.mark.parametrize("version,ok", [("0.1.0", True), ("0.1.7", True), ("0.2.0", False), ("1.0.0", False),
                                         ("0.0.9", False), (None, False), ("0.1", False), (1.0, False)])
def test_only_the_enforcer_release_line_this_was_verified_against_is_accepted(version, ok):
    assert enforcer_version_supported(version) is ok


# ------------------------------------------------------------- structure: no second path


def _calls(tree, attr):
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == attr]


def test_released_true_is_built_in_exactly_two_places_both_in_the_tower():
    """A new place that builds a released result is a new release path. This test makes it loud."""
    found = {}
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "released" and isinstance(node.value, ast.Constant) and node.value.value is True:
                found.setdefault(str(path.relative_to(PACKAGE)), []).append(node.value.lineno)
    assert list(found) == ["tower.py"], found
    assert len(found["tower.py"]) == 2, found


def test_the_release_sink_is_only_ever_called_from_the_tower_inside_a_release_path():
    tree = ast.parse((PACKAGE / "tower.py").read_text(encoding="utf-8"))
    sites = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "release_sink"]
    assert len(sites) == 2
    for path in PACKAGE.rglob("*.py"):
        if path.name != "tower.py":
            assert not _calls(ast.parse(path.read_text(encoding="utf-8")), "release_sink"), path


def test_only_the_release_module_imports_enforcer_and_only_inside_a_function():
    at_module_level, elsewhere = {}, {}
    for path in PACKAGE.rglob("*.py"):
        rel = str(path.relative_to(PACKAGE))
        tree = ast.parse(path.read_text(encoding="utf-8"))
        top = set(map(id, tree.body))
        for node in ast.walk(tree):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else []
            for name in names:
                if name == "enforcer" or name.startswith("enforcer."):
                    if id(node) in top:
                        at_module_level.setdefault(rel, []).append(name)
                    if rel != "release.py":
                        elsewhere.setdefault(rel, []).append(name)
    assert at_module_level == {} and elsewhere == {}


def _fresh(code, *, block):
    prefix = "import sys; sys.modules['enforcer'] = None; sys.modules['cns'] = None\n" if block else ""
    env = {"PYTHONPATH": str(ROOT / "src"), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-c", prefix + textwrap.dedent(code)],
                          capture_output=True, text=True, env=env, timeout=120)


def test_zts_imports_and_filters_with_enforcer_and_cns_both_blocked():
    done = _fresh("""
        import zts, zts.release, zts.cns
        from zts import ZeroTrustSieve
        assert ZeroTrustSieve("legal").run("As an AI, I may be wrong.").verdict.value == "breach"
        print('ok')
    """, block=True)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip().endswith("ok")


def test_importing_zts_does_not_load_enforcer_even_when_it_is_installed():
    done = _fresh("""
        import sys, zts, zts.release
        assert not [m for m in sys.modules if m == "enforcer" or m.startswith("enforcer.")], "enforcer was loaded"
        print('ok')
    """, block=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip().endswith("ok")


def test_the_enforcer_extra_is_pinned_to_a_commit_and_adds_no_runtime_dependency():
    import tomllib
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert meta["dependencies"] == []
    (spec,) = meta["optional-dependencies"]["enforcer"]
    assert spec.startswith("tack-enforcer @ git+https://github.com/wking53214/Enforcer.git@")
    assert len(spec.rsplit("@", 1)[1]) == 40
