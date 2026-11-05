"""Readiness uses Enforcer's public `describe()`, and its private reads are confined and cannot make a PASS.

Audit item I3: ZTS's readiness probes read several private Enforcer attributes, and never looked at
Enforcer's own limits. Now: ids, limits and the replay store come from `describe()`; the few reads
that remain (the adapter objects, which Enforcer does not expose) are in two documented helpers; and
a fact taken from `describe()` can only produce FAIL or UNKNOWN, never PASS, because a custom adapter
can claim anything about itself.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from release_kit import enforcer
from zts import EnforcerReleaseGate
from zts.ops import (
    RECOMMENDED_LIMITS, _describe, _probe_enforcer, _probe_policy, _probe_replay_store, _probe_verifier,
)

NEW = hasattr(enforcer.Enforcer, "describe")
needs_describe = pytest.mark.skipif(not NEW, reason="Enforcer.describe() needs Enforcer 0.1.1 or later")
SRC = Path(__file__).resolve().parents[1] / "src" / "zts"


class Verifier:
    verifier_id = "custom/verifier-1"

    def verify_and_decode(self, proof):
        raise enforcer.ProofVerificationError("never")


class Status:
    revalidator_id = "custom/status-1"

    def revalidate(self, envelope, claims):
        raise RuntimeError("never")


def gate_for(*, policy=None, store=None, verifier=None):
    enf = enforcer.Enforcer(verifier=verifier or Verifier(), revalidator=Status(),
                            replay_store=store or enforcer.SQLiteReplayStore(), policy=policy)
    return EnforcerReleaseGate(enf, policy_version="p1", timeout=2.0)


def states(checks):
    return {c.name: c.status for c in checks}


# --------------------------------------------------------------------- Enforcer's limits


@needs_describe
def test_limits_at_or_below_the_recommended_ones_pass():
    check = _probe_policy(_describe(gate_for()))
    assert check.status == "PASS", check.detail


@needs_describe
@pytest.mark.parametrize("loosen,mention", [
    ({"max_grant_lifetime": 900}, "max_grant_lifetime 900s"),
    ({"allowed_clock_skew": 60}, "allowed_clock_skew 60s"),
    ({"max_revalidation_age": 600}, "max_revalidation_age 600s"),
])
def test_a_looser_limit_is_unknown_and_named_never_fail(loosen, mention):
    from datetime import timedelta
    policy = enforcer.GatePolicy(**{k: timedelta(seconds=v) for k, v in loosen.items()})
    check = _probe_policy(_describe(gate_for(policy=policy)))
    assert check.status == "UNKNOWN" and mention in check.detail and "confirm it is intended" in check.detail


@needs_describe
def test_tighter_limits_still_pass():
    from datetime import timedelta
    policy = enforcer.GatePolicy(max_grant_lifetime=timedelta(seconds=60), max_revalidation_age=timedelta(seconds=10))
    assert _probe_policy(_describe(gate_for(policy=policy))).status == "PASS"


def test_the_recommended_limits_are_enforcers_own_defaults():
    if not NEW:
        pytest.skip("needs describe()")
    d = _describe(gate_for())["policy"]
    assert {k: d[k] for k in RECOMMENDED_LIMITS} == RECOMMENDED_LIMITS


def test_an_enforcer_that_cannot_describe_itself_is_unknown_not_a_crash():
    class Mute:
        def execute(self, *a, **k):
            raise AssertionError("not used")

    class Broken(Mute):
        def describe(self):
            raise RuntimeError("boom")

    for stub in (Mute(), Broken()):
        gate = EnforcerReleaseGate(stub, policy_version="p1", timeout=2.0)
        assert _describe(gate) is None
        found = states(_probe_enforcer(gate))
        assert found["enforcer_policy"] == "UNKNOWN"
        assert "PASS" not in found.values(), found


# --------------------------------------------------- facts from describe() can never pass


class Claiming:
    """A replay store that says whatever it likes about itself."""

    def __init__(self, claim):
        self._claim = claim

    def consume(self, issuer_id, nonce, request_id):
        return True

    def describe(self):
        return self._claim


@needs_describe
@pytest.mark.parametrize("claim", [
    {"kind": "postgresql", "durable": True, "shared": True, "host": "db.example", "sslmode": "verify-full"},
    {"kind": "sqlite", "durable": True, "shared": False},
    {"kind": "anything", "durable": True, "shared": True},
])
def test_a_store_describing_itself_as_excellent_never_earns_a_pass(claim):
    gate = gate_for(store=Claiming(claim))
    found = states(_probe_enforcer(gate))
    assert found["replay_store"] in ("UNKNOWN",), found
    assert "replay_store_tls" not in found, "TLS facts come only from a real PostgresReplayStore object"


@needs_describe
def test_a_store_describing_itself_as_in_memory_fails():
    found = states(_probe_enforcer(gate_for(store=Claiming({"kind": "sqlite", "durable": False}))))
    assert found["replay_store"] == "FAIL"


@pytest.mark.parametrize("backed,expected", [(False, "FAIL"), (True, "UNKNOWN")])
def test_enforcers_own_sqlite_store_is_judged_on_every_supported_release(tmp_path, backed, expected):
    store = enforcer.SQLiteReplayStore(tmp_path / "r.db") if backed else enforcer.SQLiteReplayStore()
    assert states(_probe_enforcer(gate_for(store=store)))["replay_store"] == expected


def test_a_custom_verifier_copying_a_zts_identifier_does_not_pass():
    class Lookalike:
        verifier_id = "zts-ed25519/0123456789ab"
    check = _probe_verifier(Lookalike(), "zts-ed25519/0123456789ab")
    assert check.status == "UNKNOWN" and "custom verifier" in check.detail


def test_reject_all_and_fixture_identifiers_still_fail_from_the_description():
    assert _probe_verifier(None, "reject-all/unconfigured").status == "FAIL"
    assert _probe_verifier(None, "tests/hmac").status == "FAIL"
    assert _probe_verifier(None, None).status == "UNKNOWN"


def test_the_replay_store_probe_survives_a_description_that_is_not_a_dict():
    assert _probe_replay_store(Claiming("nonsense"), "nonsense", True)[0].status == "UNKNOWN"


# ------------------------------------------------------------------- what is private


def test_private_attributes_are_read_in_two_documented_places_only():
    """ops.py may reach into another object's private attributes only in `_adapters` (the three Enforcer
    adapters Enforcer does not expose) and `_sqlite_durability` (Enforcer 0.1.0, which cannot describe itself)."""
    allowed = {"_adapters": {"_verifier", "_revalidator", "_replay_store"}, "_sqlite_durability": {"_connection"}}
    tree = ast.parse((SRC / "ops.py").read_text(encoding="utf-8"))
    offenders = []

    def visit(node, owner):
        for child in ast.iter_child_nodes(node):
            name = child.name if isinstance(child, ast.FunctionDef) else owner
            hit = None
            if isinstance(child, ast.Attribute) and child.attr.startswith("_") and not child.attr.startswith("__"):
                if not (isinstance(child.value, ast.Name) and child.value.id == "self"):
                    hit = child.attr
            if (isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == "getattr"
                    and len(child.args) >= 2 and isinstance(child.args[1], ast.Constant)
                    and isinstance(child.args[1].value, str) and child.args[1].value.startswith("_")):
                hit = child.args[1].value
            if hit is not None and hit not in allowed.get(owner or "", set()):
                offenders.append((owner, hit))
            visit(child, name)
    visit(tree, None)
    assert offenders == [], offenders


def test_the_public_accessors_exist_and_cannot_be_assigned(tmp_path):
    from issuer_kit import IssuerKey, trust_doc
    from release_kit import Clock, build
    from zts.status import HttpStatusRevalidator
    from zts.trust import Ed25519GrantVerifier, TrustRoot

    s = build(tmp_path)
    gate = s.tower.release_gate
    assert gate.enforcer is s.enforcer and gate.dock is gate._dock
    assert s.tower.ledger.anchor is None and s.tower.release_signature_key_supplied is True
    for target, name in ((gate, "enforcer"), (gate, "dock"), (s.tower.ledger, "anchor"),
                         (s.tower, "release_signature_key_supplied")):
        with pytest.raises(AttributeError):
            setattr(target, name, object())
    clock = Clock()
    root = TrustRoot.from_dict(trust_doc(IssuerKey("a", "grant").entry(clock), IssuerKey("a", "status").entry(clock)))
    assert Ed25519GrantVerifier(root).trust is root
    assert HttpStatusRevalidator("https://issuer.example", root).trust is root
    with pytest.raises(AttributeError):
        Ed25519GrantVerifier(root).trust = root


@pytest.mark.parametrize("policy", [
    {"max_grant_lifetime_seconds": 300.0, "allowed_clock_skew_seconds": 5.0},  # one limit missing
    {"max_grant_lifetime_seconds": "300", "allowed_clock_skew_seconds": 5.0, "max_revalidation_age_seconds": 30.0},
    {"max_grant_lifetime_seconds": True, "allowed_clock_skew_seconds": 5.0, "max_revalidation_age_seconds": 30.0},
    {"max_grant_lifetime_seconds": None, "allowed_clock_skew_seconds": 5.0, "max_revalidation_age_seconds": 30.0},
    "not a mapping",
])
def test_a_limit_that_cannot_be_read_is_unknown_never_assumed_fine(policy):
    check = _probe_policy({"policy": policy})
    assert check.status == "UNKNOWN", check


def test_a_description_that_is_not_a_mapping_is_treated_as_no_description():
    class Odd:
        def execute(self, *a, **k):
            raise AssertionError("not used")

        def describe(self):
            return "nonsense"

    assert _describe(EnforcerReleaseGate(Odd(), policy_version="p1", timeout=2.0)) is None
