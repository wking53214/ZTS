"""Operations: metrics, audit events, production validation, health.

The standard these hold to: a check says PASS only for something this process verified,
and UNKNOWN for anything only the operator can know. Nothing here is evidence about a
real deployment; it is evidence about what the report claims and refuses to claim.
"""

from __future__ import annotations

import json
import logging

import pytest

from release_kit import (
    TEXT, HmacVerifier, Sink, StatusSource, build, enforcer, request, run,
)
from zts import DeterministicIntegrityTower, EnforcerReleaseGate, ProductionConfigError, ReleaseState
from zts.ledger import ValLedger
from zts.ledger_store import FileLedgerAnchor, FileLedgerStore
from zts.ops import FAIL, PASS, UNKNOWN, audit_event


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


def by_name(report):
    return {c.name: c for c in report.checks}


# ----------------------------------------------------------- metrics and events


def test_metrics_count_outcomes_and_the_signals_an_alert_would_watch(tmp_path):
    s = build(tmp_path)
    grant = s.status and __import__("release_kit").static_grant(s)
    run(s, "sync", request(s, proof=grant, provider=None))                       # delivered
    run(s, "sync", request(s, proof=grant, provider=None))                       # replay
    run(s, "sync", request(s, "r2", provider=None))                              # no proof
    s.status.mode = "unavailable"
    run(s, "sync", request(s, "r3"))                                             # status source down
    snap = s.tower.metrics.snapshot()
    assert snap["total"] == 4
    assert snap["outcomes"] == {"delivered": 1, "denied": 3}
    assert snap["replays_detected"] == 1
    assert snap["security_denials"] == 1 + 0 and snap["availability_failures"] == 1
    assert snap["reasons"]["PROOF_MISSING"] == 1


def test_an_audit_event_has_identifiers_and_codes_and_never_the_artifact(tmp_path, mode):
    s = build(tmp_path)
    r = run(s, mode, request(s))
    event = audit_event(r, policy_version="policy-v1")
    text = json.dumps(event)
    assert TEXT not in text and "Disk utilization" not in text
    assert event["outcome"] == "delivered" and event["release_id"] == "rel-1"
    assert event["subject_digest"] == s.artifact.subject_digest
    assert event["delivery_verified"] is True and event["audit_durable"] is True
    assert event["grant_state"] == "spent" and event["authorized"] is True


def test_every_decision_is_logged_as_one_json_line_at_a_level_that_matches_it(tmp_path, caplog):
    s = build(tmp_path)
    with caplog.at_level(logging.DEBUG, logger="zts.release"):
        grant = __import__("release_kit").static_grant(s)
        run(s, "sync", request(s, proof=grant, provider=None))      # delivered      -> INFO
        run(s, "sync", request(s, proof=grant, provider=None))      # replay         -> ERROR (attack signature)
        s.status.mode = "unavailable"
        run(s, "sync", request(s, "r2"))                            # dependency out -> WARNING
    levels = [(r.levelno, json.loads(r.message)["reason_code"]) for r in caplog.records]
    assert levels == [(logging.INFO, "VERIFIED_ACTION_BOUND_GRANT"),
                      (logging.ERROR, "GRANT_REPLAYED"),
                      (logging.WARNING, "AUTHORITY_REVALIDATION_ERROR")]
    assert all(TEXT not in r.message for r in caplog.records)


def test_a_failing_log_handler_cannot_change_or_hide_a_release(tmp_path):
    s = build(tmp_path)

    class Boom(logging.Handler):
        def emit(self, record):
            raise RuntimeError("log pipeline down")

    logger = logging.getLogger("zts.release")
    handler = Boom()
    logger.addHandler(handler)
    old = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        r = s.tower.enforce(TEXT, release=request(s))
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old)
    assert r.release_outcome == ReleaseState.DELIVERED and len(s.sink.calls) == 1


# ------------------------------------------------------------ production validation


def production_parts(tmp_path, **over):
    clock = __import__("release_kit").Clock()
    verifier = type("V", (HmacVerifier,), {"verifier_id": "acme/proof-verifier"})()
    status = type("S", (StatusSource,), {"revalidator_id": "acme/status"})(clock)
    store = enforcer.SQLiteReplayStore(tmp_path / "replay.db")
    gate_enforcer = enforcer.Enforcer(verifier=verifier, revalidator=status, replay_store=store, clock=clock)
    options = dict(
        release_gate=EnforcerReleaseGate(gate_enforcer, policy_version="p1", timeout=5.0),
        production=True, release_sink=Sink(), delivery_confirmer=lambda r, d: True,
        hmac_key=b"k" * 32, persist_ledger_key=False,
        ledger=ValLedger(key=b"l" * 32, store=FileLedgerStore(tmp_path / "l.jsonl"),
                         anchor=FileLedgerAnchor(tmp_path / "a.jsonl")),
    )
    options.update(over)
    return options


def test_a_fully_configured_production_tower_starts_and_reports_what_it_cannot_vouch_for(tmp_path):
    tower = DeterministicIntegrityTower("ops", **production_parts(tmp_path))
    report = tower.readiness()
    checks = by_name(report)
    assert report.ready is True and report.failed == []
    assert report.fully_verified is False, "custom adapters and the replay store can only be UNKNOWN"
    for name in ("proof_verifier", "status_source", "replay_store"):
        assert checks[name].status == UNKNOWN, name
    for name in ("enforcer_gate", "no_legacy_release_path", "durable_ledger", "ledger_anchor",
                 "delivery_confirmer", "enforcer_timeout", "release_signature_key", "ledger_chain",
                 "ledger_anchor_match", "enforcer_importable", "cns_importable", "accepting_work"):
        assert checks[name].status == PASS, (name, checks[name].detail)
    assert tower.health()["status"] == "ok"


MISCONFIGURATIONS = {
    "enforcer_gate": dict(release_gate=None),
    "durable_ledger": dict(ledger=ValLedger(key=b"l" * 32)),
    "delivery_confirmer": dict(delivery_confirmer=None),
    "release_signature_key": dict(hmac_key=None),
}


@pytest.mark.parametrize("name", list(MISCONFIGURATIONS))
def test_production_refuses_to_start_when_a_required_control_is_missing(tmp_path, name):
    with pytest.raises(ProductionConfigError if name != "enforcer_gate" else ValueError):
        DeterministicIntegrityTower("ops", **production_parts(tmp_path, **MISCONFIGURATIONS[name]))


def test_production_refuses_an_unanchored_ledger(tmp_path):
    options = production_parts(tmp_path, ledger=ValLedger(key=b"l" * 32, store=FileLedgerStore(tmp_path / "x.jsonl")))
    with pytest.raises(ProductionConfigError, match="ledger_anchor"):
        DeterministicIntegrityTower("ops", **options)


def test_production_refuses_a_gate_with_no_timeout(tmp_path):
    parts = production_parts(tmp_path)
    gate = EnforcerReleaseGate(parts["release_gate"]._enforcer, policy_version="p1")
    with pytest.raises(ProductionConfigError, match="enforcer_timeout"):
        DeterministicIntegrityTower("ops", **{**parts, "release_gate": gate})


def test_production_refuses_enforcers_reject_everything_defaults(tmp_path):
    parts = production_parts(tmp_path)
    gate = EnforcerReleaseGate(enforcer.Enforcer(), policy_version="p1", timeout=5.0)
    with pytest.raises(ProductionConfigError, match="proof_verifier.*reject-all|reject-all"):
        DeterministicIntegrityTower("ops", **{**parts, "release_gate": gate})


def test_production_refuses_adapters_that_identify_as_test_fixtures(tmp_path):
    s = build(tmp_path)  # its verifier and status source are the kit's "tests/..." adapters
    parts = production_parts(tmp_path)
    gate = EnforcerReleaseGate(s.enforcer, policy_version="p1", timeout=5.0)
    with pytest.raises(ProductionConfigError, match="test fixture"):
        DeterministicIntegrityTower("ops", **{**parts, "release_gate": gate})


def test_production_refuses_an_in_memory_replay_store(tmp_path):
    parts = production_parts(tmp_path)
    clock = __import__("release_kit").Clock()
    verifier = type("V", (HmacVerifier,), {"verifier_id": "acme/proof-verifier"})()
    status = type("S", (StatusSource,), {"revalidator_id": "acme/status"})(clock)
    weak = enforcer.Enforcer(verifier=verifier, revalidator=status,
                             replay_store=enforcer.SQLiteReplayStore(":memory:"), clock=clock)
    with pytest.raises(ProductionConfigError, match="in-memory SQLite"):
        DeterministicIntegrityTower("ops", **{**parts, "release_gate": EnforcerReleaseGate(weak, policy_version="p1", timeout=5.0)})


def test_production_forbids_a_legacy_capstone(tmp_path):
    from zts import ArchitectsProtocol, ReleaseMode
    with pytest.raises(ValueError):
        DeterministicIntegrityTower("ops", **production_parts(tmp_path, capstone=ArchitectsProtocol(ReleaseMode.AUTO)))


def test_a_custom_replay_store_is_reported_unknown_not_pass(tmp_path):
    parts = production_parts(tmp_path)
    clock = __import__("release_kit").Clock()
    verifier = type("V", (HmacVerifier,), {"verifier_id": "acme/proof-verifier"})()
    status = type("S", (StatusSource,), {"revalidator_id": "acme/status"})(clock)

    class SharedStore:
        def consume(self, issuer_id, nonce, request_id):
            return True

    custom = enforcer.Enforcer(verifier=verifier, revalidator=status, replay_store=SharedStore(), clock=clock)
    tower = DeterministicIntegrityTower(
        "ops", **{**parts, "release_gate": EnforcerReleaseGate(custom, policy_version="p1", timeout=5.0)})
    assert by_name(tower.readiness())["replay_store"].status == UNKNOWN


# ------------------------------------------------------------------- health


def test_health_turns_degraded_when_the_ledger_is_tampered_with(tmp_path):
    tower = DeterministicIntegrityTower("ops", **production_parts(tmp_path))
    assert tower.health()["status"] == "ok"
    tower.ledger.log("T", "OK", "x")
    tower.ledger._entries[0].detail = "edited"
    health = tower.health()
    assert health["status"] == "degraded" and "ledger_chain" in health["failed"]


def test_health_catches_a_truncated_ledger_through_the_anchor(tmp_path):
    tower = DeterministicIntegrityTower("ops", **production_parts(tmp_path))
    for i in range(4):
        tower.ledger.log("T", "OK", str(i))
    del tower.ledger._entries[-1]
    health = tower.health()
    assert health["status"] == "degraded" and "ledger_anchor_match" in health["failed"]


def test_health_is_closed_after_shutdown(tmp_path):
    tower = DeterministicIntegrityTower("ops", **production_parts(tmp_path))
    assert tower.close(timeout=2) is True
    assert tower.health()["status"] == "closed"


def test_a_non_production_tower_still_reports_honestly():
    t = DeterministicIntegrityTower("ops", persist_ledger_key=False)
    checks = by_name(t.readiness())
    assert t.readiness().ready is False
    assert checks["enforcer_gate"].status == FAIL and checks["durable_ledger"].status == FAIL


def test_a_failing_observer_is_counted_not_swallowed_and_never_alters_the_release(tmp_path, monkeypatch):
    s = build(tmp_path)

    def broken(*args, **kwargs):
        raise RuntimeError("metrics backend down")

    monkeypatch.setattr(s.tower.metrics, "record", broken)
    r = s.tower.enforce(TEXT, release=request(s))
    assert r.release_outcome == ReleaseState.DELIVERED and len(s.sink.calls) == 1
    assert s.tower.metrics.snapshot()["observer_errors"] == 1
