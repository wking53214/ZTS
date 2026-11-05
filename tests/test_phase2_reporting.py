"""Phase 2 audit, package A: what ZTS reports must match what is true.

Covers: every denial code has a home in an alert bucket; readiness does not call a channel verified
when it is not; health notices a trust root or replay table that went bad after startup; the
tower's seal covers the content sieve and the signature key.
"""

from __future__ import annotations

import datetime as dt
import inspect
import json
import logging
import re
import ssl
import uuid

import pytest

from issuer_kit import IssuerKey, trust_doc
from pg_kit import cluster  # noqa: F401  (session fixture)
from release_kit import enforcer, request, run, build
from zts import DeterministicIntegrityTower, EnforcerReleaseGate
from zts.ops import (
    AVAILABILITY_REASONS, EXPECTED_REASONS, SECURITY_REASONS, ReleaseMetrics, _probe_replay_store, _probe_status,
)
from zts.release import ReleaseReason
from zts.replay_postgres import PostgresReplayStore
from zts.status import HttpStatusRevalidator
from zts.trust import Ed25519GrantVerifier, FileTrustRoot, TrustRoot


def real_now():
    return dt.datetime.now(dt.timezone.utc)


# ------------------------------------------------------------------- alert buckets


def _enforcer_codes():
    import enforcer.gate as gate

    found = set(re.findall(r'"([A-Z][A-Z_]{5,})"', inspect.getsource(gate)))
    return found - {"VERIFIED_ACTION_BOUND_GRANT"}


def test_every_denial_code_has_exactly_one_home_so_none_is_silently_unalerted():
    zts = {v for k, v in vars(ReleaseReason).items() if k.isupper() and isinstance(v, str)}
    zts.discard(ReleaseReason.ALLOWED)
    buckets = (SECURITY_REASONS, AVAILABILITY_REASONS, EXPECTED_REASONS)
    for i, a in enumerate(buckets):
        for b in buckets[i + 1:]:
            assert not (a & b), a & b
    homeless = [c for c in sorted(zts | _enforcer_codes()) if not any(c in b for b in buckets)]
    assert homeless == [], f"classify these as security, availability or expected: {homeless}"


def test_a_code_nobody_classified_is_counted_instead_of_dropped():
    m = ReleaseMetrics()
    m.record("denied", "A_BRAND_NEW_CODE")
    m.record("denied", "GRANT_REPLAYED")
    m.record("denied", "PROOF_MISSING")
    snap = m.snapshot()
    assert snap["unclassified_denials"] == 1 and snap["security_denials"] == 1 and snap["expected_denials"] == 1


def test_an_unauthenticated_identity_is_a_security_denial_and_logs_at_error(tmp_path, caplog):
    s = build(tmp_path, identity_verifier=lambda identity: False)
    with caplog.at_level(logging.DEBUG, logger="zts.release"):
        result = run(s, "sync", request(s))
    assert result.reason_code == "IDENTITY_NOT_AUTHENTICATED" and not s.sink.calls
    assert s.tower.metrics.snapshot()["security_denials"] == 1
    assert [r.levelno for r in caplog.records] == [logging.ERROR]


# -------------------------------------------------------------- readiness truthfulness


@pytest.fixture
def status_root():
    return TrustRoot.from_dict(trust_doc(IssuerKey("issuer-a", "status").entry(real_now)))


def test_the_status_client_is_only_called_verified_when_it_demands_a_certificate_and_host_name(status_root):
    url = "https://issuer.example"
    assert _probe_status(HttpStatusRevalidator(url, status_root), None).status == "PASS"

    no_check = ssl.create_default_context()
    no_check.check_hostname = False
    no_check.verify_mode = ssl.CERT_NONE  # deliberately unsafe: this is the configuration being detected
    assert _probe_status(HttpStatusRevalidator(url, status_root, ssl_context=no_check), None).status == "FAIL"

    no_host = ssl.create_default_context()
    no_host.check_hostname = False  # certificate required, host name not: still not verified
    assert _probe_status(HttpStatusRevalidator(url, status_root, ssl_context=no_host), None).status == "FAIL"

    opaque = HttpStatusRevalidator(url, status_root, transport=lambda u, b, t: b"")
    check = _probe_status(opaque, None)
    assert check.status == "UNKNOWN" and "cannot see" in check.detail


@pytest.mark.parametrize("mode,expected", [("verify-full", "PASS"), ("verify-ca", "UNKNOWN"),
                                           ("require", "FAIL"), ("prefer", "FAIL")])
def test_only_verify_full_counts_as_a_verified_database_connection(mode, expected, monkeypatch):
    store = PostgresReplayStore(f"host=db.example port=5432 user=x dbname=y sslmode={mode}", create=False)
    monkeypatch.setattr(store, "health", lambda: True)
    tls = [c for c in _probe_replay_store(store) if c.name == "replay_store_tls"][0]
    assert tls.status == expected
    if mode == "verify-ca":
        assert "host name" in tls.detail


# ------------------------------------------------------------ live health of adapters


def _tower(tmp_path, root, store):
    enf = enforcer.Enforcer(verifier=Ed25519GrantVerifier(root), revalidator=_NoStatus(), replay_store=store)
    return DeterministicIntegrityTower(
        "ops", release_gate=EnforcerReleaseGate(enf, policy_version="p1", timeout=2.0),
        require_enforcer=True, hmac_key=b"k" * 32, persist_ledger_key=False)


class _NoStatus:
    revalidator_id = "tests/no-status"

    def revalidate(self, envelope, claims):
        raise RuntimeError("not used")


def _write(path, doc):
    import os
    import time

    time.sleep(0.01)
    path.write_text(json.dumps(doc))
    os.chmod(path, 0o644)


def test_health_notices_when_the_trust_root_stops_having_a_usable_key(tmp_path):
    key = IssuerKey("issuer-a", "grant")
    path = tmp_path / "trust.json"
    _write(path, trust_doc(key.entry(real_now)))
    tower = _tower(tmp_path, FileTrustRoot(path), enforcer.SQLiteReplayStore(tmp_path / "r.db"))
    assert tower.health()["status"] == "ok"

    _write(path, trust_doc(key.entry(real_now, status="revoked")))  # a revocation, or a bad edit
    health = tower.health()
    assert health["status"] == "degraded" and "trust_root_grant_keys" in health["failed"]

    path.write_text("{ not json")  # a broken file refuses everything; health must say so too
    health = tower.health()
    assert health["status"] == "degraded" and "trust_root_grant_keys" in health["failed"]

    _write(path, trust_doc(key.entry(real_now)))
    assert tower.health()["status"] == "ok"


def test_health_notices_when_the_replay_table_loses_a_constraint_after_startup(cluster, tmp_path):
    import psycopg

    key = IssuerKey("issuer-a", "grant")
    root = TrustRoot.from_dict(trust_doc(key.entry(real_now)))
    table = "t_" + uuid.uuid4().hex[:12]
    store = PostgresReplayStore(cluster.dsn, table=table)
    tower = _tower(tmp_path, root, store)
    assert tower.health()["status"] == "ok"
    with psycopg.connect(cluster.dsn, autocommit=True) as c:
        for (name,) in c.execute("SELECT conname FROM pg_constraint WHERE conrelid = to_regclass(%s) AND contype IN ('p', 'u')", (table,)).fetchall():
            c.execute(f'ALTER TABLE {table} DROP CONSTRAINT "{name}"')
    health = tower.health()
    assert health["status"] == "degraded" and "replay_store_live" in health["failed"]


# ------------------------------------------------------------------------- the seal


@pytest.mark.parametrize("name", ["zts", "kg", "lc", "_key", "_key_id", "_sealed"])
def test_the_seal_covers_the_content_sieve_the_budget_and_the_signature_key(tmp_path, name):
    s = build(tmp_path)
    before = getattr(s.tower, name)
    with pytest.raises(AttributeError, match="fixed after construction"):
        setattr(s.tower, name, object() if name != "_sealed" else False)
    assert getattr(s.tower, name) is before


def test_known_limit_reaching_inside_a_sealed_object_is_not_blocked(tmp_path):
    """The seal stops assignment to the tower. It does not freeze the objects it holds: code that can run
    in this process can still change them. Containing that is process isolation, not this class."""
    s = build(tmp_path)
    s.tower.zts.run = lambda *a, **k: None  # allowed: an attribute of the sieve, not of the tower
    assert s.tower.zts.run() is None
