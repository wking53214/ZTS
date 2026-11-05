"""The production tower assembled from the real components, attacked end to end.

Real here: the Ed25519 grant verifier and trust root, the HTTPS signed status client, the
PostgreSQL replay store (a real server), the durable ledger, the RFC 3161 anchor, Enforcer,
CNS, and `production=True` startup validation.
Fixtures here, and named as such: the issuer and status service (issuer_kit), the TSA
(OpenSSL behind tsa_kit), and the receiving side. They prove the code against independent
implementations. They prove nothing about a real issuer, authority, TSA or deployment.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from issuer_kit import IssuerKey, StatusService, sign_grant, trust_doc
from pg_kit import cluster  # noqa: F401
from release_kit import SCOPE, TEXT, Sink, enforcer, make_identity, run, tap_entries
from tsa_kit import Tsa
from zts import DeterministicIntegrityTower, EnforcerReleaseGate, KineticGovernor, ReleaseRequest
from zts.anchor_tsa import Rfc3161Anchor
from zts.cns import CNSDock
from zts.ledger import ValLedger
from zts.ledger_store import FileLedgerStore
from zts.replay_postgres import PostgresReplayStore
from zts.status import HttpStatusRevalidator
from zts.trust import Ed25519GrantVerifier, TrustRoot


def now():
    return datetime.now(timezone.utc)


class Shared:
    """What the hosts have in common: the issuer, the status service, the TSA and the database."""

    def __init__(self, tmp, cluster):
        self.grant_key, self.status_key = IssuerKey("issuer-a", "grant"), IssuerKey("issuer-a", "status")
        self.root = TrustRoot.from_dict(trust_doc(self.grant_key.entry(now), self.status_key.entry(now)))
        (tmp / "svc").mkdir()
        self.svc = StatusService(tmp / "svc", self.status_key, now)
        (tmp / "tsa").mkdir()
        self.tsa = Tsa(tmp / "tsa")
        self.table = "t_" + __import__("uuid").uuid4().hex[:12]
        self.cluster = cluster
        self.identity = make_identity()
        self.artifact = CNSDock().to_zts_artifact(self.identity)

    def close(self):
        self.svc.close()
        self.tsa.close()


class Host:
    """One release host: its own Enforcer, tower, ledger, receipts and sink."""

    def __init__(self, shared: Shared, directory, *, production=True, **overrides):
        directory.mkdir(exist_ok=True)
        self.shared, self.sink = shared, Sink()
        self.replay = PostgresReplayStore(shared.cluster.dsn, table=shared.table)
        self.anchor = Rfc3161Anchor(shared.tsa.url, [shared.tsa.pem.read_bytes()], directory / "receipts.jsonl",
                                    min_interval=3600, timeout=5.0)  # lazy: the end-of-release flush does the work
        self.ledger = ValLedger(key=b"l" * 32, store=FileLedgerStore(directory / "ledger.jsonl"), anchor=self.anchor)
        self.status = HttpStatusRevalidator(shared.svc.url, shared.root, timeout=2.0,
                                            ssl_context=shared.svc.client_context())
        self.enforcer = enforcer.Enforcer(verifier=Ed25519GrantVerifier(shared.root), revalidator=self.status,
                                          replay_store=self.replay)
        options = dict(
            release_gate=EnforcerReleaseGate(self.enforcer, policy_version="policy-v1", timeout=5.0),
            production=production, require_enforcer=True, release_sink=self.sink,
            delivery_confirmer=lambda rid, digest: digest in {
                __import__("hashlib").sha256(o.encode()).hexdigest() for o, _ in self.sink.calls},
            hmac_key=b"k" * 32, persist_ledger_key=False, ledger=self.ledger,
            governor=KineticGovernor(ceiling_seconds=0.001))
        options.update(overrides)
        self.tower = DeterministicIntegrityTower("ops", **options)
        self.captured_grants: dict[str, bytes] = {}

    def request(self, release_id="rel-1", *, key=None, **grant_options):
        key = key or self.shared.grant_key

        def provide(candidate):
            proof = sign_grant(enforcer.ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes), now, key,
                               nonce=f"nonce-{release_id}", **grant_options)
            self.captured_grants[release_id] = proof
            return proof

        return ReleaseRequest(identity=self.shared.identity, artifact=self.shared.artifact,
                              release_id=release_id, scope=SCOPE, proof_provider=provide)

    def close(self):
        self.tower.close(timeout=5)
        self.replay.close()


@pytest.fixture
def world(tmp_path, cluster):
    shared = Shared(tmp_path, cluster)
    hosts = []

    def make(name="a", **kw):
        h = Host(shared, tmp_path / name, **kw)
        hosts.append(h)
        return h

    yield type("W", (), dict(shared=shared, make=staticmethod(make), tmp=tmp_path))
    for h in hosts:
        h.close()
    shared.close()


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


# ------------------------------------------------------------ the assembled system


def test_a_tower_built_from_the_real_components_passes_production_validation(world):
    host = world.make()
    report = host.tower.readiness()
    states = {c.name: c.status for c in report.checks}
    assert report.ready, [(c.name, c.detail) for c in report.failed]
    for name in ("enforcer_gate", "no_legacy_release_path", "durable_ledger", "ledger_anchor", "delivery_confirmer",
                 "enforcer_timeout", "release_signature_key", "proof_verifier", "status_source", "replay_store",
                 "anchor_kind", "ledger_chain", "ledger_anchor_match"):
        assert states[name] == "PASS", (name, [c.detail for c in report.checks if c.name == name])
    # "anchor_service" is UNKNOWN until the TSA has answered once: a fresh tower has not tested it.
    for name in ("trust_root_governance", "identity_authentication", "anchor_independence", "replay_store_tls",
                 "anchor_service"):
        assert states[name] == "UNKNOWN", name
    assert report.fully_verified is False, "governance and independence can only be established by people"


def test_a_release_is_delivered_confirmed_durable_and_anchored(world, mode):
    host = world.make()
    r = run(host, mode, host.request())
    assert r.release_outcome == "delivered" and r.delivery_verified and r.audit_durable and r.audit_anchored
    assert len(host.sink.calls) == 1
    assert host.ledger.verify_anchored()[0] is True
    event = r.authorization["decision"]
    assert event["verifier_id"].startswith("zts-ed25519/") and event["revalidator_id"] == "zts-http-status/localhost"
    # a restart: a fresh ledger object over the same files still verifies against the same receipts
    reopened = ValLedger(key=b"l" * 32, store=FileLedgerStore(world.tmp / "a" / "ledger.jsonl"), anchor=host.anchor)
    assert reopened.verify_anchored()[0] is True


# ---------------------------------------------------- attacks against the real stack


ATTACKS = {
    "forged grant": dict(key="forger"), "revoked authorization": dict(svc="revoked"),
    "stale status": dict(svc="stale"), "status outage": dict(svc="http500"),
    "unknown status answer": dict(svc="bad-sig"),
}


@pytest.mark.parametrize("attack", list(ATTACKS))
def test_attacks_against_the_assembled_stack_never_reach_the_delivery_callback(world, mode, attack):
    host = world.make()
    spec = ATTACKS[attack]
    if "svc" in spec:
        world.shared.svc.mode = spec["svc"]
    key = IssuerKey("issuer-a", "grant") if spec.get("key") == "forger" else None
    if key is not None:
        key.kid = world.shared.grant_key.kid
    r = run(host, mode, host.request(key=key))
    assert r.released is False and r.output == "" and host.sink.calls == []
    assert r.release_outcome == "denied"
    assert tap_entries(host)[-1].status == "HELD"
    assert host.tower.ledger.verify_anchored()[0] is True, "the denial is on the anchored record too"


def test_a_grant_replayed_on_a_second_host_is_denied_through_the_shared_database(world, mode):
    a, b = world.make("a"), world.make("b")
    assert run(a, mode, a.request("rel-1")).released
    replay_request = b.request("rel-1")
    replay_request = ReleaseRequest(**{**replay_request.__dict__, "proof_provider": None,
                                       "proof": a.captured_grants["rel-1"]})
    r = run(b, mode, replay_request)
    assert r.reason_code == "GRANT_REPLAYED" and b.sink.calls == [] and len(a.sink.calls) == 1


def test_two_complete_hosts_racing_for_one_grant_deliver_it_once(world):
    a, b = world.make("a"), world.make("b")
    proof = None

    def mint(candidate):
        return sign_grant(enforcer.ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes), now,
                          world.shared.grant_key, nonce="shared-nonce")

    first = a.request("rel-1")
    proof = mint(type("C", (), {"envelope_bytes": enforcer.ActionEnvelope.from_canonical_bytes(
        __import__("release_kit").envelope_for(TEXT, world.shared.artifact, release_id="rel-1").canonical_bytes()
    ).canonical_bytes()}))
    barrier = threading.Barrier(8)

    def attempt(host):
        barrier.wait()
        req = ReleaseRequest(identity=first.identity, artifact=first.artifact, release_id="rel-1", scope=SCOPE, proof=proof)
        return host.tower.enforce(TEXT, release=req)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(attempt, [a, b] * 4))
    assert sum(r.released for r in results) == 1
    assert len(a.sink.calls) + len(b.sink.calls) == 1
    assert all(r.reason_code == "GRANT_REPLAYED" for r in results if not r.released)


def test_a_replay_database_outage_denies_everything_and_recovers(world, mode):
    host = world.make()
    host.replay._dsn = "host=127.0.0.1 port=1 user=zts dbname=postgres connect_timeout=1"
    host.replay.close()
    r = run(host, mode, host.request("rel-1"))
    assert r.reason_code == "REPLAY_STORE_ERROR" and host.sink.calls == []
    host.replay._dsn = world.shared.cluster.dsn
    assert run(host, mode, host.request("rel-2")).released
    assert tap_entries(host)[-1].status == "RELEASED"


def test_an_identity_check_that_fails_stops_the_release_before_any_authority_is_asked(world, mode):
    host = world.make()
    gate = EnforcerReleaseGate(host.enforcer, policy_version="policy-v1", timeout=5.0, identity_verifier=lambda i: False)
    other = world.make("c", release_gate=gate)
    r = run(other, mode, other.request("rel-1"))
    assert r.reason_code == "IDENTITY_NOT_AUTHENTICATED" and other.sink.calls == []
    assert world.shared.svc.requests == [], "the status service was never asked"


# ------------------------------------------------------- the audit trail under attack


def test_the_tsa_being_down_does_not_undo_a_delivery_but_is_reported_everywhere(world, mode):
    host = world.make()
    world.shared.tsa.mode = "http500"
    r = run(host, mode, host.request())
    assert r.released and r.audit_durable is True and r.audit_anchored is False
    assert len(host.sink.calls) == 1
    assert host.tower.metrics.snapshot()["anchor_failures"] == 1
    health = host.tower.health()
    assert health["status"] == "degraded" and "anchor_service" in health["failed"]
    world.shared.tsa.mode = "normal"
    assert run(host, mode, host.request("rel-2")).audit_anchored is True
    assert host.tower.health()["status"] == "ok"


def test_truncating_the_ledger_after_a_release_is_detected_through_the_real_timestamps(world, mode):
    host = world.make()
    run(host, mode, host.request("rel-1"))
    path = world.tmp / "a" / "ledger.jsonl"
    rows = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(rows[:-1]))  # remove the RELEASED record
    victim = ValLedger(key=b"l" * 32, store=FileLedgerStore(path), anchor=host.anchor)
    assert victim.verify()[0] is True
    ok, reason = victim.verify_anchored()
    assert ok is False and "truncated" in reason


def test_editing_a_ledger_entry_is_detected(world, mode):
    host = world.make()
    run(host, mode, host.request("rel-1"))
    host.ledger._entries[3].detail = "edited"
    assert host.tower.health()["status"] == "degraded"
    assert "ledger_chain" in host.tower.health()["failed"]


def test_every_release_is_stamped_by_the_tsa_at_the_end_of_the_release(world, mode):
    host = world.make()
    before = world.shared.tsa.requests
    run(host, mode, host.request("rel-1"))
    run(host, mode, host.request("rel-2"))
    assert world.shared.tsa.requests > before
    receipts = host.anchor.verify_all()
    assert receipts[-1][0] == len(host.ledger) - 1, "the newest receipt covers the final record"


def test_production_validation_refuses_when_a_real_component_is_missing_or_weak(world):
    from zts import ProductionConfigError
    with pytest.raises(ProductionConfigError, match="delivery_confirmer"):
        world.make("x", delivery_confirmer=None)
    shared = world.shared
    empty = TrustRoot.from_dict(trust_doc())
    weak = enforcer.Enforcer(verifier=Ed25519GrantVerifier(empty),
                             revalidator=HttpStatusRevalidator(shared.svc.url, shared.root, ssl_context=shared.svc.client_context()),
                             replay_store=PostgresReplayStore(shared.cluster.dsn, table=shared.table))
    gate = EnforcerReleaseGate(weak, policy_version="policy-v1", timeout=5.0)
    with pytest.raises(ProductionConfigError, match="no usable grant key"):
        world.make("y", release_gate=gate)


def test_production_refuses_a_replay_table_that_has_lost_a_uniqueness_constraint(world):
    """Without UNIQUE(request_id) a release id could be reused. The tower must not start on that table."""
    import psycopg
    from zts.replay_postgres import ReplayStoreError
    PostgresReplayStore(world.shared.cluster.dsn, table=world.shared.table).close()
    with psycopg.connect(world.shared.cluster.dsn, autocommit=True) as c:
        c.execute(f"ALTER TABLE {world.shared.table} DROP CONSTRAINT {world.shared.table}_request_id_key")
    # The store itself now refuses such a table when it is built, before the tower's startup validation runs.
    with pytest.raises(ReplayStoreError, match="uniqueness constraints"):
        world.make("z")
