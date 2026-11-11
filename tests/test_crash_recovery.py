"""A real process killed in the middle of a delivery, and what the next process finds.

Until now the suite stopped a release by exceptions inside one process. This kills a real host with
SIGKILL while its delivery callback is running, then opens the same ledger, replay table and receipts from
a fresh process. Real here: PostgreSQL, the Ed25519 trust root, the HTTPS status client, the RFC 3161
anchor (OpenSSL's TSA), the ledger file. Fixtures: the issuer, status service and receiving side.

What a hard kill leaves is the point: no process was alive to record `delivery_unknown`, so the ledger holds
`ATTEMPT` and `RELEASING` for the release and nothing after them. An operator finds it with the helper in
docs/DEPLOYMENT.md.
"""

from __future__ import annotations

import base64
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from issuer_kit import IssuerKey, StatusService, sign_grant, trust_doc  # skips this module without cryptography
from cryptography.hazmat.primitives import serialization  # noqa: I001
from pg_kit import cluster  # noqa: F401  (session fixture)
from release_kit import SCOPE, TEXT, enforcer, make_identity
from tsa_kit import Tsa
from zts import DeterministicIntegrityTower, EnforcerReleaseGate, KineticGovernor, ReleaseRequest
from zts.anchor_tsa import Rfc3161Anchor
from zts.cns import CNSDock
from zts.ledger import ValLedger
from zts.ledger_store import FileLedgerStore
from zts.replay_postgres import PostgresReplayStore
from zts.status import HttpStatusRevalidator
from zts.trust import Ed25519GrantVerifier, TrustRoot

HOST = Path(__file__).resolve().parent / "crash_host.py"
GUIDE = Path(__file__).resolve().parents[1] / "docs" / "DEPLOYMENT.md"


def now():
    return datetime.now(timezone.utc)


def unfinished_releases(ledger):
    """The helper the guide shows, taken from the guide itself so the two cannot drift."""
    code = re.search(r"```python\n# verified-function\n(.*?)```", GUIDE.read_text(encoding="utf-8"), re.S).group(1)
    scope: dict = {}
    exec(compile(code, "<guide>", "exec"), scope)  # noqa: S102
    return scope["unfinished_releases"](ledger)


def test_a_host_killed_mid_delivery_leaves_a_verifiable_ledger_a_spent_grant_and_a_findable_release(tmp_path, cluster):
    grant, status = IssuerKey("issuer-a", "grant"), IssuerKey("issuer-a", "status")
    doc = trust_doc(grant.entry(now), status.entry(now))
    root = TrustRoot.from_dict(doc)
    for name in ("svc", "tsa", "host"):
        (tmp_path / name).mkdir()
    svc, tsa = StatusService(tmp_path / "svc", status, now), Tsa(tmp_path / "tsa")
    table, rid = "t_" + uuid.uuid4().hex[:12], "rel-crash-1"
    PostgresReplayStore(cluster.dsn, table=table).close()
    seed = grant.private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                       serialization.NoEncryption())
    cfg = dict(dir=str(tmp_path / "host"), dsn=cluster.dsn, table=table, release_id=rid, trust_doc=doc,
               grant_seed=base64.b64encode(seed).decode(), grant_kid=grant.kid,
               grant_pub=base64.b64encode(grant.raw).decode(), tsa_url=tsa.url, tsa_pem=str(tsa.pem),
               status_url=svc.url, ca=str(svc.ca))
    (tmp_path / "cfg.json").write_text(json.dumps(cfg))
    host = subprocess.Popen([sys.executable, str(HOST), str(tmp_path / "cfg.json")],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        started = tmp_path / "host" / "STARTED"
        deadline = time.time() + 60
        while not started.exists() and time.time() < deadline and host.poll() is None:
            time.sleep(0.05)
        assert started.exists(), ("the host never reached the delivery callback", host.poll(),
                                  host.stderr.read() if host.poll() is not None else "")
        os.kill(host.pid, signal.SIGKILL)  # no handler runs, nothing is flushed, no final entry is written
        host.wait(timeout=10)
        assert host.returncode == -signal.SIGKILL

        # ---- a fresh process opens the same files
        anchor = Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "host" / "receipts.jsonl",
                               min_interval=3600, timeout=5.0)
        ledger = ValLedger(key=b"l" * 32, store=FileLedgerStore(tmp_path / "host" / "ledger.jsonl"), anchor=anchor)
        assert ledger.verify()[0] is True and ledger.verify_anchored()[0] is True
        tap = [(e.status, e.extra.get("release_id")) for e in ledger.entries if e.layer == "TAP"]
        assert tap == [("ATTEMPT", rid), ("RELEASING", rid)], "a delivery began and nothing records how it ended"
        assert unfinished_releases(ledger) == [rid], "and the operator's helper finds exactly that release"

        # ---- the grant is spent: the same one cannot be used again, by anyone
        store = PostgresReplayStore(cluster.dsn, table=table, create=False)
        assert store.consume("issuer-a", "nonce-" + rid, rid) is False
        enf = enforcer.Enforcer(
            verifier=Ed25519GrantVerifier(root), replay_store=store,
            revalidator=HttpStatusRevalidator(svc.url, root, timeout=2.0, ssl_context=svc.client_context()))
        delivered: list[str] = []
        tower = DeterministicIntegrityTower(
            "ops", release_gate=EnforcerReleaseGate(enf, policy_version="policy-v1", timeout=10.0),
            production=True, require_enforcer=True, release_sink=lambda output, sig: delivered.append(output),
            delivery_confirmer=lambda r, digest: bool(delivered), hmac_key=b"k" * 32, persist_ledger_key=False,
            ledger=ledger, governor=KineticGovernor(ceiling_seconds=0.001))
        identity = make_identity()
        artifact = CNSDock().to_zts_artifact(identity)
        proof = (tmp_path / "host" / "grant.bin").read_bytes()
        retry = tower.enforce(TEXT, release=ReleaseRequest(identity=identity, artifact=artifact, release_id=rid,
                                                           scope=SCOPE, proof=proof))
        assert retry.reason_code == "GRANT_REPLAYED" and delivered == []

        # ---- a new release under a new grant works, and the chain carries on unbroken
        def provide(candidate):
            return sign_grant(enforcer.ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes), now, grant,
                              nonce="nonce-" + candidate.release_id)
        fresh = tower.enforce(TEXT, release=ReleaseRequest(identity=identity, artifact=artifact,
                                                           release_id="rel-after-crash", scope=SCOPE,
                                                           proof_provider=provide))
        assert fresh.release_outcome == "delivered" and fresh.audit_anchored and len(delivered) == 1
        assert ledger.verify()[0] is True and ledger.verify_anchored()[0] is True
        assert tower.health()["status"] == "ok"
        assert unfinished_releases(ledger) == [rid], "only the killed release is still unfinished"
        store.close()
    finally:
        if host.poll() is None:
            host.kill()
        svc.close()
        tsa.close()
