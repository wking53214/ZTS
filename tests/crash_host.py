"""A real release host in its own process, for tests/test_crash_recovery.py.

It delivers through a sink that announces it has started and then hangs, so the test can kill the process
in the middle of a delivery. Not a test module: pytest does not collect it.
"""
# ruff: noqa: E402  (the import path is set from the config file before the project is imported)
import base64
import json
import ssl
import sys
import time
from pathlib import Path

cfg = json.load(open(sys.argv[1]))
sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "src"), str(Path(__file__).resolve().parent)]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import enforcer
from issuer_kit import IssuerKey, sign_grant
from release_kit import SCOPE, TEXT, make_identity
from zts import DeterministicIntegrityTower, EnforcerReleaseGate, KineticGovernor, ReleaseRequest
from zts.anchor_tsa import Rfc3161Anchor
from zts.cns import CNSDock
from zts.ledger import ValLedger
from zts.ledger_store import FileLedgerStore
from zts.replay_postgres import PostgresReplayStore
from zts.status import HttpStatusRevalidator
from zts.trust import Ed25519GrantVerifier, TrustRoot
from datetime import datetime, timezone  # noqa: E402


def now():
    return datetime.now(timezone.utc)


root = TrustRoot.from_dict(cfg["trust_doc"])
key = IssuerKey("issuer-a", "grant")
key.private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(cfg["grant_seed"]))
key.kid, key.raw = cfg["grant_kid"], base64.b64decode(cfg["grant_pub"])
anchor = Rfc3161Anchor(cfg["tsa_url"], [open(cfg["tsa_pem"], "rb").read()], cfg["dir"] + "/receipts.jsonl",
                       min_interval=3600, timeout=5.0)
ledger = ValLedger(key=b"l" * 32, store=FileLedgerStore(cfg["dir"] + "/ledger.jsonl"), anchor=anchor)
status = HttpStatusRevalidator(cfg["status_url"], root, timeout=2.0, ssl_context=ssl.create_default_context(cafile=cfg["ca"]))
enf = enforcer.Enforcer(verifier=Ed25519GrantVerifier(root), revalidator=status,
                        replay_store=PostgresReplayStore(cfg["dsn"], table=cfg["table"], create=False))
sunk = []
def sink(output, signature):
    open(cfg["dir"] + "/STARTED", "w").write("delivering")   # the callback has begun
    time.sleep(3600)                                          # ...and never finishes: the process is killed here
tower = DeterministicIntegrityTower(
    "ops", release_gate=EnforcerReleaseGate(enf, policy_version="policy-v1", timeout=30.0),
    production=True, require_enforcer=True, release_sink=sink,
    delivery_confirmer=lambda rid, digest: True, hmac_key=b"k" * 32, persist_ledger_key=False, ledger=ledger,
    governor=KineticGovernor(ceiling_seconds=0.001))
identity = make_identity()
artifact = CNSDock().to_zts_artifact(identity)
def provide(candidate):
    proof = sign_grant(enforcer.ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes), now, key,
                       nonce="nonce-" + candidate.release_id)
    open(cfg["dir"] + "/grant.bin", "wb").write(proof)
    return proof
result = tower.enforce(TEXT, release=ReleaseRequest(identity=identity, artifact=artifact, release_id=cfg["release_id"],
                                                     scope=SCOPE, proof_provider=provide))
print("UNREACHABLE: the process returned", result.release_outcome)
