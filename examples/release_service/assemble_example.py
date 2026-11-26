"""An example tower factory: the guide's production assembly (docs/DEPLOYMENT.md section 6) with this service's paths.

NOT TESTED against real components. It is the guide's snippet, whose calls are checked against the real signatures, with the file
locations of ../isolation/ filled in. Copy it, change the addresses and names at the top, and point `tower_factory` at your copy.
"""

from __future__ import annotations

from pathlib import Path

import enforcer
from delivery import HttpsReceiver

from zts import DeterministicIntegrityTower, EnforcerReleaseGate
from zts.anchor_tsa import Rfc3161Anchor
from zts.identity import Ed25519IdentityVerifier
from zts.ledger import ValLedger, load_or_create_ledger_key
from zts.ledger_store import FileLedgerStore
from zts.replay_postgres import PostgresReplayStore, PostgresSerialStore
from zts.status import HttpStatusRevalidator
from zts.trust import Ed25519GrantVerifier, FileTrustRoot

# ---- change these ---------------------------------------------------------------------------------------------------
REPLAY_DSN_FILE = "/etc/zts/secrets/replay.dsn"            # a PostgreSQL connection string, sslmode=verify-full
RECEIPT_EXPORT = None                                      # e.g. zts.receipts.HttpsReceiptExporter(...).__call__
STATUS_URL = "https://status.internal"
TSA_URL = "https://tsa.example/"
RECEIVER_URL = "https://receiver.internal/release"
POLICY_VERSION = "2026-11"
AUDIENCE = "zts-release/prod"
# ---------------------------------------------------------------------------------------------------------------------


def build_tower(config: dict) -> DeterministicIntegrityTower:
    dsn = Path(REPLAY_DSN_FILE).read_text(encoding="utf-8").strip()
    trust = FileTrustRoot("/etc/zts/trust-root.json", serial_store=PostgresSerialStore(dsn, create=False))
    replay = PostgresReplayStore(dsn, create=False)
    anchor = Rfc3161Anchor(TSA_URL, [Path("/etc/zts/tsa-signing.pem").read_bytes()], "/var/lib/zts/receipts.jsonl",
                           timeout=10.0, on_receipt=RECEIPT_EXPORT)
    ledger = ValLedger(key=load_or_create_ledger_key("/var/lib/zts/ledger.key"),
                       store=FileLedgerStore("/var/lib/zts/ledger.jsonl"), anchor=anchor)
    gate_enforcer = enforcer.Enforcer(
        verifier=Ed25519GrantVerifier(trust),
        revalidator=HttpStatusRevalidator(STATUS_URL, trust, timeout=2.0),
        replay_store=replay)
    receiver = HttpsReceiver(RECEIVER_URL, "/etc/zts/secrets/delivery.cred")
    return DeterministicIntegrityTower(
        "ops",
        production=True,
        release_gate=EnforcerReleaseGate(
            gate_enforcer, policy_version=POLICY_VERSION, timeout=5.0, reask_status=True,
            identity_verifier=Ed25519IdentityVerifier(trust, audience=AUDIENCE)),
        release_sink=receiver.deliver,
        delivery_confirmer=receiver.confirm,
        hmac_key=Path("/etc/zts/secrets/release-signing.key").read_bytes(),
        ledger=ledger)
