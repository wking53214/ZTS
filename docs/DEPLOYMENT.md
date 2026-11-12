# Deploying the release boundary

This is a checklist for the person standing up ZTS with the Enforcer path in production. It turns the
blockers in [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) into steps, files, roles and acceptance tests.

**What this is not.** Nothing here has been observed in a real deployment. The code blocks below are checked by
the test suite (the SQL is run against a real PostgreSQL, the Python is checked against the real signatures), and the
database privileges were found by experiment on PostgreSQL 16. Everything that depends on your issuer, your network,
your identity system and your hosts is yours to establish, and section 7 lists the tests that establish it.

## 1. What you must provide

ZTS enforces and records. It does not issue grants, run a status service, host a database, or isolate a process.

| Component | Who | What ZTS needs from it |
|---|---|---|
| Grant issuer | You | Signs `zts-grant-1` grants for one exact release. Keeps the private keys. See [WIRE_FORMATS.md](WIRE_FORMATS.md) |
| Status service | You | HTTPS `POST /v1/status`, answers `zts-status-1` signed by a `status` key, echoing a fresh challenge |
| Trust root file | You | The public keys ZTS accepts, with roles, windows, `serial`. Whoever edits it decides who may release |
| PostgreSQL | You | One database shared by every release host: spent grants, and the trust-root serial |
| Timestamp authority | A third party you choose | Signs ledger heads (RFC 3161). You pin its signing certificate |
| Receipt custody | You | A place the ledger's writer cannot rewrite, which receives every receipt |
| Delivery receiver | You | The system that gets the artifact, and an independent way to ask it whether it has it |
| Identity authenticator | You | Optional hook that says whether the subject is who the request claims |
| Process isolation | You | Keeps untrusted code from calling the delivery callback. A library cannot do this |

```
 grant issuer ---(signed grant)--> caller --> ZTS tower --Enforcer.execute--> delivery sink --> receiver
      |  signs status answers          |          |  |  |                                        |
      v                                |          |  |  +-- ledger (local file) + RFC 3161 receipts --> receipt custody
 status service <---HTTPS, signed------+          |  +----- PostgreSQL (spent grants, trust-root serial)
                                                  +-------- trust root file (public keys only)
```

## 2. Trust root and keys

* Generate the issuer's keys where the issuer lives. ZTS holds public keys only and contains no signing code. Use
  **separate keys for the `grant` role and the `status` role** (the same key cannot hold both).
* A key id is `ed25519-` plus the first 16 hex characters of the SHA-256 of the raw public key (`zts.trust.key_id`).
* The trust root file lists each key with its issuer, role, validity window and status. Raise `serial` on every edit.
* **Permissions.** The file is a regular file of at most 1 MiB, owned by the service user or root, mode 644 or
  stricter. Every directory above it (and above any symlink target) is owned by the service user or root and not
  writable by group or others. ZTS refuses the trust root otherwise, on every use. A sticky directory such as
  `/tmp` is accepted but is a poor home for it.
* **Rollback protection.** Give `FileTrustRoot` a `PostgresSerialStore` (the replay database is the natural home) so
  an older copy of the file is refused. Without it readiness reports `trust_root_rollback` UNKNOWN.
* **Edit procedure.** One person prepares the new file. A second person runs
  `python scripts/trust_root_review.py NEW.json --previous LIVE.json` and signs off on its output: it applies ZTS's own
  parser, prints every key with its role, issuer, window and state, prints the SHA-256 to pin, and fails the review if the
  serial does not rise, a revoked key becomes active again, or a key id changes role or issuer. It cannot judge whether the keys
  are the right ones; that is the review. Keep the previous file until the new one has been live and healthy.
* **Rotate:** add the new key with a start time before first use, raise `serial`, switch the issuer to it, let old
  grants expire, then mark the old key `revoked`. **Revoke after compromise:** set `status` to `revoked` and raise
  `serial`; every grant under that key fails from the next check.

## 3. The issuer and status service contract

ZTS checks what an issuer produces; it does not run one. What your issuer must get right:

* A grant is bound to one envelope: subject, action, target, release id, artifact digest, parameters digest, policy
  version. Compute them as [WIRE_FORMATS.md](WIRE_FORMATS.md) and `release.py` define. A grant is for one release.
* The grant's lifetime is within Enforcer's limit (5 minutes by default) and its nonce is unique per grant.
* The status service answers `CURRENT`, `REVOKED` or `UNKNOWN`, echoing the challenge, envelope digest, policy
  version, issuer and nonce, with `checked_at` and `valid_until` no more than 30 seconds apart.
* **Revocation is not instant.** A grant revoked after the status answer and before delivery starts still
  delivers. The window is the replay-database round trip plus a few local steps, bounded by the gate `timeout`
  (measured at 0 to 2.5 s in the audit probe). State this to whoever depends on revocation.
* Serve the status endpoint over TLS with a certificate valid for the name ZTS connects to. ZTS refuses plain HTTP,
  redirects, and a context that does not verify the certificate and host name.

## 4. PostgreSQL

The same database holds spent grants and, if you use it, the trust-root serial.

**Use three roles.** The admin owns the tables and is the only one that can change them. Release hosts can only
add rows. A separate pruning job deletes expired ones. The grants below were checked by experiment (PostgreSQL 16):

* release hosts need only `INSERT` on the replay table (`SELECT` is not needed), and cannot delete rows, prune, or
  drop a constraint;
* the pruner needs `SELECT` and `DELETE` on the replay table, and cannot consume a grant;
* the serial table needs `SELECT`, `INSERT` and `UPDATE` for hosts (it reads back what it wrote);
* a role that is not the table's owner cannot drop its constraints, so **the admin, not a release role, must own both tables**;
* creating the tables needs `CREATE`, so hosts connect with `create=False` and an admin creates the tables once.

Run once as the admin, then the SQL:

```python
# verified-snippet
from zts.replay_postgres import PostgresReplayStore, PostgresSerialStore

ADMIN_DSN = "host=db.internal dbname=zts user=zts_admin sslmode=verify-full sslrootcert=/etc/zts/db-ca.pem"
PostgresReplayStore(ADMIN_DSN).close()   # creates the replay table, owned by the admin
PostgresSerialStore(ADMIN_DSN).close()   # creates the trust-root serial table
```

```sql
-- verified-sql
CREATE ROLE zts_release LOGIN;
CREATE ROLE zts_pruner LOGIN;
REVOKE ALL ON zts_consumed_grants, zts_trust_serial FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO zts_release, zts_pruner;
GRANT INSERT ON zts_consumed_grants TO zts_release;
GRANT SELECT, DELETE ON zts_consumed_grants TO zts_pruner;
GRANT SELECT, INSERT, UPDATE ON zts_trust_serial TO zts_release;
```

* **TLS.** Put `sslmode=verify-full` and the CA file in the DSN. `verify-ca` is reported UNKNOWN because it does not
  check the host name. Authentication (client certificates, passwords from a secret store) is yours; keep secrets out of the DSN.
* **Durability.** An asynchronously replicated standby that is promoted can forget a spent grant. Use synchronous
  replication, or accept that window. Restoring from an old backup re-opens every grant spent since (wait out the
  grant lifetime first). Keep database and release-host clocks within seconds of each other.
* **Pruning.** Run `PostgresReplayStore.prune()` as the pruner role on a schedule. It judges expiry by the database
  clock and will not accept a grace period under 30 seconds.

## 5. Timestamp authority, ledger and receipts

* **Pick a TSA and pin its signing certificate** (the certificate itself, not a CA): it must carry a critical
  time-stamping extended key usage. ZTS verifies the imprint, nonce, signer, usage, validity, digest and signature of
  every token, and does no chain building or revocation check. When the TSA rotates, pin the new certificate in
  addition and keep the old one while old receipts matter. ZTS was tested against OpenSSL's TSA, not a public one.
  Test your TSA before relying on it (section 7, test 6), and first run `python scripts/tsa_interop.py <url> --cert <signing-cert.pem>` from the releasing host: it stamps one head through ZTS's own client and prints PASS only if the token verifies against the certificate you pinned and the stamped time is near this host's clock.
* **Bound the unstamped tail.** `max_unanchored_entries` (500) and `max_unanchored_age` (300 s) are the defaults. Past
  either, new releases are refused with `ANCHOR_BEHIND` until the TSA stamps again. Set the entries bound above
  what one release writes (about 11) times the releases you run at once. Tighten both if removing five minutes of
  audit trail is too much for you.
* **Receipts leave the box.** Pass `on_receipt` a function that writes each receipt (a dict) to a place the ledger's
  writer cannot rewrite or delete (append-only, write-once, or an auditor's system). Raise if the write fails: the
  failure shows as `receipt_export_live` in `health()`, and `anchor.receipts()` lists everything for a re-export.
  Without this, an attacker who restores an older ledger and its receipts together is not detected.
  `zts.receipts.HttpsReceiptExporter(url, headers={"Authorization": "Bearer ..."})` is a ready hook: one POST per receipt over
  verified TLS with a 3 s deadline (it runs on the path of a ledger write), the URL never appears in an error, and
  `exporter.resend(anchor, after_sequence=N)` pushes everything above the newest sequence the destination holds, oldest first,
  stopping at the first failure so there is no gap. It cannot create the separation that makes the copy worth having: the
  destination must be append-only for this host, must treat a repeated `sequence` as the same receipt, and should refuse a
  different receipt for a sequence it already holds.
  A reference receiver for a locked AWS S3 bucket (Object Lock), with its IAM policy, setup and a trial checklist, is in
  `examples/receipt_receiver/`; its S3 code has only been tested against a stand-in client.
* **Ledger and keys.** The ledger is a local file on a filesystem that honors `fsync` and `flock` (not a network
  share), one per host. The ledger key is a 32-byte secret in a file with mode 600 that you create before first start
  (`load_or_create_ledger_key` creates a missing file, so check it exists). The release signature key (32 bytes) comes
  from your secret store; if it is random per process, readiness FAILs.

## 6. Assembling the tower

```python
# verified-snippet
import enforcer

from zts import DeterministicIntegrityTower, EnforcerReleaseGate
from zts.anchor_tsa import Rfc3161Anchor
from zts.ledger import ValLedger, load_or_create_ledger_key
from zts.ledger_store import FileLedgerStore
from zts.replay_postgres import PostgresReplayStore, PostgresSerialStore
from zts.status import HttpStatusRevalidator
from zts.trust import Ed25519GrantVerifier, FileTrustRoot

DSN = "host=db.internal dbname=zts user=zts_release sslmode=verify-full sslrootcert=/etc/zts/db-ca.pem"

trust = FileTrustRoot("/etc/zts/trust.json", serial_store=PostgresSerialStore(DSN, create=False))
replay = PostgresReplayStore(DSN, create=False)
anchor = Rfc3161Anchor(
    "https://tsa.example/", [open("/etc/zts/tsa-signing.pem", "rb").read()], "/var/lib/zts/receipts.jsonl",
    timeout=10.0, on_receipt=export_receipt)  # export_receipt(dict) writes outside the ledger writer's reach
ledger = ValLedger(
    key=load_or_create_ledger_key("/etc/zts/ledger.key"),  # create the file first; do not let it be generated
    store=FileLedgerStore("/var/lib/zts/ledger.jsonl"), anchor=anchor)
gate_enforcer = enforcer.Enforcer(
    verifier=Ed25519GrantVerifier(trust),
    revalidator=HttpStatusRevalidator("https://status.internal", trust, timeout=2.0),
    replay_store=replay)
tower = DeterministicIntegrityTower(
    "ops",
    production=True,                  # refuses to start if any readiness check FAILs
    release_gate=EnforcerReleaseGate(
        gate_enforcer, policy_version="2026-11", timeout=5.0, identity_verifier=authenticate_subject,
        reask_status=True),           # ask the status service again just before delivery (Enforcer 0.1.2+)
    release_sink=deliver,             # the protected delivery callback
    delivery_confirmer=receiver_has,  # asks the RECEIVING side; never the sink's own return value
    hmac_key=load_secret("zts-release-signing-key"),
    ledger=ledger)
```

`production=True` raises `ProductionConfigError` listing each FAIL. Call `tower.readiness()` before taking traffic
and `tower.health()` from your health endpoint. Keep the gate `timeout`: it bounds the release itself, including the
parts the HTTP deadlines cannot reach (name resolution, TCP connect).

## 7. Readiness: what each check means and what clears it

`tower.readiness()` on a fully assembled production tower (real run). PASS means ZTS verified it. UNKNOWN means only
you can.

| Check | Expected | If UNKNOWN or FAIL, you need |
|---|---|---|
| `enforcer_gate`, `no_legacy_release_path`, `durable_ledger`, `ledger_anchor`, `delivery_confirmer`, `enforcer_timeout`, `release_signature_key` | PASS | Configure what the detail names |
| `proof_verifier`, `status_source` | PASS | A usable trust-root key for each role; a status client whose TLS verifies (custom transports are UNKNOWN) |
| `trust_root_rollback` | PASS | A serial store, or a pinned digest (which forces a restart per rotation) |
| `replay_store` | PASS | A reachable PostgreSQL table with both constraints. File-backed SQLite is UNKNOWN (one host only), in-memory is FAIL |
| `replay_store_tls` | PASS | `sslmode=verify-full`. `verify-ca` and local connections are UNKNOWN |
| `status_recheck` | PASS | `reask_status=True` on the gate, which needs Enforcer 0.1.2 or later. UNKNOWN when off: a revocation after the first status answer is then not seen |
| `enforcer_policy` | PASS | Limits at or below 5 min lifetime, 5 s skew, 30 s status age. Looser is UNKNOWN: confirm it is intended |
| `anchor_kind`, `anchor_backlog_bound` | PASS | A pinned TSA certificate and at least one bound |
| `ledger_chain`, `ledger_anchor_match`, `anchor_backlog`, `trust_root_grant_keys`, `trust_root_status_keys`, `replay_store_live`, `enforcer_importable`, `cns_importable`, `accepting_work` | PASS | Live state; a FAIL here is a fault to fix now |
| `anchor_service` | PASS after the first release | Release once; UNKNOWN until the TSA has answered |
| `trust_root_governance` | UNKNOWN always | A named owner, an edit procedure, a distribution procedure |
| `identity_authentication` | UNKNOWN always | An authenticator hook you have reviewed, or accept the issuer as the only authentication |
| `receipt_export` | UNKNOWN always | An `on_receipt` destination you have confirmed is out of the writer's reach |
| `anchor_independence` | UNKNOWN always | The same confirmation about the receipts |

## 8. Process isolation

ZTS stops callers that go through the tower. It cannot stop code in the same process, which can call `release_sink`
directly. Isolation is a property of your deployment. Objectives to meet, and how to check each:

* Untrusted code cannot read the delivery credentials. *Check:* run as the application user and try to read them.
* Untrusted code cannot reach the receiver except through the delivery process. *Check:* try, from the application's
  network position.
* Untrusted code cannot write the trust root, the ledger, the receipts, the ledger key or the release signature key,
  or read the replay database credentials. *Check:* the same, as the application user.
* The tower and delivery path run under an account the application does not share.

## 9. Acceptance tests to run in your environment

None of these has been run against your deployment. Each should be run before go-live, and again after any change to
the issuer, the status service, the TSA or the database. Record the date and result.

| # | Do this | Expect | Where it shows |
|---|---|---|---|
| 1 | Release with a valid grant | `delivered`, `audit_anchored` true | Result; `zts.release` log at INFO |
| 2 | Present the same grant to a second host | `GRANT_REPLAYED` | `replays_detected`; ERROR log |
| 3 | Revoke at the status service; release again | `GRANT_REVOKED`. Measure the time from revocation to refusal | `security_denials` |
| 4 | Release under an expired, revoked or unknown key | `PROOF_INVALID` | `on_reject` reasons |
| 5 | Put an older trust root back | The trust root is refused; `health()` lists `trust_root_grant_keys` | `health()` |
| 6 | Block the TSA; keep releasing; then block longer | Deliveries continue unanchored, then `ANCHOR_BEHIND`; unblock and the hold lifts | `anchor_failures`, `anchor_backlog` |
| 7 | Stop the replay database | Every release denied `REPLAY_STORE_ERROR`; recovers when it returns | `availability_failures` |
| 8 | In a test copy, drop a replay constraint | Releases denied; `health()` lists `replay_store_live` | `health()` |
| 9 | Make the status service answer slowly | Denied within the `timeout`, not after | `availability_failures` |
| 10 | Make the identity hook return false | `IDENTITY_NOT_AUTHENTICATED` | `security_denials`; ERROR log |
| 11 | Kill the process mid-delivery (SIGKILL); restart | The ledger opens and verifies. The release has `ATTEMPT` and `RELEASING` entries and **no final entry**: nothing records `delivery_unknown`, because no process was alive to. Find it with the helper below, ask the receiver whether it holds the artifact, and do not retry the same grant (it is spent: `GRANT_REPLAYED`). Issue a new grant under a new release id | The helper; `tests/test_crash_recovery.py` does this for real |
| 12 | Restore an old ledger and its receipts together | Detected only if your off-box receipts are newer | Compare with the custody copy |
| 13 | Fail the receipt export destination | `receipt_export_live` in `health()`; release still delivers | `health()` |
| 14 | Try section 8's checks as the application user | Every one fails | Your own evidence |

Fill in [ACCEPTANCE_RECORD.md](ACCEPTANCE_RECORD.md) as you go: it has a section per test below, with places for what you saw, what you measured and who signed off.

### What this repository already proves, and what only you can

Each row's mechanism is exercised against stand-ins in the files named (a real PostgreSQL, OpenSSL's TSA, a killed process).
That shows the code does the right thing. It does not show your issuer, status service, network, database or TSA do. Your run
of the row is the evidence for those, and for the rows with no file at all.

| # | Mechanism proven in | Only your run can show |
|---|---|---|
| 1 | `test_production_assembly.py`, `test_crash_recovery.py` | Your sink, receiver and confirmer |
| 2 | `test_phase2_replay.py`, `test_ops.py` | That every host really shares one replay database |
| 3 | `test_release_boundary.py`, `test_status_http.py` | The revocation-to-refusal time through your status service |
| 4 | `test_trust_ed25519.py`, `test_release_boundary.py` | That your issuer signs with the keys in your trust root |
| 5 | `test_phase2_trust_serial.py` | That your serial store is the one all hosts use |
| 6 | `test_phase2_anchor_bound.py` | That blocking your TSA behaves the same through your firewall |
| 7 | `test_replay_postgres.py`, `test_production_assembly.py` | Your database failover and recovery |
| 8 | `test_phase2_replay.py` | Nothing beyond running it on a copy |
| 9 | `test_phase2_deadlines.py`, `test_release_async.py` | Your status service's real slow modes (DNS and connect are not covered by the HTTP deadline) |
| 10 | `test_identity_hook.py` | Your authenticator |
| 11 | `test_crash_recovery.py` | Your receiver's answer to "do you hold it?" |
| 12 | `test_anchor_tsa.py`, `test_ledger_durable.py` | That your off-box receipts really are newer and out of the writer's reach |
| 13 | `test_phase2_anchor_bound.py`, `test_receipt_export.py` | Your destination refusing, and `resend` filling the gap |
| 14 | none | Everything: it is about your operating system accounts |

### After a crash: finding the release whose delivery is unknown

A hard stop leaves no event and no `delivery_unknown` result. The ledger still shows it: a release whose delivery
began (`RELEASING`) and has no final entry (`RELEASED`, `UNCONFIRMED` or `HELD`). Run this after every unclean stop:

```python
# verified-function
def unfinished_releases(ledger):
    """Release ids with a delivery that began and was never recorded as ended.

    A new attempt under the same release id does not hide an earlier one: a retry after a crash writes its own
    ATTEMPT and a final entry, and the delivery it follows is still unfinished.
    """
    state, lost = {}, set()
    for entry in ledger.entries:
        if entry.layer != "TAP":
            continue
        release_id = entry.extra.get("release_id")
        if entry.status == "ATTEMPT":
            if state.get(release_id) == "delivering":
                lost.add(release_id)  # a new attempt began while the last delivery had no ending
            state[release_id] = "attempt"
        elif entry.status == "RELEASING":
            state[release_id] = "delivering"
        elif entry.status in ("RELEASED", "UNCONFIRMED", "HELD"):
            state[release_id] = "done"  # any final entry closes the current attempt
    return sorted(lost | {r for r, s in state.items() if s == "delivering"})
```

For each id it returns, ask the receiving system whether it holds the artifact (the release id and the artifact's
SHA-256 are what you have). Reconcile by writing a new ledger entry that names the release id; never edit an
existing one. This was verified with a real process killed by SIGKILL during delivery, against a real PostgreSQL, TSA
and status service: the chain verified, the grant was spent, a retry with it was denied, and a new release delivered.

## 10. Monitoring and incidents

Alert signals and responses are in [OPERATIONS.md](OPERATIONS.md) sections 4 and 7. At minimum alert on
`security_denials`, `availability_failures`, `delivery_unknown`, `audit_incomplete`, `anchor_failures`,
`unclassified_denials` above zero, and any `health()` that is not `ok`.

## 11. Decisions only you can make

* Who owns the issuer and the trust root, and the procedure to edit it.
* How long a revocation may take to bite (the window in section 3), and the grant lifetime.
* The unstamped-tail bounds, and where receipts go.
* Which TSA, and the plan if it is unreachable for a long time.
* Whether replay-database failover may lose a spent grant.
* What authenticates a subject, and what isolates the delivery path.
