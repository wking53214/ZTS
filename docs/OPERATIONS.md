# Operating the release boundary

This is for the person running ZTS with the Enforcer path enabled. It describes what the code
provides. Where a procedure depends on something this repository does not contain (an issuer, a
status authority, a shared replay store, an independent anchor), it says so, and the matching
decision is in [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md). Nothing here has been observed
in a real deployment.

## 1. Topology this code supports

One process, or several processes on **one host**, sharing:

* one replay database file (Enforcer's `SQLiteReplayStore`; atomic across connections),
* one ledger file (`FileLedgerStore`; appends are serialized across processes with `flock`),
* one anchor file (`FileLedgerAnchor`).

Not supported: several hosts. `flock` is advisory and unreliable on many network filesystems, and
Enforcer's SQLite store does not coordinate hosts. Running two hosts against the same replay data
leaves a window where one grant releases twice. Do not do it until a shared replay store exists
(decision C).

## 2. Configuration

```python
tower = DeterministicIntegrityTower(
    "ops",
    production=True,                  # refuse to start unless the checks below do not FAIL
    release_gate=EnforcerReleaseGate(enforcer, policy_version="2026-11-3", timeout=5.0),
    release_sink=deliver,             # the protected delivery callback
    delivery_confirmer=receiver_has,  # asks the RECEIVING side; never the sink's own return value
    hmac_key=load_secret(...),        # release signature key, 32 bytes, supplied, not generated
    ledger=ValLedger(
        key=ledger_key,               # see "Secrets" below
        store=FileLedgerStore("/var/lib/zts/ledger.jsonl"),
        anchor=FileLedgerAnchor("/mnt/anchor/zts-anchor.jsonl"),   # mount somewhere the writer cannot rewrite
    ),
)
```

`production=True` raises `ProductionConfigError` listing each failed check. It FAILs on: no Enforcer
gate, a legacy capstone, a non-durable ledger, no anchor, no delivery confirmer, no timeout, a
per-process random signature key, Enforcer's reject-everything defaults, an adapter that calls
itself a test fixture, and an in-memory replay store. It does **not** and cannot vouch for a custom
proof verifier, status source or replay store: those report UNKNOWN, and a deployment must review
and exercise them itself.

Call `tower.readiness()` for the full list (PASS / FAIL / UNKNOWN with a reason) and
`tower.health()` for a live status (`ok`, `degraded`, `closed`).

## 3. Secrets and files

* The release signature key, the ledger key and the replay database are secrets or integrity
  anchors. Keep them out of source control and out of environment dumps. ZTS does not read keys
  from the environment; pass bytes in from your secret store.
* The ledger key defaults to `~/.config/zts/ledger.key` (mode 600; a readable file is refused). A
  production deployment should set `ledger_key_file` explicitly.
* Ledger and anchor files are created mode 600, and opening one writable by others is refused.
* Key rotation: **not supported for the ledger key.** Entries record a key id, but nothing rotates
  the key, and rotating it makes older payload fingerprints unmatchable (README, "Open items").
  The release signature key can be replaced by restarting with a new key; signatures made under
  the old key stop verifying, so keep the old key available to whoever verifies old signatures.
* Trust-root rotation and update: **blocked** on decision A. There is no trust root yet.

## 4. Monitoring

Events are one JSON object per decision on the standard `logging` logger `zts.release`. Attach a
handler; nothing prints otherwise. Levels: INFO for `delivered`, ERROR for an attack signature
(`GRANT_REPLAYED`, `PROOF_INVALID`, `SCOPE_MISMATCH`, `GRANT_REVOKED`, `ARTIFACT_CHANGED`, ...) or
`delivery_unknown`, WARNING for everything else. An event holds identifiers, digests, codes and
times. It never holds the artifact, a proof, or matched text. A broken log handler cannot change a
release (tested).

`tower.metrics.snapshot()` returns counters. Alert on:

| Signal | Meaning | Suggested response |
|---|---|---|
| `replays_detected` rising | Someone is re-presenting a grant, or a client is retrying badly | Section 7, replay |
| `security_denials` rising | Forged, mismatched, revoked, changed-artifact attempts | Treat as an attack until explained |
| `availability_failures` rising | Enforcer, CNS, the grant provider, the status source or the ledger is failing | Section 7, outage |
| `delivery_unknown` > 0 | A delivery began and could not be confirmed | Section 7, unknown delivery. Never auto-retry |
| `audit_incomplete` > 0 | A delivery happened without a durable final record | Section 7, audit gap |
| `health()["status"] != "ok"` | The ledger chain or its anchor no longer verifies, or a dependency cannot be imported | Section 7, ledger integrity |

## 5. Normal operation and shutdown

A release is `delivered` only when Enforcer allowed it, the callback finished, the receiving side
confirmed it, and the final ledger entry is on disk. `close(timeout)` stops new work (`enforce()`
and `run()` then raise `TowerClosedError`), waits for in-flight releases including one that is
mid-delivery, and then closes the ledger files. Returns `False` if something did not drain.

In `run()`, cancelling the task is cooperative. It stops a release that has not reached the delivery
callback. One already delivering finishes. In both cases the caller sees `CancelledError`, which
means "the result was not returned", **not** "nothing happened". Read the ledger before retrying.

## 6. Backup and recovery

* **Back up** the ledger file, the anchor file and the replay database together, and keep the
  anchor copy somewhere the ledger writer cannot reach. A ledger restored without its anchor
  cannot be checked against it.
* **Opening a ledger** verifies the whole chain. A final line with no newline is an interrupted,
  never-acknowledged write: it is removed, a copy is kept in `<ledger>.torn`, and the open reports
  it (`ledger.recovery`). Any other damage, a line that does not parse, a broken link, a digest
  mismatch, makes the open fail and is **not** repaired, because tampering looks the same.
* **After an unclean stop** run `ledger.verify_anchored()`. "Anchor is one entry ahead" means a
  write was interrupted after the anchor accepted a head, or the tail was removed; ZTS does not
  guess which. Compare with `<ledger>.torn` and the logs, then decide.
* **Restoring** the replay database from an old backup re-opens every grant spent since. Treat a
  restore as a security event; wait out the grant lifetime (Enforcer's default maximum is 5
  minutes) before accepting releases, or restore from a backup newer than that.
* **Retention.** Neither the ledger nor Enforcer's replay table is ever pruned by ZTS. Archive by
  copying; do not truncate a live ledger or its anchor. Enforcer has no safe replay pruning yet.

## 7. Incident response

**Replay detected.** Find the release id in the event. The grant was already spent, so nothing was
delivered a second time. Decide whether it is a faulty client (a retry loop) or an attacker. If a
grant was captured, treat the issuer channel as exposed.

**Delivery unknown (`delivery_unknown`).** The grant is spent and the receiver did not confirm. Ask
the receiving system whether it holds the artifact (`release_id`, artifact SHA-256 are in the
event). Do not simply retry: a retry needs a new grant and a new release id and risks a duplicate.

**Audit gap (`delivered_audit_incomplete`).** The artifact was delivered. The ledger could not
durably record it, or the ledger is in memory. Repair the ledger, then write a manual
reconciliation entry referencing the release id; do not edit existing entries.

**Ledger integrity alert.** If the chain fails: someone or something modified the file; stop
releasing (`close()`), preserve the file, restore from backup, and verify against the anchor. If
only the anchor check fails, compare lengths: shorter ledger means truncation or rollback; an
anchor one ahead means an interrupted write.

**Enforcer, CNS, status source or issuer outage.** Releases are denied (`availability_failures`).
That is the intended behavior: there is no fallback path. Restoring service restores releases;
spent grants stay spent. Do not set `capstone=AUTO` to "get unstuck". It is refused by
`production=True`, and if you do remove that, it performs no authorization at all.

**Key compromise.** Issuer key: blocked on decision A (no trust root exists to revoke from).
Release signature key: replace and restart; old signatures are no longer trustworthy. Ledger
key: payload fingerprints become matchable to guessed values; rotation is not supported, so
plan a new ledger and archive the old.

## 8. What this guide cannot tell you

Whether your anchor is out of the writer's reach; whether your sink's receiving side is
independent of the sink; whether your filesystem honors `flock` and `fsync`; whether your
verifier, status source and issuer are sound; whether the process is isolated from code that
could call the delivery callback directly. Each of these needs to be established by looking at the
deployment. A library cannot contain code running in its own process; the control for that is
process or network isolation of the delivery path.
