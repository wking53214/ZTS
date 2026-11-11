# Operating the release boundary

This is for the person running ZTS with the Enforcer path enabled. It describes what the code
provides. Where a procedure depends on something this repository does not contain (an issuer, a
status authority, a shared replay store, an independent anchor), it says so, and the matching
decision is in [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md). Nothing here has been observed
in a real deployment.

## 1. Topology this code supports

Several release hosts, each with its own tower, ledger file, anchor receipts and delivery sink, sharing:

* **one PostgreSQL database** for replay protection (`PostgresReplayStore`); this is what makes a grant
  releasable once across all hosts;
* **one issuer** that signs grants and answers status queries, and one **trust-root file** each host reads;
* optionally one **timestamp authority** for the ledger anchor.

A single host may use Enforcer's file-backed SQLite store instead of PostgreSQL. Ledger files are per host
(`flock` is advisory and unreliable on many network filesystems, so do not share one ledger file across hosts).
Each host's chain stands alone; the release id in every entry ties them together.

What this does **not** cover, because it is the database's and the network's: PostgreSQL replication and
failover (an asynchronously replicated standby that is promoted can forget a spent grant; use synchronous
replication or accept that window), TLS to the database (`sslmode=verify-full`), and who may delete rows.

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
and exercise them itself. `enforcer_policy` reads Enforcer's own limits through its public `describe()` (0.1.1 or
later): PASS at or below 5 min grant lifetime, 5 s clock skew and 30 s status age, UNKNOWN when any is looser (a longer
limit widens how long a stolen or revoked grant stays usable) and UNKNOWN on Enforcer 0.1.0, which cannot report them.

Setting up a deployment for the first time: [DEPLOYMENT.md](DEPLOYMENT.md). It lists the components you must
provide, the database roles and grants (checked by experiment), the files and their permissions, what each readiness
check means and what clears it, and the acceptance tests to run in your own environment.

Call `tower.readiness()` for the full list (PASS / FAIL / UNKNOWN with a reason) and
`tower.health()` for a live status (`ok`, `degraded`, `closed`). Health re-checks the live state of what ZTS can
see: the ledger chain and anchor, the anchor backlog, whether each trust-root role still has a usable key, and
for PostgreSQL whether the replay table still answers and keeps both constraints. A status client whose TLS
context does not demand a verified certificate and host name FAILS readiness; one that uses a caller-supplied
transport is UNKNOWN. `sslmode=verify-ca` is UNKNOWN (it does not check the host name); use `verify-full`.

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
* **Trust-root rotation and revocation** are file edits that take effect on the next verification, with no
  restart (see [WIRE_FORMATS.md](WIRE_FORMATS.md)). To rotate: add the new key, switch the issuer to it, let old
  grants expire, then mark the old key `revoked`. To revoke after compromise: set `status` to `revoked`; every
  grant under that key fails from the next check. Protect the file: mode 644 or stricter, and restrict who can
  write it, because whoever can edit it decides who may release. A broken edit refuses everything until fixed.
  **Keep an older copy from being put back** (it would un-revoke a key): raise `"serial"` in the file on every
  edit and give `FileTrustRoot` a serial store, `PostgresSerialStore` (the replay database is the natural home)
  or `FileSerialStore` on one host. Rotation then stays hot. The alternative is a pinned digest
  (`expected_sha256=`), which needs a restart per rotation. Readiness reports `trust_root_rollback` UNKNOWN until
  one of them is in place. A serial store does not stop someone who can write the file from authoring a new one
  with a higher serial. Keep the serial store's writers and the trust-root file's writers apart.
  The file and every directory above it (and above any symlink target) must be owned by the service user or
  root and not writable by others; ZTS refuses the trust root otherwise, on every use. Keep the file in a
  directory only root or the service user can write.
* **TSA certificate rotation:** the pinned certificate is the TSA's signing certificate itself. When the TSA
  rotates, pin the new one **in addition**, keep the old one until its receipts are no longer needed, and
  expect old receipts to fail verification if you remove it.

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
| `anchor_failures` > 0, or `health()` lists `anchor_service` | The timestamp authority could not stamp a head; tamper evidence is behind | Section 7, anchor |
| `ANCHOR_BEHIND` denials, or `health()` lists `anchor_backlog` | Too many ledger entries, or entries that are too old, have no timestamp, so new releases are refused until the TSA stamps again | Section 7, anchor |
| `health()` lists `receipt_export_live` | The receipt export hook failed; the receipt is on this host only | Re-export with `anchor.receipts()` |
| `health()` lists `trust_root_grant_keys`, `trust_root_status_keys` or `replay_store_live` | The trust root has no usable key or cannot be loaded (or was rolled back), or the replay table is unreachable or lost a constraint | Section 7 |
| `unclassified_denials` > 0 | A denial code that is in no alert bucket, because someone added a code without deciding whether it is an alert | Classify it in `zts.ops` |
| `on_reject` reasons `unknown_kid`, `revoked_key`, `bad_signature`, `unsupported_alg` | Someone presented a grant ZTS refuses; the reason says why | Treat `bad_signature` and `unsupported_alg` as attack signatures |
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
* **Receipts.** Copy the RFC 3161 receipts somewhere the ledger's writer cannot reach. Without that, an
  attacker who restores an older ledger *and* the matching older receipts is invisible. With an off-box
  copy, the newest receipt proves how far the ledger had got. `Rfc3161Anchor(on_receipt=fn)` calls `fn` with each
  receipt (a dict: `gen_time`, `head`, `sequence`, `token`) as soon as it is durable here, so an append-only or
  object-locked store can keep a copy. A failing hook never undoes a release; it shows as `receipt_export_live`
  in `health()`, and `anchor.receipts()` lists everything for a re-export. Whether the destination is out of the
  writer's reach is a deployment fact ZTS cannot check.
* **Retention.** ZTS never prunes the ledger or its anchor; archive by copying, and do not truncate a live
  ledger. The PostgreSQL replay table can be pruned: `PostgresReplayStore.prune()` deletes only rows whose
  grant expired longer ago than a grace period, judged by the **database's** clock (a pruning host with a fast
  clock cannot delete a live grant), with a floor of 30 s on the grace period. Keep the database and release
  hosts' clocks within seconds of each other. Pruning is safe because an expired grant is refused before the
  store is consulted. It needs Enforcer 0.1.1 to record each grant's expiry; rows without one are never
  pruned. Run it with a database role that may `DELETE`; give the release hosts `INSERT`/`SELECT` only.

## 7. Incident response

**Replay detected.** Find the release id in the event. The grant was already spent, so nothing was
delivered a second time. Decide whether it is a faulty client (a retry loop) or an attacker. If a
grant was captured, treat the issuer channel as exposed.

**Delivery unknown (`delivery_unknown`).** The grant is spent and the receiver did not confirm. After a hard stop
(a kill, a power loss) there is no event and no such result: the ledger shows a `RELEASING` entry with no final entry
for that release id, and [DEPLOYMENT.md](DEPLOYMENT.md) has the helper that lists them. Ask
the receiving system whether it holds the artifact (`release_id`, artifact SHA-256 are in the
event). Do not simply retry: a retry needs a new grant and a new release id and risks a duplicate.

**Audit gap (`delivered_audit_incomplete`).** The artifact was delivered. The ledger could not
durably record it, or the ledger is in memory. Repair the ledger, then write a manual
reconciliation entry referencing the release id; do not edit existing entries.

**Ledger integrity alert.** If the chain fails: someone or something modified the file; stop
releasing (`close()`), preserve the file, restore from backup, and verify against the anchor. If
only the anchor check fails, compare lengths: shorter ledger means truncation or rollback; an
anchor one ahead means an interrupted write.

**A slow or stalled endpoint.** The status client and the timestamp client each give up when their `timeout`
is up for the WHOLE exchange (handshake, request and response), whatever the server does in between; a server
that answers a byte at a time is cut off, not waited for. Name resolution and the TCP connect are not covered by
that deadline (the operating system owns them), so keep the gate's `timeout` set: it bounds the release itself.

**Enforcer, CNS, status source or issuer outage.** Releases are denied (`availability_failures`).
That is the intended behavior: there is no fallback path. Restoring service restores releases;
spent grants stay spent. Do not set `capstone=AUTO` to "get unstuck". It is refused by
`production=True`, and if you do remove that, it performs no authorization at all.

**Anchor failure.** Deliveries continue and `audit_anchored` is False until stamping works again; the next
release's flush anchors everything written so far, so a short outage leaves no permanent gap. Entries after the
last timestamp are only as trustworthy as the ledger file itself: removing them cannot be detected. So the
tail is bounded (`max_unanchored_entries`, default 500, and `max_unanchored_age`, default 300 s). Past either,
a new release is refused before anything is filtered or written, with outcome `not_attempted` and reason
`ANCHOR_BEHIND`, and each refused attempt asks the TSA again (at most once per `min_interval`), so the hold
lifts by itself when the TSA answers. Set the bound above the entries one release writes (about 11) times the
releases you run at once. A tail found at startup counts from the start. Check the TSA, its certificate, and
the clock; do not delete receipts.

**Key compromise.** Issuer key: mark it `revoked` in the trust root (every grant under it fails from the next
check), issue a new key, and treat releases made under the old key since the suspected compromise as
unverified; the ledger lists them by the verifier id, which names the trust root that decided.
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
