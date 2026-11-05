# Production readiness: what is done, what was decided, and what only people can establish

This document is the honest state of the release boundary. It separates four things
that are easy to blur:

* **Implemented and tested here.** Code exists in this repository and a test ran it.
* **Interface only.** A protocol exists, an implementation does not. No credit.
* **Test-only.** A fixture used to exercise the real code. Proves the code, not a deployment.
* **Deployment-dependent.** True or false depending on how someone runs it. Unknown from source.

Nothing below claims a deployment is secure. ZTS has not been deployed anywhere this
review could observe.

## What is implemented and tested here

| Capability | Where | Evidence |
|---|---|---|
| Release only inside Enforcer's guarded call; denial never reaches the callback | `zts.release`, `zts.tower` | `tests/test_release_boundary.py`, run through both `enforce()` and `run()` |
| Six distinct release states, independent delivery confirmation | `ReleaseState`, `Tower._conclude` | `tests/test_release_states.py` |
| Durable, fsynced, cross-process append-only ledger; torn-write recovery; refuses to auto-heal corruption | `zts.ledger_store` | `tests/test_ledger_durable.py`, including 4 real processes writing one chain |
| File-backed ledger anchor; detection of truncation, rollback, tail replacement | `FileLedgerAnchor`, `ValLedger.verify_anchored` | `tests/test_ledger_durable.py`, `tests/test_release_residual.py` |
| `run()` off the event loop; cooperative cancellation; bounded grant provider and Enforcer call; late-arrival guard; graceful shutdown | `zts.tower`, `zts.release` | `tests/test_release_async.py` |
| Release controls sealed after construction; decision-time production invariant | `zts.tower` | `tests/test_release_containment.py` |
| Security metrics, structured audit events, startup validation (`production=True`), health | `zts.ops` | `tests/test_ops.py` |
| Ed25519 grant verifier; rotatable, revocable, file-based trust root | `zts.trust` | `tests/test_trust_ed25519.py` (against an independent issuer), `tests/test_wire_vectors.py` |
| Online signed status revalidation over verified HTTPS, challenge-bound, no cache | `zts.status` | `tests/test_status_http.py` (a real TLS service) |
| Shared PostgreSQL replay store; safe pruning; refuses a table that lost a constraint | `zts.replay_postgres` | `tests/test_replay_postgres.py` (a real PostgreSQL server; threads, processes, two hosts) |
| RFC 3161 ledger anchor; lazy publishing; every token re-verified | `zts.anchor_tsa` | `tests/test_anchor_tsa.py` (tokens issued by OpenSSL) |
| Optional identity-authentication hook, checked twice, fail closed | `EnforcerReleaseGate(identity_verifier=)` | `tests/test_identity_hook.py` |
| The whole stack assembled and attacked | all of the above | `tests/test_production_assembly.py` |

Each guard above was mutation-tested: the code was deliberately broken and the suite had to fail. Three
survivors were equivalent mutants (redundant checks); every real gap that turned up got a test.

## Decisions taken, and what each still leaves open

Each of these was a stop point: a choice about who owns a key, an authority or infrastructure that the
repositories did not define. They were put to the owner with options and a recommendation, and decided:

| Decision | Chosen | Implemented | What it still leaves to people |
|---|---|---|---|
| A. Proof verification | Ed25519, keys pinned in a trust-root file | `zts.trust` | Who owns the trust root and issues grants; how the file is stored, rotated and edited; the issuer service itself |
| B. Revalidation | Online signed status API on the issuer | `zts.status` | Running that service; its availability and its own security |
| C. Replay topology | Several hosts, shared PostgreSQL | `zts.replay_postgres` | The database, its TLS, replication and failover durability, backups, who may delete rows |
| D. Ledger anchor | RFC 3161 timestamp authority | `zts.anchor_tsa` | Which TSA and its certificate; where receipts are kept so a rollback of ledger and receipts is visible; interop with a public TSA is untested |
| E. Identity | Issuer authenticates the subject, plus an optional hook | `identity_verifier` | An authenticator, if you want ZTS-side checks; otherwise the issuer is the only authentication |
| F. Compatibility | Accepted | See CHANGELOG | |

Nothing here is deployment-verified. Every component was tested against an independent implementation
(a separate encoder for the issuer and status service, a real PostgreSQL server, OpenSSL's RFC 3161 TSA),
and each of those is a fixture, not evidence about a real issuer, authority or TSA.

## Changes made to a dependency (Enforcer 0.1.1, merged and pinned)

Authorized, additive and backward compatible; merged to Enforcer `main` as PR #7 (commit `b2ee452`), which ZTS now pins:

* `execute(..., on_allow=)` hands the caller the ALLOW decision before the callback, so a release that aborts
  after the grant is spent keeps its decision record. ZTS uses it when present.
* `Enforcer.describe()` and `SQLiteReplayStore.describe()`: public accessors for verifier id, revalidator
  id, limits and replay-store durability. ZTS's checks still read private attributes today and fall back
  safely; moving them to `describe()` is a follow-up now that 0.1.1 is merged and pinned.
* Replay retention: the store records each grant's expiry (databases from 0.1.0 are upgraded in place) and
  `prune()` removes only records for grants that expired longer ago than a grace period, which is safe
  because an expired grant is refused before the store is consulted. Rows with no recorded expiry are never
  pruned.

ZTS pins Enforcer 0.1.1 and is still tested against 0.1.0 (accepted as `0.1.x`). **CNS needs no change**; its consumer table should list `cns.gate.subject_digest` for ZTS.

## What cannot be established from source

Whether any authority is trustworthy; whether the sink's receiving side is independent of the sink;
whether the anchor is out of the ledger writer's reach; whether file permissions, backups, secret
handling and key custody are as documented; whether `flock` behaves on the filesystem in use;
whether the host is single or multi; whether the process is isolated from code that could call the
delivery callback directly. These are UNKNOWN until observed in a real deployment.
