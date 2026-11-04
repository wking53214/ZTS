# Production readiness: what is done, what is blocked, and what needs a decision

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

Each guard above was mutation-tested: the code was deliberately broken and the suite had to fail.

## What is NOT a production capability, and why

| Gap | State | Why it is not closed |
|---|---|---|
| Proof verifier for real grants | **Absent.** Only the HMAC fixture in `tests/release_kit.py` exists. | Needs a trust-root decision (A below). Enforcer's default rejects every proof, so an unconfigured system denies everything. |
| Authorization status / revocation source | **Absent.** Only a fixture. | Needs an authority to exist (B below). Enforcer's default rejects everything. |
| Replay protection across hosts | **Absent.** | Needs the deployment topology (C below). |
| External ledger anchor | **Mechanism exists, independence unknown.** | A file anchor is only independent if mounted where the ledger's writer cannot rewrite it (D below). |
| Authenticated caller identity | **Absent by design.** ZTS binds an identity; it does not authenticate one. | Needs an authenticator to exist (E below). |

## Decisions required (stop points)

Each of these was reached in the campaign and **not** decided, because deciding it means choosing
who owns a key, an authority, or an infrastructure that the repositories do not define. The
stack's other components say the same thing about themselves: `Conservation_Kernel` "checks,
does not issue" authorizations; the `sentinel_os` action-authorization spec says "no production
provider currently implements these checks" and that issuer and reviewer-authority policy is
unresolved; `Governance_Gateway` lists "issuing, registering or expiring authority" as not its
own. Nothing in the stack issues Enforcer grants.

### A. Proof verification and the trust root (critical)

**Established from source.** Enforcer's seam is `ProofVerifier.verify_and_decode(bytes) -> GrantClaims`.
The stack's existing convention for signed evidence is Ed25519 with public keys pinned by the
caller, keyed by id, unknown keys rejected, via the `cryptography` package (TIE `herald_intake`,
HERALD export version 3). `sentinel_os` uses HMAC with service-level keys for attestation, which
is symmetric.

**Not established.** Who issues grants. Who owns the trust root and where it is stored. How keys
rotate and how a compromised key is revoked. How the trust root is distributed and updated. The
proof wire format. Whether adding `cryptography` to ZTS (which has no runtime dependencies today)
is acceptable.

| Option | What it is | Consequences |
|---|---|---|
| **A1 (recommended)** | ZTS ships an Ed25519 verifier adapter for Enforcer's seam. It reads an operator-supplied trust-root file of `{key id: public key, valid_from, valid_until, status}`; rejects unknown issuers, unknown or expired or revoked keys, any algorithm other than Ed25519, and malformed proofs. A new optional extra pulls in `cryptography`. | Follows the stack's existing pattern. Needs from you: who owns the trust root and how it is distributed and rotated, approval of the grant wire format, and an issuer (a separate service you own; it is not, and must not be, part of ZTS or Enforcer). |
| A2 | The verifier lives in the Enforcer repository (or a new one) and ZTS only configures it. | Keeps ZTS free of cryptography. Requires changing a dependency repository, which this campaign is not authorized to do. |
| A3 | A stdlib HMAC verifier, like `sentinel_os` attestation. | **Not recommended.** The verifier would hold the key that mints grants, so the verifying side can issue authority, which Enforcer's design forbids. |

### B. Authorization revalidation and revocation (critical)

**Established.** Enforcer requires an `AuthorizationRevalidator` that returns an authenticated
`CURRENT` status bound to the envelope digest and policy version, no older than 30 seconds,
and denies on anything else or on any error. **Not established:** where current status comes from.

| Option | Consequences |
|---|---|
| **B1** Signed status list, pulled by an adapter with a maximum staleness inside Enforcer's 30 s bound | Works offline from the issuer; needs a signer (the A question again) and a freshness distribution channel. |
| **B2 (recommended if the issuer is a service)** An authenticated online status API on the issuer | Simple semantics; the network failure behavior is already fail-closed (Enforcer denies on error, and ZTS bounds the call with a timeout). Needs that service. |
| B3 Use the `Conservation_Kernel` registry | It checks registered authorization events but "does not issue them" and is a library with an in-memory registry. Mixes a transformation-conservation component into authorization; not recommended. |

### C. Replay protection topology (critical)

**Established.** Enforcer's SQLite store is atomic per host (`BEGIN IMMEDIATE`, unique
constraints) and survives restart when file-backed; three connections racing on one file released
exactly once (`test_release_residual.py`). `production=True` refuses an in-memory store. It has
no retention or pruning, and it is not shared across hosts. **Not established:** single-host or
multi-host.

| Option | Consequences |
|---|---|
| **C1** Single host, file-backed SQLite on local disk | Works today. Backup and recovery are yours. Growth is unbounded until Enforcer gains retention (see "Proposed dependency changes"). |
| **C2 (required if more than one host releases)** A shared transactional store implementing Enforcer's `ReplayStore.consume` with uniqueness constraints | ZTS or the deployment can host the adapter. Needs a database choice; `sentinel_os` already runs PostgreSQL, which is a hint, not a decision. |
| C3 Route all releases for a scope to one host | Cheap, but a failover is a replay window. |

### D. External ledger anchor (critical for tamper evidence)

**Established.** `FileLedgerAnchor` publishes and verifies; truncation, rollback and tail
replacement are detected when the anchor survives. **Not established:** where an independent
anchor lives. A file on the same volume and account as the ledger anchors nothing.

| Option | Consequences |
|---|---|
| **D1 (recommended minimum)** Mount the anchor file on an append-only / WORM volume, or an account the ledger's writer cannot modify | No new code. Independence is entirely an operations fact that this repository cannot verify. |
| D2 A remote append-only service | Needs the service and a protocol. |
| D3 A transparency log or RFC 3161 timestamp authority | Strongest external assurance; adds an external trust decision. |

### E. Caller identity authentication

**Established.** CNS `IdentityContext` carries `verified`, `signature` and `trust_level`, and CNS
is a neutral contract layer that does not evaluate them. ZTS binds the artifact to the identity's
CNS digest. It does not authenticate the identity, and no component in the stack does.

| Option | Consequences |
|---|---|
| **E1 (recommended)** The grant issuer authenticates the subject before issuing; the grant, bound to the subject digest, is the only authentication ZTS relies on | No ZTS change. A caller who holds a valid grant for subject X can present X's identity: the grant is a bearer credential bound to one release. The issuer must keep grants short-lived and single-use (Enforcer enforces both). |
| E2 An optional `identity_verifier` hook in ZTS, run before the gate and failing closed | Small interface, but with no authenticator to plug in it earns no credit. |
| E3 Verify `IdentityContext.signature` in ZTS | The signing scheme and keys are undefined. Would put identity logic in ZTS. |

### F. Compatibility changes made in this campaign (for your approval)

All are in unreleased work, but they change values and behavior an adopter of the earlier commit could rely on:

1. `TowerResult.release_outcome` values were renamed and split (see `ReleaseState`): `released`
   became `delivered` / `delivered_unverified` / `delivered_audit_incomplete`; `held` became
   `not_attempted` / `failed_before_delivery`; `unconfirmed` became `delivery_unknown`;
   `released_unrecorded` became `delivered_audit_incomplete`. Legacy releases are `released_legacy`.
2. A tower's release controls (`tap`, `release_gate`, `release_sink`, `ledger`, `profile`, ...) are
   read-only after construction. `tower.ledger = ...` now raises.
3. `enforce()` and `run()` raise `TowerClosedError` after `close()`.
4. An in-memory ledger can no longer produce `delivered`; the best it can say is
   `delivered_audit_incomplete`.

## Proposed changes to dependencies (not made)

* **Enforcer**: replay-record retention and pruning that cannot make a still-valid grant reusable;
  return the decision record when the guarded callback aborts after an allow (today ZTS gets none);
  public accessors for the configured verifier and status-source ids, which the startup check now
  reads from private attributes and reports UNKNOWN when it cannot.
* **CNS**: none required. ZTS uses only `__version__`, `gate.subject_digest` and `IdentityContext`.
  CNS's consumer table (`cns_composition/consumers.py`, `REQUIRED["ZTS"]`) should list
  `cns.gate.subject_digest`; that was noted in an earlier PR and is a CNS-side change.

## What cannot be established from source

Whether any authority is trustworthy; whether the sink's receiving side is independent of the sink;
whether the anchor is out of the ledger writer's reach; whether file permissions, backups, secret
handling and key custody are as documented; whether `flock` behaves on the filesystem in use;
whether the host is single or multi; whether the process is isolated from code that could call the
delivery callback directly. These are UNKNOWN until observed in a real deployment.
