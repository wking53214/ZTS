# The release boundary: CNS, Enforcer and ZTS at G7

This document describes what the code does today and what it does not. Every
claim here is backed by a test named in the last section, or is listed under
"Known unresolved risks". Nothing here is a security certification, and unit
tests alone do not make this production ready.

## Who is responsible for what

| Component | Responsible for | Never responsible for |
|-----------|-----------------|-----------------------|
| CNS | Shared identity contract: the subject digest (`cns.gate.subject_digest`) and canonical representation of the identity an output is for. Version rules for that contract. | Authorizing anything. A valid digest is not a grant, and a CNS identity is not permission. |
| Enforcer | The decision. Verifies an externally issued grant, checks it is bound to this exact envelope, current, revalidated and unused, and consumes it. Owns all authorization policy and the replay store. | Identity, filtering, delivery. |
| ZTS | Enforcement. Builds the envelope from the artifact about to leave, makes the release the callback Enforcer guards, and treats anything but "allowed, then completed" as not released. Records the evidence. | Deciding policy. ZTS contains no authorization rules and does not duplicate Enforcer's checks. |

`cns` stays a shapes-and-contract package. ZTS uses three things from it:
`cns.__version__`, `cns.gate.subject_digest` and `cns.governance.IdentityContext`.
It does not use CNS composition (`SuperGate`, decision-root recomputation,
ALPHA/OMEGA sequencing, terminal-breach handling). The pinned release ships
`cns_composition`, but ZTS does not consume it, so none of those capabilities is
claimed here. ZTS does not interpret CNS gate statuses and does not redefine
them. Nothing in ZTS treats PASS, RETRY, UNKNOWN or TERMINAL_BREACH as
authorization.

## The enforcement boundary

Output leaves the tower in exactly one place. Both entry points end there:

```
enforce()  (sync)   --\
                       >-- _finish --> _decide --> _decide_enforced --> EnforcerReleaseGate.release
run()      (async)  --/                                                    |
                                                                           v
                                                       Enforcer.execute(envelope, proof, guarded)
                                                                           |  only after ALLOW
                                                                           v
                                                  guarded: CNS rebind -> deliver(snapshot)
                                                           (artifact check, ledger, sign, release_sink)
```

The release is the callback. Enforcer calls it only after it allows the action,
so the artifact is not reachable on a denial. There is no separate "check, then
release" step that a later edit could separate.

### Every release path, and what guards it

| Path | Guarded by |
|------|------------|
| `enforce()` | `_finish` -> `_decide` |
| `run()` and its rewrite/retry loop | the same `_finish`, once, for the final result only |
| Sieve breach | held before the gate is reached (`SIEVE_BREACH`) |
| No release authority configured | held (`RELEASE_NOT_CONFIGURED`) |
| Exception anywhere in the gate | converted to a denial or an unconfirmed outcome; never a release |
| Exception raised by the delivery callback | `unconfirmed`, output withheld |
| Legacy `ArchitectsProtocol` capstone | explicit opt-in only, see "Development and test bypasses" |
| `scrub()`, `audit()`, `ZeroTrustSieve.run()`, `zts` CLI | NOT guarded. These are inspection tools that return filtered text by design. They are not release paths and must not be wired to one. |

A structural test fails if a second place builds a released result or calls the
release sink.

## Required production configuration

```python
from enforcer import Enforcer, SQLiteReplayStore
from zts import DeterministicIntegrityTower, EnforcerReleaseGate, ReleaseRequest
from zts.cns import CNSDock

enforcer = Enforcer(
    verifier=your_reviewed_proof_verifier,        # authenticates grants and issuers
    revalidator=your_reviewed_status_source,      # current policy and revocation
    replay_store=SQLiteReplayStore("/secure/path/replay.db"),   # persistent, access controlled
)
tower = DeterministicIntegrityTower(
    "ops",
    release_gate=EnforcerReleaseGate(enforcer, policy_version="2026-11-policy-3"),
    require_enforcer=True,          # makes every legacy mode impossible
    release_sink=deliver,           # optional: the protected delivery callback
    ledger_key_file=...,            # as before
)

identity = ...                       # a cns.governance.IdentityContext from your identity layer
request = ReleaseRequest(
    identity=identity,
    artifact=CNSDock().to_zts_artifact(identity),
    release_id=unique_per_attempt,   # becomes the Enforcer request id
    scope="tenant-1/ops-report",
    proof_provider=ask_issuer_for_a_grant,   # receives a ReleaseCandidate, returns grant bytes
)
result = tower.enforce(text, release=request)       # or: await tower.run(prompt, generator, release=request)
```

Enforcer ships no production verifier and no production status source, and its
defaults reject everything. Selecting, implementing and reviewing those two
adapters, the issuer and the trust roots is the deployment's job and is not done
in any of these repositories.

A grant cannot be issued for output that does not exist yet. `proof_provider`
exists for that: after the sieve has produced the final text, ZTS passes the
provider a `ReleaseCandidate` (digests and canonical envelope bytes, never the
text) and expects grant bytes back. A pre-issued `proof` also works when the
artifact is known in advance. Supply one or the other. Anything the provider
returns is verified by Enforcer; the provider cannot grant by returning
something. The provider, the sink and Enforcer's calls are synchronous, so in
`run()` they block the event loop for as long as they take.

## The envelope

ZTS builds an Enforcer action envelope (schema v1) like this. An issuer that
wants to authorize a release must compute the same values. The test kit does so
independently of ZTS's code, from this table.

| Envelope field | Value |
|----------------|-------|
| `subject_id` | the CNS subject digest of the identity |
| `action` | the requested operation, default `zts.release` |
| `target_type` | `zts.output` |
| `target_id` | the authorization scope |
| `request_id` | the release identifier |
| `parameters_sha256` | SHA-256 of `release_parameters_bytes(...)`: the SHA-256 of the CNS canonical representation, the ZTS profile name, and a parameter-format version, as sorted compact JSON |
| `policy_version` | the policy version configured on the gate |
| `evidence_sha256` | SHA-256 of the UTF-8 bytes of the exact artifact |
| `schema_version` | 1 |

A grant for another subject, artifact, operation, scope, release id, profile or
policy version does not match and is denied. The decision timestamp comes from
Enforcer's decision record.

## What is checked, and when

Before Enforcer sees the grant (so a failure here never spends one):
release request present; release id and scope non-blank; Enforcer importable
and a supported release (0.1.x); CNS importable, on a supported release, with the
`IdentityContext` fields present; the identity is a real CNS `IdentityContext`;
the docked artifact is `KNOWN`, compatible, and equals what CNS yields for the
identity right now (subject digest and canonical representation); the envelope
builds. A write-ahead ledger entry is also required, and the grant is requested
only after it succeeds.

Inside Enforcer: proof authenticity, exact envelope binding, expiry, issue-time,
maximum lifetime, current authorization status (bounded freshness), and atomic
single-use consumption.

Inside the guarded call, after the allow and immediately before delivery: the CNS
binding is re-derived again, the artifact is compared with the exact text the
envelope was built from, and a second ledger entry must succeed.

## Denial semantics

A denied or invalid release returns a `TowerResult` with `released=False`,
`output=""`, no signature and no checksum, no payload text anywhere in `sieve`
(it is `sieve.redacted()`), never calls the release sink, and writes a ledger
entry. This holds for every outcome except `released`, including a sieve breach. `release_outcome` is one of:

* `released`: allowed, and the callback finished.
* `denied`: an authorization or precondition check said no. Nothing was spent.
* `held`: no authority configured, a sieve breach, or Enforcer allowed and the
  grant was spent, but ZTS stopped before delivering anything (artifact changed,
  CNS gone, ledger refused). The grant is not reusable.
* `unconfirmed`: Enforcer allowed and the callback began but did not finish.
  Delivery cannot be ruled out. The grant is spent; a retry needs a new grant.
* `released_unrecorded`: released, and the final ledger entry could not be
  written. Delivery cannot be undone, so this is reported instead of hidden.

`reason_code` is Enforcer's code (`PROOF_MISSING`, `PROOF_INVALID`,
`SCOPE_MISMATCH`, `GRANT_EXPIRED`, `GRANT_REPLAYED`, `AUTHORITY_STATUS_STALE`,
`GRANT_REVOKED`, ...) or a ZTS code from `ReleaseReason` (`CNS_UNAVAILABLE`,
`CNS_CONTRACT_INCOMPATIBLE`, `CNS_IDENTITY_UNTRUSTED`, `CNS_VERIFICATION_FAILED`,
`ENFORCER_UNAVAILABLE`, `ENFORCER_INCOMPATIBLE`, `ENFORCER_ERROR`,
`ENVELOPE_INVALID`, `RELEASE_ID_MISSING`, `RELEASE_SCOPE_MISSING`,
`RELEASE_REQUEST_MISSING`, `PROOF_PROVIDER_ERROR`, `ARTIFACT_CHANGED`,
`LEDGER_UNAVAILABLE`, `RELEASE_ACTION_FAILED`, `RELEASE_NOT_CONFIGURED`,
`SIEVE_BREACH`).

`TowerResult.authorization` is evidence of a decision (digests, ids, codes,
times). It is never a credential, and nothing may treat it as permission.

## Replay protection and revalidation

Replay protection is Enforcer's: an atomic uniqueness constraint on
`(issuer, nonce)` and on the request id. ZTS binds the Enforcer request id to the
release identifier, so a spent release id cannot be reused with a fresh grant,
and a spent grant cannot be reused for another release.

* With a file-backed `SQLiteReplayStore`, a replay after a restart is denied
  (tested).
* With an in-memory store, a restart forgets every spent grant, and a grant can
  release a second time until it expires. ZTS cannot tell what kind of store it
  was given. This is a configuration requirement, not something ZTS enforces.
  The grant lifetime (Enforcer caps it at five minutes by default) bounds the
  window (tested).
* A single SQLite file does not coordinate hosts. A multi-host deployment needs a
  shared store with the same atomic semantics. None is provided.
* Revalidation happens inside Enforcer immediately before consumption and
  delivery, and ZTS re-derives the CNS binding and the artifact once more inside
  the guarded call. A residual window remains between the last check and the
  external effect of whatever `release_sink` does. Nothing in these libraries can
  close it.
* An interrupted release (callback raised or the process died inside it) has
  spent its grant. There is no automatic retry. A new grant and a new release id
  are required, and the `unconfirmed` outcome tells the caller to check
  downstream state before issuing one.

## The ledger

For an Enforcer release the ledger holds, in order, `ATTEMPT` (written before
any grant is requested), `RELEASING` (written inside the guarded call, before
delivery) and the final `RELEASED`, `HELD` or `UNCONFIRMED`. The final entry
records the release id, CNS subject digest, operation, scope, policy version,
profile, whether it was authorized and released, the reason code, and the
Enforcer decision's status, reason code, request id, evaluation time, proof
SHA-256 and verifier and revalidator ids. The artifact is recorded as the
ledger's existing keyed fingerprint, not as text and not as a plain hash.
Enforcer's free-text decision message is not copied.

What is and is not true about it:

* It is a hash chain. That is tamper evidence, not tamper-proofing. Anyone able
  to write it can rebuild it.
* Writes are now serialized by a lock, so threads in one process cannot fork the
  chain (tested). That says nothing about several processes.
* An optional `LedgerAnchor` receives each new head before the entry is
  appended, and `verify_anchored()` checks the chain against it. This detects
  truncation and replacement only while the anchor is out of the writer's
  reach. ZTS ships the interface and a test double. No operational anchor exists.
* The ledger is in memory. It is gone when the process ends. There is no
  persistence, restart recovery or expected-head retention in this repository.
  Operating it needs an append-only external store and anchor that this
  repository does not contain.
* If the aborted release was authorized inside Enforcer but ZTS stopped it, the
  Enforcer decision record is not available to ZTS (Enforcer's `execute` does not
  return it on that path), so that entry carries ZTS's reason and `authorized`
  but no decision record.

## CNS compatibility

The dock accepts CNS releases of the same major version at or above
`CNS_CONTRACT_VERSION`, now `2.3.0`, which is the release `pyproject.toml` pins
(tag `v2.3.0`, commit `41592fb7b6735abe140f745353c09ba3eed8e7a2`). Before this
change the floor was `1.4.0` and refused major 2, so the dock refused the very
release ZTS pins: with the real pinned CNS installed, 19 existing tests failed.
1.x releases are now refused because nothing was verified against them. The
dock refuses anything that is not a plain `X.Y.Z` string. If CNS is unavailable,
incompatible or cannot verify the binding, a release is denied; a locally made
identity is never substituted.

Enforcer is accepted on `0.1.x` only, because it is a 0.x prototype whose minor
releases may break. It is pinned in `pyproject.toml` to commit
`3ff6a56a0c417a83e3b002feed6bdec4175454f3`.

## Development and test bypasses

`ReleaseMode.AUTO` and the other `ArchitectsProtocol` modes still exist, for
development, tests and existing callers. They are never selected implicitly:

* A tower with no release authority holds everything. Before this change it
  released everything that cleared the sieve.
* `ArchitectsProtocol()` with no arguments is `SEALED`, no longer `AUTO`.
* `AUTO` performs no authorization. A result released that way carries
  `authorization={"kind": "legacy-capstone", "enforcer_authorized": False}` and
  the ledger says so.
* `require_enforcer=True` refuses a tower built with any capstone, and a tower
  cannot be given both a capstone and a gate. Production deployments should set
  it.
* The legacy `signature=` argument is only the HANDSHAKE token. It means nothing
  to the Enforcer path.

## Known unresolved risks

1. **No production verifier, status source, issuer or trust root exists.** Without
   them the Enforcer path denies everything, which is safe and unusable.
2. **In-memory ledger, no operational anchor, no persistence.** See above.
3. **Replay durability depends on the store the deployment passes in**, and ZTS
   cannot check it. An in-memory store reopens a replay window after a restart.
4. **Multi-host replay protection is not provided.**
5. **A released result keeps its full sieve record**, including `payload_in` (the
   text before filtering) and the matched text of findings. Only results whose
   output was withheld are redacted: `sieve.redacted()` blanks the payloads and
   replaces matched text with `[redacted]`, keeping verdict, score, gate, offsets
   and codes. The ledger never holds matched text: its gate entries record the
   gate, verdict and number of findings.
6. **ZTS does not authenticate the identity it is given.** It binds the
   artifact to the CNS digest of whatever `IdentityContext` the caller supplies.
   Whether that identity is the true caller is the identity layer's problem, and
   whether it may receive the output is the grant's.
7. **The Enforcer library only guards calls routed through it.** A process that can
   run arbitrary code can read the text from the result of any inspection call
   or call the sink directly. A library is not a boundary against code in the
   same process.
8. **Blocking calls in `run()`.** The proof provider, sink, ledger and Enforcer are
   synchronous.
9. **Behavior changes for existing callers** (see CHANGELOG): the default tower no
   longer releases; `tower.tap` is `None` unless a capstone was passed; the CNS
   floor moved to 2.3.0.
10. **The test trust adapters are test code.** A permissive verifier defeats
    Enforcer, and the tests prove nothing about a real one.

## Tests

* `tests/test_release_boundary.py`: the adversarial suite against the real tower,
  adapter, CNS and Enforcer, with a test-only HMAC verifier and status source
  (`tests/release_kit.py`). Each denial is checked for: no output, no signature,
  the release callback never ran, a ledger entry exists, and the result cannot
  be read as a success. Each runs through both `enforce()` and `run()`.
* `tests/test_release_defaults.py`: the safe default, legacy-mode isolation,
  independence from CNS and Enforcer, and structural guards. Needs neither
  package.
* `tests/test_ledger_hardening.py`: concurrent writers, expected head, anchoring.
* `tests/test_cns_version_rule.py`, `tests/test_cns_connector.py`: the version
  floor and the dock against real CNS.

CI has a job with `.[dev,cns,enforcer]` and `ZTS_REQUIRE_CNS=1`,
`ZTS_REQUIRE_ENFORCER=1`, so a missing package fails the run instead of skipping.
