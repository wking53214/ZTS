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
| Sieve breach | `not_attempted` before the gate is reached (`SIEVE_BREACH`) |
| No release authority configured | `not_attempted` (`RELEASE_NOT_CONFIGURED`) |
| Exception anywhere in the gate | converted to a denial or a `delivery_unknown` outcome; never a release |
| Exception raised by the delivery callback | `delivery_unknown`, output withheld |
| A timed-out Enforcer call that wakes up later | refused at the callback by an abandoned flag taken under a lock |
| Cancellation of `run()` | cooperative flag checked before an authority is asked and again before delivery |
| Reassigning `release_gate`, `tap`, `release_sink`, `ledger`, ... on a built tower | raises `AttributeError`; a forced swap is caught by the decision-time invariant |
| Calls after `close()` | raise `TowerClosedError`; a call racing shutdown returns `not_attempted` |
| Legacy `ArchitectsProtocol` capstone | explicit opt-in only, see "Development and test bypasses" |
| `scrub()`, `audit()`, `ZeroTrustSieve.run()`, `zts` CLI | NOT guarded. These are inspection tools that return filtered text by design. They are not release paths and must not be wired to one. |

A structural test fails if a second place builds a released result or calls the
release sink.

## Required production configuration

```python
trust = FileTrustRoot("/etc/zts/trust.json")        # the keys you pinned; see WIRE_FORMATS.md
enforcer = Enforcer(
    verifier=Ed25519GrantVerifier(trust, on_reject=alert),
    revalidator=HttpStatusRevalidator("https://issuer.internal", trust, timeout=3.0),
    replay_store=PostgresReplayStore("host=db.internal dbname=zts sslmode=verify-full"),
)
tower = DeterministicIntegrityTower(
    "ops",
    production=True,                  # refuse to start unless the controls below are present
    release_gate=EnforcerReleaseGate(enforcer, policy_version="2026-11-3", timeout=5.0,
                                     identity_verifier=authenticate),     # optional
    release_sink=deliver,             # the protected delivery callback
    delivery_confirmer=receiver_has,  # asks the RECEIVING side
    hmac_key=release_signature_key,   # supplied, not generated per process
    ledger=ValLedger(key=ledger_key, store=FileLedgerStore(ledger_path),
                     anchor=Rfc3161Anchor(tsa_url, [tsa_signing_cert_pem], receipts_path)),
)
identity = ...                         # a cns.governance.IdentityContext from your identity layer
request = ReleaseRequest(
    identity=identity, artifact=CNSDock().to_zts_artifact(identity),
    release_id=unique_per_attempt,     # becomes the Enforcer request id
    scope="tenant-1/ops-report",
    proof_provider=ask_issuer,         # receives a ReleaseCandidate, returns grant bytes
)
result = tower.enforce(text, release=request)       # or: await tower.run(prompt, generator, release=request)
```

For one host you may use `SQLiteReplayStore("/secure/path/replay.db")` instead of PostgreSQL. Enforcer itself
ships no verifier or status source (its defaults reject everything); the three adapters above are ZTS's.
**The issuer and status service are not part of ZTS or Enforcer.** You run them, they sign what
[WIRE_FORMATS.md](WIRE_FORMATS.md) specifies, and who owns their keys is your decision.

A grant cannot be issued for output that does not exist yet. `proof_provider` exists for that: after the
sieve has produced the final text, ZTS passes the provider a `ReleaseCandidate` (digests and canonical
envelope bytes, never the text) and expects grant bytes back, bounded by the gate's timeout. A pre-issued
`proof` also works when the artifact is known in advance. Supply one or the other. Anything the provider
returns is verified by Enforcer; the provider cannot grant by returning something. In `run()` the whole
release path runs on a worker thread, so these blocking calls do not stall the event loop.

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

A release that does not deliver returns a `TowerResult` with `released=False`,
`output=""`, no signature and no checksum, no payload text anywhere in `sieve`
(it is `sieve.redacted()`), and a ledger entry. If the delivery callback was never
reached, it was never called. `release_outcome` is one of the `ReleaseState` values,
each a different fact:

| State | Callback ran | Grant | Output returned |
|---|---|---|---|
| `denied` | no | unspent | no |
| `not_attempted` | no | unspent | no |
| `failed_before_delivery` | no | spent | no |
| `delivery_unknown` | began, or finished unconfirmed | spent | no |
| `delivered_audit_incomplete` | yes | spent | yes |
| `delivered_unverified` | yes | spent | yes |
| `delivered` | yes, and confirmed | spent | yes |
| `released_legacy` | yes (legacy capstone) | n/a | yes |

`delivered` needs all three: Enforcer allowed and the callback finished; the receiving side
confirmed (`delivery_confirmer` returned exactly `True`); and the final ledger entry was fsynced
to a durable store. Without a confirmer the best state is `delivered_unverified`. With an
in-memory ledger, or when the last write failed, it is `delivered_audit_incomplete`. A
confirmer that says no, raises, or does not answer within `confirm_timeout` makes the state
`delivery_unknown` and withholds the output, even though the callback ran. `grant_state` in the
evidence is `unspent`, `spent`, or `unknown` (after an Enforcer timeout or a replay-store error,
when the grant may or may not have been consumed; treat it as spent).

`reason_code` is Enforcer's code (`PROOF_MISSING`, `PROOF_INVALID`,
`SCOPE_MISMATCH`, `GRANT_EXPIRED`, `GRANT_REPLAYED`, `AUTHORITY_STATUS_STALE`,
`GRANT_REVOKED`, ...) or a ZTS code from `ReleaseReason` (`CNS_UNAVAILABLE`,
`CNS_CONTRACT_INCOMPATIBLE`, `CNS_IDENTITY_UNTRUSTED`, `CNS_VERIFICATION_FAILED`,
`ENFORCER_UNAVAILABLE`, `ENFORCER_INCOMPATIBLE`, `ENFORCER_ERROR`,
`ENVELOPE_INVALID`, `RELEASE_ID_MISSING`, `RELEASE_SCOPE_MISSING`,
`RELEASE_REQUEST_MISSING`, `PROOF_PROVIDER_ERROR`, `ARTIFACT_CHANGED`,
`LEDGER_UNAVAILABLE`, `RELEASE_ACTION_FAILED`, `RELEASE_NOT_CONFIGURED`,
`SIEVE_BREACH`, `DELIVERY_UNCONFIRMED`, `RELEASE_CANCELLED`, `SHUTTING_DOWN`, `ENFORCER_TIMEOUT`,
`PROOF_PROVIDER_TIMEOUT`, `POLICY_CHANGED`, `PRODUCTION_INVARIANT_VIOLATED`).

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
  are required, and the `delivery_unknown` outcome tells the caller to check
  downstream state before issuing one.
* By default revocation is checked once, inside Enforcer, immediately before the grant is spent. A
  revocation that arrives after that check and before the callback's effect is not
  caught (a tested known limit: `test_release_residual.py`, `test_reask_status.py`).
  With `EnforcerReleaseGate(..., reask_status=True)` (needs Enforcer 0.1.2, which exposes its
  verifier and status source) the status source is asked a second time inside the guarded call,
  as the last step before delivery begins, with Enforcer's own verifier and status source. ZTS
  does not re-implement the decision: it checks only that the answer is a status, is CURRENT,
  names this envelope and policy, and has well-formed times. Anything else refuses delivery with
  `GRANT_REVOKED_BEFORE_DELIVERY` (the source said revoked) or `STATUS_RECHECK_FAILED`
  (no usable answer). The grant is already spent, so the outcome is `failed_before_delivery`,
  and a new grant is needed. This narrows the window to one round trip; it cannot close it,
  and it costs one more call to the status service per release.
* Timeouts: `EnforcerReleaseGate(timeout=...)` bounds the grant provider and the whole
  Enforcer call (proof verification, status revalidation and replay consumption are
  all inside it). A call that times out before the callback starts is marked abandoned
  under the same lock the callback takes, so if it wakes later and allows, the callback
  refuses. If the callback has already started, delivery is waited for, not abandoned.
  The grant is then reported `unknown`, since the late call may have consumed it.

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
* **Durable store.** `FileLedgerStore` appends one entry per line and fsyncs before
  `log()` returns, serializes appenders across processes with `flock`, and catches up
  with entries other processes appended. A write that cannot be persisted raises and the
  entry is not acknowledged. Files are created mode 600, and opening one writable by
  others is refused.
* **Recovery.** Opening verifies the whole chain. A final line without its newline is an
  unacknowledged interrupted write: it is removed, copied to `<ledger>.torn`, and reported
  in `ledger.recovery`. Every other defect (a line that does not parse, a broken link, a
  wrong sequence or digest) raises `LedgerCorruptionError` and is not repaired.
* **Write-ahead.** The `ATTEMPT` entry must be written before any grant is requested, so
  an unwritable audit trail stops the release before anything is spent.
* **Anchor.** A `LedgerAnchor` receives each head; `verify_anchored()` detects truncation, rollback and tail
  replacement against it. Two real anchors ship. `Rfc3161Anchor` stamps heads with a timestamp authority
  whose signing certificate you pin, re-verifies every token on every read, stamps lazily so a slow TSA never
  stalls a ledger write, and is flushed at the end of each release; if the TSA is down the delivery stands,
  `audit_anchored` is False, `anchor_failures` counts it and `health()` turns degraded. `FileLedgerAnchor`
  writes heads to a second file. Neither is independent by itself: a TSA proves a head existed but does not
  remember your ledger, so an attacker who rewrites both the ledger and the receipts file can restore an older
  consistent pair; keep copies of the receipts where the writer cannot reach them. Tested against OpenSSL's
  independent RFC 3161 implementation, not any public TSA. If an anchor accepts a head and the file write then
  fails, the anchor is exactly one entry ahead; that is reported, not healed, because it looks identical to a
  removed tail.
* **Not provided.** Replication, backup, retention or pruning of the ledger, rotation of the ledger key, a
  ledger shared by several hosts, a ledger on a filesystem where `flock` or `fsync` are not honored.
* If a release is authorized inside Enforcer but ZTS stops it before delivery, the Enforcer decision record is
  kept only with Enforcer 0.1.1 or later (`execute(on_allow=...)`). With 0.1.0 that entry carries ZTS's
  reason and `authorized` but no decision record. ZTS detects which it has on every call.

## Trust, status, replay and anchor: what each component checks

* **Grant verification** (`zts.trust`): one algorithm (Ed25519) named in the signed header; a pinned key by
  id; the key's role, status and validity window; the key bound to the grant's issuer; the grant's whole
  lifetime inside the key's window; the signature before the claims are parsed; strict canonical encoding
  with no duplicate keys. Every refusal is the same generic error to Enforcer and a specific code to the
  `on_reject` hook (`unknown_kid`, `revoked_key`, `bad_signature`, `unsupported_alg`, `key_window`,
  `issuer_mismatch`, `wrong_role`, `format`, `claims`, `trust_root`). Formats: [WIRE_FORMATS.md](WIRE_FORMATS.md).
* **Status** (`zts.status`): verified HTTPS only, no redirects, 64 KiB cap, hard timeout, a status-role
  signature, and an echo of a fresh challenge plus the envelope digest, policy version, issuer and nonce. No
  cache. Enforcer applies the freshness bound. Failure is denial (`AUTHORITY_REVALIDATION_ERROR`).
* **Replay** (`zts.replay_postgres`): one atomic insert over two unique constraints; any database error is a
  denial; `production=True` refuses a table that lost either constraint.
* **Identity** (`identity_verifier` on the gate): optional, exact-`True` only, bounded by the gate timeout, run
  before Enforcer is asked and again just before delivery. `zts.identity.Ed25519IdentityVerifier` is a ready one: it checks an
  identity provider's Ed25519 signature (key role `identity` in the trust root) over the identity's fields, an audience and a short
  validity window, carried in `IdentityContext.signature`. A signed identity is a bearer credential until it expires.
* **Production validation** reports PASS only for ZTS's own implementations, and only for what ZTS verified
  about them (for example, the trust root loads and holds a usable key of the right role). Trust-root
  governance, anchor independence, identity authentication, TLS to a local database and any custom adapter
  stay UNKNOWN.

## CNS compatibility

The dock accepts CNS releases of an accepted major version (`CNS_ACCEPTED_MAJORS`, now 2, 3 and 4) at or above
`CNS_CONTRACT_VERSION`, now `2.3.0`, which is the release `pyproject.toml` pins
(tag `v2.3.0`, commit `41592fb7b6735abe140f745353c09ba3eed8e7a2`). Before this
change the floor was `1.4.0` and refused major 2, so the dock refused the very
release ZTS pins: with the real pinned CNS installed, 19 existing tests failed.
1.x releases are now refused because nothing was verified against them. Major 3 was added after
reading CNS 3.0.0's release note: its only breaking change is that `subject_digest` refuses a
subclass of `str`, `int`, `float`, `dict`, `list` or `tuple` (a `str` Enum, for one), and plain
values digest as before. The dock passes plain values, so an ordinary identity behaves the same
on 2.x and 3.x; an identity that carries a subclass is refused by CNS 3.x and the release is
denied `CNS_IDENTITY_UNTRUSTED` (`tests/test_cns_three.py`). Major 4 is refused until it is read
the same way. The
dock refuses anything that is not a plain `X.Y.Z` string. If CNS is unavailable,
incompatible or cannot verify the binding, a release is denied; a locally made
identity is never substituted.

Enforcer is accepted on `0.1.x` only, because it is a 0.x prototype whose minor
releases may break. It is pinned in `pyproject.toml` to commit
`e4d5688e1564d91ded7d5337e93c0b734375d073` (0.1.2, Enforcer PR #9).

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

The decisions behind these, and what was chosen, are in [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md).

1. **The trust root's legitimacy.** ZTS verifies against keys you pinned. Who owns them, how they are stored,
   rotated and revoked, and who may edit the file are operator decisions. There is no reference issuer.
2. **A revocation after the issuer's status answer and before the callback starts is missed.** Measured
   (Phase 2 audit): an issuer that revokes the instant it answers CURRENT still sees the release delivered, and
   the next release refused. The window runs from the signed answer to the start of the delivery callback. It
   holds the replay-store round trip, Enforcer's `on_allow`, the second CNS and identity check, and nothing
   else, so it is as short as those are fast: 0.0 s with no database latency, 2.5 s with 2.5 s of it. It is
   bounded by the gate's `timeout` (a release not started by then is abandoned and denied), not by Enforcer's
   30 s freshness limit, which is checked once, before the grant is consumed. `timeout=None` leaves it
   unbounded, which `production=True` refuses. It is not eliminated, and ZTS does not claim instant
   revocation. A second status request just before the callback would narrow it to one round trip, never to
   zero; that was considered and not done.
3. **Replay durability stops where your database's does.** Asynchronous failover can forget a spent grant.
   A custom replay store is reported UNKNOWN.
4. **Anchor independence is a deployment fact.** A TSA does not remember your ledger; a consistent rollback of
   ledger and receipts goes unnoticed unless newer receipts are held elsewhere. Not interop-tested against a
   public TSA.
5. **ZTS does not authenticate the identity it is given.** The grant issuer, or your optional hook, does.
6. **Code in the same process is not contained.** It can call the delivery callback, read keys, or edit memory.
   Sealing the tower's and the gate's attributes stops accidents and ordinary assignment, not an attacker.
   The control is process or network isolation of the delivery path.
7. **Confirmation is only as independent as the confirmer.** If it asks the sink's own process, it proves nothing.
8. **A released result keeps its full sieve record**, including `payload_in` and the matched text of findings.
   Only results whose output was withheld are redacted. The ledger never holds matched text.
9. **Cancellation returns no result for a release that finished.** `CancelledError` means the outcome was not
   returned; the ledger holds it.
10. **Behavior changes for existing callers** (see CHANGELOG): the default tower no longer releases;
    `tower.tap` is `None` unless a capstone was passed; the CNS floor is 2.3.0; the `release_outcome` values
    changed; release controls are read-only after construction.
11. **The test issuer, status service, TSA and receiver are fixtures.** They prove the code against
    independent implementations, and nothing about a real issuer, authority or TSA.

## Tests

All of these run the real tower, adapter, CNS and Enforcer; the only stand-ins are the two test
trust adapters in `tests/release_kit.py`, which are named as fixtures and are not production code.

* `test_release_boundary.py`: the original attack list, each denial checked for no output, no
  signature, the callback never ran, a ledger entry, and an unambiguous result; sync and async.
* `test_release_states.py`: every release state reached for real; independent confirmation.
* `test_release_async.py`: cancellation at each stage, timeouts and late arrival, shutdown, policy
  and subject changes after authorization, concurrent distinct releases.
* `test_release_residual.py`: altered artifact under a reused id, several writers on one replay
  file, partial delivery, anchor failure at the decision point, truncation after a release, and
  the known limits.
* `test_release_containment.py`: sealed controls, the forced-swap invariant, structural checks
  that no second release path exists.
* `test_ledger_durable.py`, `test_ledger_hardening.py`: persistence, torn-write recovery,
  corruption refusal, truncation/rollback/replacement against an anchor, four real processes
  writing one chain.
* `test_ops.py`: metrics, audit events, production validation, health.
* `test_release_defaults.py`: the safe default, legacy isolation, independence from CNS and
  Enforcer. Needs neither package.
* `test_trust_ed25519.py`, `test_wire_vectors.py`: the verifier against an independent issuer; golden vectors.
* `test_status_http.py`: the status client against a real HTTPS service (TLS, signatures, challenge, timeouts).
* `test_replay_postgres.py`: the replay store against a real PostgreSQL server, including a two-host race.
* `test_anchor_tsa.py`: the RFC 3161 anchor against tokens issued by OpenSSL.
* `test_identity_hook.py`, `test_enforcer_extensions.py`: the identity hook; Enforcer 0.1.1's additions.
* `test_production_assembly.py`: the real stack assembled and attacked end to end.
* `test_cns_version_rule.py`, `test_cns_connector.py`: the version floor and the dock against real CNS.

CI has a job with `.[dev,cns,enforcer]`, and a `production-stack` job with every extra plus a real
PostgreSQL and OpenSSL, under `ZTS_REQUIRE_CNS/ENFORCER/POSTGRES/TSA=1`, so a missing package fails the run
instead of skipping.
