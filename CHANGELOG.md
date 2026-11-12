# Changelog

## Unreleased

### Deployment support (ninth pass)

Added:
- `zts.identity.Ed25519IdentityVerifier` (deployment step 6): a ready `identity_verifier` hook. The identity provider signs the
  identity's fields (tenant, subject, roles, trust level, authentication method, `verified`), an audience and a validity window
  with its own Ed25519 key; the result travels in the `signature` field of the CNS `IdentityContext`. The hook returns True only
  if the key is a current `identity`-role key in the trust root, the signature covers exactly these fields, the audience is
  ours, the window is current and no longer than 300 s, and `verified` is true. It never raises. New trust-root role
  `identity`; a key of another role is refused and an identity key cannot verify grants. Readiness: `identity_authentication`
  is PASS for this verifier with a usable key (FAIL with none, UNKNOWN for any other hook), and a live `trust_root_identity_keys`
  check. `examples/identity_provider/` has a reference signer that depends only on `cryptography` (checked against the
  verifier) and the identity provider's checklist. `tests/test_identity_auth.py` (78 tests, including through the real release
  gate, checked again just before delivery); nine mutations fail it. NOT done: connecting a real identity provider.
- `examples/isolation/`: a separate release service on its own account. `setup_accounts.sh` builds the accounts and the layout
  (trust root root-owned so a compromised service cannot rewrite who it trusts; secrets and state 700 and service-owned);
  `zts-release.service` is a hardened systemd unit (offline exposure score 1.1, "OK"); `check_isolation.py` is acceptance
  test 14 (run as the application, nothing may succeed; run as the service with `--expect-access` as a control so a typo is not
  a pass; a missing path is an ERROR; running as root is refused). `tests/test_isolation_example.py` builds the layout and runs
  the check as real `nobody` and `daemon` accounts, loosens permissions five ways and finds exactly those, and checks the
  check changes nothing; six mutations fail it. NOT provided: the release service program itself (its request format is a design
  decision). The unit has not been started under a real systemd.
- `docs/TRUST_ROOT_PROCEDURE.md` and `examples/trust_root_repo/`: the two-person trust-root review as a procedure (roles, an ordinary
  change, a rotation order, an emergency revocation path, deployment and confirmation, routine checks, what it does not protect
  against) and a ready set-up for a separate repository: a workflow that runs `scripts/trust_root_review.py` on every pull
  request against the file live on the base branch and posts the result, a code-owner list that also covers the workflow, and a
  branch-protection checklist. `tests/test_trust_root_repo_example.py` runs the workflow's own review script against real git
  histories (good edit, un-revoke, serial not raised, broken file, first version, workflow-only change) and holds properties of the
  file (pull_request not pull_request_target, read-only permissions, actions pinned to commits, no event value in a shell command);
  five mutations fail it. The workflow itself has not run on GitHub.
- `examples/receipt_receiver/`: a reference receiver for a locked AWS S3 bucket (Object Lock, write-if-absent, COMPLIANCE or
  GOVERNANCE mode), with a Lambda entry point, least-privilege IAM, a trial checklist and what to alarm on. A repeated receipt
  is accepted, a different one for a stored sequence is refused 409, and with a pinned authority certificate a receipt whose
  token does not verify is refused 422. `tests/test_receipt_receiver.py` (38 tests, including the real exporter over TLS and
  real tokens from OpenSSL's authority); seven mutations fail it. The S3 calls ran only against a stand-in client.
- `docs/ACCEPTANCE_RECORD.md`: a fill-in record for the 14 acceptance tests (what to do, what is expected, what to measure, what
  evidence to attach, pass or fail, initials, sign-off). A guide test keeps it to exactly the guide's 14 tests, in order.
- `zts.receipts.HttpsReceiptExporter`: a ready `on_receipt` hook (bounded HTTPS POST, URL never in an error) with `resend()`
  that fills an outage without leaving a gap. `tests/test_receipt_export.py` runs it against a local TLS receiver; three
  mutations (swallowing errors in resend, an off-by-one on the sequence, accepting http) each fail it. It cannot supply the
  separation that makes an off-box copy worth having: that is the destination's job.
- `scripts/trust_root_review.py`: the second person's tool for a trust-root edit (valid under ZTS's own parser, key table, pin
  value, and a diff that fails on a serial that does not rise, a revoked key made active, or a changed role or issuer).
  `tests/test_trust_root_review.py`; three mutations fail it.
- `docs/DEPLOYMENT.md`: the edit procedure, the exporter, and a table of which repository test proves each acceptance test's
  mechanism against which stand-in, and what only a run in your environment can show.

Not done, and not doable from here: a run against your issuer, status service, database, TSA or network.

### Open items closed (eighth pass)

Changed:
- Pins Enforcer to 0.1.2 (`e4d5688`, Enforcer PR #9); CI sets `ZTS_REQUIRE_ENFORCER_012=1` in the `enforcer`, `production-stack`
  and `cns-3` jobs, so the re-ask and accessor tests cannot silently skip there.

Added:
- `EnforcerReleaseGate(..., reask_status=True)`: asks the status source a second time inside the guarded call, as the
  last step before delivery begins, using Enforcer's own verifier and status source (Enforcer 0.1.2 and later; the
  constructor raises `ValueError` on an Enforcer that does not expose them). A status that is revoked refuses delivery
  with `GRANT_REVOKED_BEFORE_DELIVERY`; no usable answer is `STATUS_RECHECK_FAILED`. Both are `failed_before_delivery`
  (the grant is spent). It narrows the revocation window to one round trip and does not close it. A re-ask that
  outlives the gate timeout cannot deliver. Off by default; behaviour without it is unchanged. Tests:
  `tests/test_reask_status.py`; each mutation of the new code (no call, revoked ignored, binding ignored, call after
  the abandoned check) fails it.
- `scripts/tsa_interop.py` (tested against OpenSSL's TSA in `tests/test_tsa_interop_script.py`): stamps one head with
  a real authority through ZTS's own client and verifies it against the certificate you pin. Not run against a public
  authority: this sandbox cannot reach one, so that run is yours.
- Readiness check `status_recheck` (PASS when on, UNKNOWN when off). Both new reasons are classified in `ops`.
- The dock accepts CNS major 3 (`CNS_ACCEPTED_MAJORS = (2, 3)`), after reading CNS 3.0.0's release note: its only
  breaking change is that `subject_digest` refuses a subclass of `str`, `int`, `float`, `dict`, `list` or `tuple`.
  Executed: the whole suite against CNS 3.0.0 passes apart from the tests that asserted 3.x was refused. An identity
  carrying such a subclass is denied `CNS_IDENTITY_UNTRUSTED` (`tests/test_cns_three.py`). Major 4 stays refused.
  `pyproject.toml` still pins CNS 2.3.0; a CI job runs the suite against 3.0.0.

Changed:
- Readiness reads the verifier, status source and replay store through Enforcer 0.1.2's public properties when they
  exist, and falls back to the private attributes (in the one documented helper) for 0.1.0 and 0.1.1.
- Existing tests edited, each because the change above alters exactly what they assert: `test_cns_version_rule.py`
  (3.x accepted, 4.x refused, instead of 3.x refused), `test_release_boundary.py::test_attack_14_incompatible_cns_version`
  (the refused example is 4.0.0, not 3.0.0). The CNS error message now names the accepted majors.
- Test helper `release_kit.build` takes `reask_status`.

### Crash drill (seventh pass)

Added:
- `tests/test_crash_recovery.py` (with `tests/crash_host.py`): a real host process is killed with SIGKILL in the middle
  of a delivery, against a real PostgreSQL, trust root, status client, RFC 3161 anchor and ledger file; a fresh process
  then opens the same files. Verified: the ledger opens and its chain and anchor verify; the grant is spent (a retry is
  denied `GRANT_REPLAYED`); a new release under a new grant delivers; health is `ok`.
- `docs/DEPLOYMENT.md`: a verified helper, `unfinished_releases(ledger)`, that lists releases whose delivery began and
  was never recorded as ended. It is tested against a retry under the same release id, which writes its own entries and
  must not hide the earlier unfinished delivery.

Changed:
- The guide's acceptance test 11 said a killed host's release is `delivery_unknown`. It is not: a hard kill leaves a
  `RELEASING` entry and nothing after it, because no process was alive to record anything. The guide and the operations
  document now say so and point at the helper.


### Readiness through the public interface, and a deployment guide (sixth pass)

Added:
- `docs/DEPLOYMENT.md`: components you must provide, trust-root and issuer contract, PostgreSQL roles and grants
  (found by experiment on PostgreSQL 16), TSA and receipt custody, tower assembly, what each readiness check means,
  process-isolation objectives, and 14 acceptance tests to run in your own environment. `tests/test_deployment_guide.py`
  runs its SQL against a real PostgreSQL, checks its Python against the real signatures, requires every readiness check
  to be named in it, and checks the numbers it quotes against the code.
- Readiness check `enforcer_policy` (limits read from `Enforcer.describe()`; UNKNOWN when looser than recommended).
- Public read-only accessors: `EnforcerReleaseGate.enforcer` and `.dock`, `ValLedger.anchor`,
  `DeterministicIntegrityTower.release_signature_key_supplied`, `Ed25519GrantVerifier.trust`,
  `HttpStatusRevalidator.trust`; `ops.RECOMMENDED_LIMITS`.

Changed:
- Readiness takes identifiers, replay-store facts and limits from `Enforcer.describe()`. A fact taken that way can only
  produce FAIL or UNKNOWN; PASS still needs the real adapter object. The private reads that remain (Enforcer's three
  adapters, and the SQLite connection on Enforcer 0.1.0 only) are confined to two documented helpers, and a test fails if
  another appears.


### Phase 2 audit follow-up (fifth pass)

Changed:
- The status client (`https_post`) and the timestamp client (`http_post`) share one bounded POST
  (`zts._http.bounded_post`). `timeout` is now the total time for the TLS handshake, the request and the
  response, enforced by a watchdog that closes the socket, not the length of one wait. A response cut off by the
  deadline is never returned as an answer. Name resolution and the TCP connect are not covered. Error texts
  are unchanged, plus `did not answer within Ns`.
- `FileTrustRoot` parses strictly (repeated keys, `NaN` and `Infinity` are refused), accepts only a regular file
  of at most 1 MiB, opens it once and checks and reads that open file, and on every use checks the directories that
  decide what the path means (parents, symlink targets one step at a time, the resolved file): owned by this user
  or root, not writable by others, sticky directories accepted.


### Phase 2 audit hardening (fourth pass)

Added:
- `Rfc3161Anchor(max_unanchored_entries=500, max_unanchored_age=300.0, on_receipt=)`, `.behind()`, `.catch_up()`,
  `.receipts()`; `ValLedger.anchor_behind()`. New release reason `ANCHOR_BEHIND` (outcome `not_attempted`): checked
  before the tower writes anything, so a hold cannot grow the gap. Lifts by itself when the TSA stamps again.
- Trust root: optional `serial`; `FileSerialStore`, `PostgresSerialStore`; `FileTrustRoot(serial_store=,
  recheck_interval=)` and `.describe()`; readiness `trust_root_rollback`.
- `HttpStatusRevalidator.describe()` (TLS posture). `health()` now covers trust-root keys, the replay table and the
  anchor backlog. Metrics `expected_denials`, `unclassified_denials`; `ops.EXPECTED_REASONS`.

Changed:
- Seven more tower attributes are sealed after construction: `zts`, `kg`, `lc`, `_key`, `_key_id`, `_sealed`.
- `PostgresReplayStore` refuses a table without both uniqueness constraints at construction and on every `consume`;
  `prune()` uses the database clock and refuses a grace period under 30 s (`MIN_GRACE`).
- Readiness: a status client with an unverified TLS context FAILs; one with a custom transport, `sslmode=verify-ca`,
  and an anchor the TSA has not yet answered are UNKNOWN (they were PASS). Anchors without a bound FAIL.
- Alert buckets now cover every denial code (identity, lifetime, status-stale and others).
- Documentation: the revocation window is described as bounded by the gate timeout (it said Enforcer's freshness
  limit, which does not bound it).

Existing tests changed because they asserted exactly the behavior above:
- `test_production_assembly.py::test_a_tower_built_from_the_real_components_passes_production_validation`:
  `anchor_service` is UNKNOWN on a fresh tower, not PASS.
- `test_production_assembly.py::test_production_refuses_a_replay_table_that_has_lost_a_uniqueness_constraint`:
  the refusal now comes from the store (`ReplayStoreError`) when it is built.
- `test_release_residual.py` docstring only: the revocation window's bound.


### Real trust, status, replay and anchor components (third pass)

Added (optional extras; `zts` itself still has no runtime dependency):
- `zts.trust` (`zts[trust]`): `Ed25519GrantVerifier`, `FileTrustRoot`, `TrustRoot`. One algorithm, pinned
  keys by id, role/status/window/issuer checks, signature before parsing, canonical strict encoding,
  rotation and revocation by editing the file, no fallback when the file breaks.
- `zts.status` (`zts[trust]`): `HttpStatusRevalidator`. Verified HTTPS only, signed answers, a fresh
  challenge echoed back, no redirects, size cap, timeout, no cache.
- `zts.replay_postgres` (`zts[replay-postgres]`): `PostgresReplayStore`, a shared replay store for several
  hosts. Safe `prune()`; `health()` verifies its uniqueness constraints.
- `zts.anchor_tsa` (`zts[tsa]`): `Rfc3161Anchor`, an external ledger anchor on a timestamp authority you pin.
  Lazy publishing with back-off, flushed at the end of each release; every token re-verified on every read.
- `EnforcerReleaseGate(identity_verifier=)`: optional, fail-closed, checked before Enforcer is asked and
  again before delivery. `ReleaseReason.IDENTITY_NOT_AUTHENTICATED`.
- `TowerResult.audit_anchored`; metrics `anchor_failures`; `health()` reports `anchor_service`.
- `production=True` now reports PASS for ZTS's own verifier, status client, replay store and anchor (and FAIL
  for an empty trust root, an unreachable replay table, a table missing a uniqueness constraint, a non-verified
  TLS path to a remote database) while trust-root governance, anchor independence and identity stay UNKNOWN.
- `docs/WIRE_FORMATS.md` and byte-exact golden vectors (`tests/test_wire_vectors.py`).
- `pip install "zts[production]"`; a `production-stack` CI job with a real PostgreSQL and OpenSSL.
- Uses Enforcer 0.1.1's `on_allow` when present (decision record kept on an aborted release); still works
  with Enforcer 0.1.0.
- Pins Enforcer to 0.1.1 (`b2ee452`, Enforcer PR #7).

Changed:
- The structural test that only `release.py` may import Enforcer now allows the adapter modules, each
  importing it inside a function. Optional third-party packages may only be imported inside functions.
- `EnforcerReleaseGate.timeout` and `identity_verifier` are read-only after construction.

Not done:
- The issuer and status *services* (they are yours), a reference trust-root tool, interop with a public TSA,
  replication or failover durability of the replay database, ledger retention.


### Production hardening of the release boundary (second pass)

Added:
- `zts.ledger_store`: `FileLedgerStore` (append-only JSONL, fsync per entry, cross-process `flock`,
  torn-write recovery, refusal to auto-heal corruption) and `FileLedgerAnchor`. `ValLedger(store=)`,
  `.durable`, `.anchored`, `.recovery`.
- `ReleaseState`: the six release states and their facts. `TowerResult.delivery_verified`,
  `TowerResult.audit_durable`.
- `DeterministicIntegrityTower(delivery_confirmer=, confirm_timeout=, ledger=, production=)`: success
  now needs the receiving side's confirmation when a confirmer is configured.
- `EnforcerReleaseGate(timeout=)`: bounds the grant provider and the Enforcer call; an abandoned call
  can never deliver late. `ReleaseOutcome.grant_state`.
- `run()` releases on a worker thread (the event loop is no longer blocked) with cooperative
  cancellation. `close()`, `TowerClosedError`, `inflight`.
- `zts.ops`: `ReleaseMetrics`, structured audit events on the `zts.release` logger,
  `tower.readiness()`, `tower.health()`, `ProductionConfigError`.
- `docs/PRODUCTION_READINESS.md` (decisions required), `docs/OPERATIONS.md`.

Changed (BREAKING for anything built on the previous unreleased commit):
- `release_outcome` values: `released` is now `delivered`, `delivered_unverified` or
  `delivered_audit_incomplete`; `held` is `not_attempted` or `failed_before_delivery`;
  `unconfirmed` is `delivery_unknown`; `released_unrecorded` is `delivered_audit_incomplete`;
  legacy releases are `released_legacy`.
- A tower's release controls are read-only after construction.
- An in-memory ledger can no longer yield `delivered`.

Fixed:
- A `require_enforcer` tower could be turned into a legacy-AUTO tower by assigning two attributes.
- `run()` blocked the event loop for as long as any provider, sink or Enforcer call took, and
  ignored cancellation.
- Success was reported when the delivery callback returned, with no independent check.

Existing tests edited: `tests/test_release_boundary.py`, `tests/test_release_defaults.py` and
`tests/release_kit.py` (outcome names and the kit's default ledger), all from the previous unreleased
commit.

Release boundary. Behavior changes for existing callers are marked BREAKING.

### Added
- `zts.release`: `EnforcerReleaseGate`, `ReleaseRequest`, `ReleaseCandidate`,
  `ReleaseOutcome`, `ReleaseReason`. Output is released only inside Enforcer's
  guarded call, bound to the CNS subject digest, the exact artifact, operation,
  scope, release id and policy version. `pip install ".[enforcer]"`.
- `DeterministicIntegrityTower(release_gate=, require_enforcer=, release_sink=)`
  and `enforce(..., release=)` / `run(..., release=)`.
- `TowerResult.release_outcome`, `reason_code`, `release_id`, `authorization`.
- Ledger: writes are serialized by a lock; optional `LedgerAnchor`,
  `ValLedger(anchor=)`, `verify_anchored()`, `LedgerAnchorError`.
- `docs/RELEASE_BOUNDARY.md`.
- Tests: adversarial release suite, default and structure tests, ledger tests.

### Changed
- Ledger gate entries record the gate code and the number of findings in `detail`,
  not the matched text of each finding. Matched text is payload text.
- BREAKING: a `TowerResult` whose output was withheld carries `sieve.redacted()`:
  `payload_in`, `payload_out`, each gate's payloads and the matched text of
  findings and flags are blanked. Verdict, score, gate, offsets and counts are kept.
  Code that read the filtered text from a held result must stop; that was a way
  around the release boundary. Released results are unchanged.
- BREAKING: a tower with no `capstone` and no `release_gate` holds everything
  (`RELEASE_NOT_CONFIGURED`). It used to release everything that cleared the
  sieve (`ReleaseMode.AUTO`). Callers that want the old behavior must pass
  `capstone=ArchitectsProtocol(ReleaseMode.AUTO)` explicitly.
- BREAKING: `ArchitectsProtocol()` with no argument is `SEALED`, not `AUTO`.
- BREAKING: `DeterministicIntegrityTower.tap` is `None` unless a capstone was passed.
- BREAKING: `CNS_CONTRACT_VERSION` is `2.3.0`. The dock accepts CNS 2.x at or above
  2.3.0 and refuses 1.x. The old floor, `1.4.0`, refused major 2, so the dock
  refused the CNS release the package itself pins (`v2.3.0`).
- The legacy `AUTO` path records in the ledger and the result that no
  authorization was performed.

### Existing tests edited (behavior they asserted changed)
- `tests/test_cns_version_rule.py`: version numbers moved to the 2.3.0 floor.
- `test_causality`, `test_dashboard`, `test_ledger_keyed`, `test_ledger_keyfile`,
  `test_passive`, `test_signature`, `test_tower`: twelve tests that built a tower
  with no capstone and expected a release now pass
  `capstone=ArchitectsProtocol(ReleaseMode.AUTO)` explicitly. Nothing else in them
  changed.

### Not done
- No production proof verifier, status source or issuer. No durable or external
  ledger, no operational anchor, no multi-host replay store. See
  `docs/RELEASE_BOUNDARY.md`, "Known unresolved risks".
