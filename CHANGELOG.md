# Changelog

## Unreleased

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
