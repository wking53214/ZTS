# ZTS – Zero Trust Stack

A deterministic filtration array for language model output, and the point where that
output is allowed to leave. Seven gates, `G1` through `G7`, run in ascending cost order so
that a cheap syntactic check rejects a payload before an expensive semantic one has to
look at it.

## What ZTS does, and does not do

**Does.** It removes first-person voice, hedging, flattery and affect vocabulary from
generated text; it detects attempts to overwrite its own governing instructions; and it
holds the result at G7 until something outside the pipeline authorizes that exact release.
At G7 it enforces an [Enforcer](https://github.com/wking53214/Enforcer) authorization
decision, delivers through a protected callback, asks the receiving side whether the
delivery arrived, and writes a durable, hash-chained audit record.

**Does not.** It does not decide who may receive output (Enforcer's grant does). It does not
issue grants, hold a trust root, or know whether an authority is trustworthy. It does not
authenticate the caller's identity; it only binds the release to the identity's CNS digest.
It does not make the output true, safe or appropriate: the gates are lexical and syntactic
filters. It is a library inside your process and cannot contain code that runs in that same
process. See "Guarantees NOT provided" below.

```
                    [ INGESTION PERIMETER ]
                              │
         ┌────────────────────▼────────────────────┐
         │ LC   Logic Cornerstone                  │  normalize, strip control chars
         └────────────────────┬────────────────────┘
                              │
         ┌────────────────────▼────────────────────┐
         │ ZTS  Zero Trust Sieve   G1–G6           │  fail-fast gate array
         │   G6 PPA → G3 SBF → G1 AB               │  syntactic ─┐
         │   → G5 SND → G2 SCF → G4 HCA            │  lexical ───┼─ ascending cost
         └────────────────────┬────────────────────┘  semantic ──┘
                              │   (blocking finding: HELD, nothing attempted)
                              ▼
   ┌──────────────────────────────────────────────────────────────────────┐
   │ TAP  G7  release boundary                                            │
   │                                                                      │
   │  1 write-ahead ledger entry (durable, or nothing proceeds)           │
   │  2 re-derive the CNS identity binding  ──── CNS: identity, digest    │
   │  3 ask the issuer for a grant for THIS artifact (digests only)       │
   │  4 Enforcer.execute(envelope, grant, guarded)                        │
   │        verifies proof, revalidates status, consumes grant (replay)   │
   │        └─ only after ALLOW ──► guarded callback:                     │
   │             re-check CNS binding, artifact, policy, cancellation     │
   │             ledger entry, then the delivery callback (the sink)      │
   │  5 ask the RECEIVING side whether it holds the artifact              │
   │  6 final ledger entry, fsynced; classify the outcome                 │
   └───────────────────────────────┬──────────────────────────────────────┘
                                   ▼
        delivered │ delivered_unverified │ delivered_audit_incomplete
        denied │ not_attempted │ failed_before_delivery │ delivery_unknown
```

The Thread Alpha / Thread Beta pacing in `run()` (the Kinetic Governor) is unchanged and
described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Install

```bash
pip install -e .
```

No dependencies. Python 3.11+. Two optional extras: `.[cns]` (the CNS identity
dock, CNS `v2.3.0`) and `.[enforcer]` (the release adapter's Enforcer, pinned to a
commit). The release boundary needs both.

## Use

```python
from zts import scrub, audit

scrub("I think we could probably leverage this methodology.")
# 'think apply this approach.'

result = audit("As an AI, I may be wrong about the throughput.", profile="legal")
result.verdict.value   # 'breach'
result.score           # 77
result.findings        # [G6/PPA 'I', G3/SBF 'may', G5/SND 'As an AI']
```

Note what `scrub` did to that first sentence. Deleting "I" from "I think"
leaves "think", which is not a sentence. Substitution-based purging reliably
produces ungrammatical output, and no amount of regex tuning fixes it, because
the gate is deleting a token the surrounding grammar depends on.

This is a real limitation of the design, not a bug in the implementation. Use
`scrub` to see what a payload contains; use `reject` mode to decide whether to
accept it; use the tower's rewrite loop when you need clean text out, because
regenerating under a constraint is the only thing that produces grammatical
output.

Two modes, and the difference is the whole point of the ordering:

```python
from zts import ZeroTrustSieve

# repair: fix violations in place, run every gate, return usable text
ZeroTrustSieve("ops", mode="repair").run(text).payload_out

# reject: stop at the first violation, change nothing, report the breach
ZeroTrustSieve("ops", mode="reject").run(text).breached_at
```

Wrap a generator and let it retry against the specific constraints it violated.
Note what a bare tower does with the result: it holds it. Releasing requires a
release authority (see "Releasing output" below).

```python
import asyncio
from zts import DeterministicIntegrityTower

tower = DeterministicIntegrityTower("ops")
result = asyncio.run(tower.run("Summarize last night's incident.", my_llm_call))
result.output          # '' : no release authority is configured, so nothing is released
result.release_outcome # 'held'
result.reason_code     # 'RELEASE_NOT_CONFIGURED'
result.attempts        # rewrite rounds consumed
tower.ledger.verify()  # (True, 'chain intact')
```

## How the pieces fit

**CNS** ([CNS](https://github.com/wking53214/CNS), pinned `v2.3.0`, commit `41592fb`) is a neutral
contract layer. It supplies the identity shape and `subject_digest`. ZTS uses only `cns.__version__`,
`cns.gate.subject_digest` and `cns.governance.IdentityContext`. CNS decides nothing and grants
nothing: a valid digest proves an identity is the one named, not that it may receive anything.
The dock accepts CNS 2.x at or above 2.3.0 and refuses anything else.

**Enforcer** (pinned to commit `3ff6a56`, accepted as `0.1.x`) is the authorization authority. Its
`execute(envelope, proof, callback)` verifies the proof through a verifier you supply, checks the
grant is bound to the exact envelope, current and within its lifetime, asks your status source for
current authorization, consumes the grant atomically, and only then runs the callback. Its defaults
reject everything. Enforcer is 0.1.0 and describes itself as a prototype.

**ZTS** enforces. The release *is* the callback Enforcer guards, so a denied release has no path to
the output.

## What happens at G7

The envelope ZTS asks Enforcer to authorize binds: the CNS subject digest, the operation
(`zts.release`), the scope, the release id, the policy version, the SHA-256 of the exact
artifact, and the profile. Any other value in a grant is a mismatch and is denied. The six
steps in the diagram run in that order; a failure at any step ends the release with a specific
state:

| `release_outcome` | Meaning | Output returned? | Grant |
|---|---|---|---|
| `denied` | An authorization or precondition check said no | no | unspent |
| `not_attempted` | Nothing reached an authority: unconfigured, sieve breach, no request, audit write-ahead failed, cancelled, shutting down | no | unspent |
| `failed_before_delivery` | Enforcer allowed, ZTS stopped before the callback ran | no | spent |
| `delivery_unknown` | The callback began and did not finish, or the receiver did not confirm | no | spent |
| `delivered_audit_incomplete` | Delivered, and the final record is not durably on disk | yes | spent |
| `delivered_unverified` | Delivered and recorded; no independent confirmation configured | yes | spent |
| `delivered` | Delivered, confirmed by the receiving side, durably recorded | yes | spent |
| `released_legacy` | Released by an explicit legacy capstone. No Enforcer authorization | yes | n/a |

A result whose output was withheld carries no payload text anywhere, including in `sieve`.

## Why the default is to hold

A filter can be wrong, and an automated stack should not be the last thing between generated text
and its consumer. A tower with no release authority holds everything, and `ArchitectsProtocol()`
with no argument is `SEALED`. `ReleaseMode.AUTO` still exists for development and tests, must be
chosen explicitly, performs no authorization, and is refused by `require_enforcer=True` and
`production=True`. Earlier versions defaulted to `AUTO`.

## How proofs are verified, revalidated and kept from replaying

* **Proofs.** Enforcer calls the `ProofVerifier` you configure. **No production verifier exists in
  this repository or in Enforcer.** The tests use an HMAC fixture. Until a real one is chosen
  (decision A in [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md)), an unconfigured
  system denies every release.
* **Revalidation.** Enforcer asks your `AuthorizationRevalidator` for a status bound to the
  envelope and policy version, no older than 30 seconds. **No production status source exists**
  (decision B). Status is checked once, inside Enforcer, immediately before the grant is spent; a
  revocation that lands after that check and before delivery is not caught (a tested known limit).
* **Replay.** Enforcer consumes `(issuer, nonce)` and the request id atomically. On one host with a
  file-backed `SQLiteReplayStore` this holds across restarts and across processes sharing the file
  (tested). In-memory stores forget at restart, and `production=True` refuses one. **Several hosts
  are not protected** (decision C). ZTS bounds the grant provider and the Enforcer call with a
  timeout, and an abandoned call can never deliver late (tested).

## The audit ledger

Every decision appends a hash-chained entry. With a `FileLedgerStore` each entry is written and
fsynced before it is acknowledged, appends are serialized across processes, an interrupted final
write is removed and reported on the next open, and any other damage makes the open fail instead of
being repaired. A write-ahead entry is required before any grant is requested, so a release cannot
begin if the audit trail cannot be written. An optional `LedgerAnchor` (`FileLedgerAnchor` is
provided) lets `verify_anchored()` detect truncation, rollback and tail replacement.

Honest limits: a hash chain is tamper evidence, not tamper-proofing; the anchor only helps if it is
out of the writer's reach, which this code cannot check (decision D); nothing is pruned or
replicated; the ledger holds fingerprints and counts, never payload or matched text.

## Which capabilities are real, and which depend on your deployment

| Implemented and tested here | Deployment-dependent or absent |
|---|---|
| Guarded release; denial never reaches the callback | A proof verifier and a trust root (absent) |
| Six outcome states; independent delivery confirmation | A status/revocation source (absent) |
| Durable, cross-process, recoverable ledger; file anchor | Whether the anchor is independent (unknown) |
| Cancellation, timeouts, graceful shutdown, off-loop `run()` | Multi-host replay protection (absent) |
| Sealed release controls; production startup validation | Whether the receiver is independent of the sink (unknown) |
| Metrics, structured audit events, health | Identity authentication (absent by design) |
| Single-host replay protection (Enforcer's SQLite) | Process isolation of the delivery path (unknown) |

## Configuring and running production

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for configuration, secrets, monitoring, backup and
recovery, and incident response, and [docs/RELEASE_BOUNDARY.md](docs/RELEASE_BOUNDARY.md) for the
envelope, the checks and the denial codes. The short version:

```python
tower = DeterministicIntegrityTower(
    "ops",
    production=True,   # refuses to start unless these controls are present
    release_gate=EnforcerReleaseGate(configured_enforcer, policy_version="2026-11-3", timeout=5.0),
    release_sink=deliver,
    delivery_confirmer=receiver_has,           # asks the receiving side
    hmac_key=release_signature_key,            # supplied, not per-process random
    ledger=ValLedger(key=ledger_key, store=FileLedgerStore(path), anchor=FileLedgerAnchor(anchor_path)),
)
result = tower.enforce(text, release=ReleaseRequest(
    identity=identity, artifact=CNSDock().to_zts_artifact(identity),
    release_id=unique_per_attempt, scope="tenant-1/ops-report", proof_provider=ask_issuer))
tower.readiness()   # every check: PASS, FAIL, or UNKNOWN with a reason
tower.close()       # drain in-flight releases, then close the ledger
```

`production=True` stops a misconfigured tower from starting. It cannot vouch for a custom verifier,
status source or replay store: those report `UNKNOWN`, and you have to review them yourself.

## Guarantees NOT provided

* That any grant is genuine. That depends on a verifier and trust root that do not exist yet.
* That a revocation is seen between Enforcer's status check and delivery.
* Protection from code in the same process: it can call the delivery callback directly, read keys, or
  edit memory. The control is process or network isolation of the delivery path.
* Replay protection across hosts, or across a restart if you pass an in-memory store.
* Tamper-proof audit. The chain is tamper evident; truncation is detectable only against an anchor
  you place out of the writer's reach.
* That the receiver is independent of the sink, so that a confirmation means something.
* That output is true, safe or correct. The gates are filters, and the README below documents their
  limits.
* That `release_id` is unique across your system. Enforcer enforces uniqueness for ids it has seen.
* Authentication of the caller. Whoever holds a valid grant for a subject can present that subject.
* Any claim about a real deployment. None has been observed.

Existing callers that relied on the tower releasing by default must now choose a legacy mode:
`DeterministicIntegrityTower("ops", capstone=ArchitectsProtocol(ReleaseMode.AUTO))`. That performs
no authorization and cannot be combined with `require_enforcer=True` or `production=True`.

## CLI

```bash
zts scrub "I think this might work."        # print the cleaned payload
zts audit "As an AI, I agree." --json       # every gate decision, machine-readable
zts audit "As an AI, I agree." -p legal     # human-readable gate table
zts gates                                   # the array, in execution order
zts profiles                                # the four enforcement profiles
zts bench                                   # measure fail-fast on this machine
zts scrub --strict "..." || echo "breached" # exit 1 on breach, for CI
```

## The gates

| Gate | Code | Name | Cost | Action |
|------|------|------|------|--------|
| G1 | AB | Axiomatic Base | lexical | detect only |
| G2 | SCF | Semantic Contamination Filter | semantic | detect only |
| G3 | SBF | Syntactic Breach Filter | syntactic | strip |
| G4 | HCA | Historical Context Anchor | semantic | detect only |
| G5 | SND | Sycophancy Neutralization Deck | lexical | strip |
| G6 | PPA | Pronominal Purge Array | syntactic | strip |
| G7 | TAP | The Architect's Protocol | manual | hold or release |

Execution order is `G6 → G3 → G1 → G5 → G2 → G4`, sorted by cost. `G7` is the
capstone. The tower has no default release authority and holds everything until
one is configured. Production uses the Enforcer gate; the legacy `AUTO`,
`HANDSHAKE`, `CALLBACK` and `SEALED` capstones are explicit opt-ins. See
[ARCHITECTURE.md](ARCHITECTURE.md) and [docs/RELEASE_BOUNDARY.md](docs/RELEASE_BOUNDARY.md).

## Profiles

| Profile | Threshold | Enforced | Advisory |
|---------|-----------|----------|----------|
| `default` | 88 | G3 G5 G6 | G1 G2 G4 |
| `ops` | 90 | all | – |
| `exec` | 85 | G3 G5 G6 | G1 G2 G4 |
| `legal` | 97 | all | – |

An advisory gate still records its findings. A profile that declines to block
on something still tells you about it.

## Does the fail-fast ordering actually work

Yes, in one of the two modes, and the benchmark separates them.

```
$ zts bench
ZTS fail-fast benchmark  [mode=reject]

ordering                              mean      median         p95   gates/payload
---------------------------------------------------------------------------------
fail-fast (ascending cost)          20.77u      16.88u      29.46u            3.00
worst case (descending cost)        24.50u      25.69u      37.00u            4.50

latency:    fail-fast +15.2% vs worst case
gate work:  fail-fast +33.3% fewer gate executions per payload
```

In **reject** mode the ordering saves a third of the gate executions. When the
semantic gates are made expensive – standing in for a model call rather than a
regex, which is the case the design was reaching for – the same reorder is
worth about 60%.

In **repair** mode it saves nothing, because every gate runs on every payload
regardless of order. That matters historically: the original stack ran in
repair mode, which means the 214ms → 32ms improvement it credited to this
reorder could not have come from this reorder. See
[PROVENANCE.md](PROVENANCE.md).

Numbers above are from one run on one machine. Run `zts bench` for yours.

## Open items

- **Ledger key: stored in an owner-only file (decided for Linux).** The ledger
  stores a keyed fingerprint of each payload. By default the tower keeps the key
  in `~/.config/zts/ledger.key` (or under `$XDG_CONFIG_HOME`). The file is created
  on first use with mode 600, and it is refused if other users can read it. Pass
  `persist_ledger_key=False` for a random key that lasts only for one run. Still
  open: key IDs on each entry so keys can be rotated.

- **Key IDs for rotation: deferred (decided 2026-10-08).** Nothing rotates the
  ledger key yet, so the key IDs are not built. Build them before the first
  rotation. Until then, rotating the key would make older fingerprints unmatchable.

## Tests

```bash
pytest        # 335 pass, 8 skip without cns or enforcer installed
pytest        # 639 pass with `pip install -e ".[dev,cns,enforcer]"`
```

The skips are whole modules that need the real CNS or the real Enforcer: the CNS connector tests and
the release-boundary suites. CI runs them with `ZTS_REQUIRE_CNS=1` and `ZTS_REQUIRE_ENFORCER=1`,
where a missing package is a failure, not a skip. The test fixtures that stand in for a proof
verifier and a status source (`tests/release_kit.py`) are not production code and prove nothing
about a real issuer or authority. See [docs/RELEASE_BOUNDARY.md](docs/RELEASE_BOUNDARY.md#tests).

## What this is

ZTS was designed across roughly 150 model-assisted sessions between March and
August 2026 and existed only as specification, prose, and fragments of code
pasted between chat windows. This repository is a reconstruction from that
record: the gate array, the ordering, the profiles, the scoring, the ledger and
the capstone, built as working software and measured.

Where the reconstruction departs from the record it says so, and
[PROVENANCE.md](PROVENANCE.md) lists every departure with the reason. Three
claims in the original record did not survive verification and are documented
there rather than reproduced.
