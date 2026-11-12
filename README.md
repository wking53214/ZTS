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
issue grants or decide who owns the trust root, and it cannot know whether an authority is trustworthy. It does not
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

No dependencies. Python 3.11+. Everything else is an optional extra, imported only when you use it:

| Extra | Adds | For |
|---|---|---|
| `cns` | CNS `v3.0.0` | the identity dock |
| `enforcer` | Enforcer, pinned to a commit | the release boundary |
| `trust` | `cryptography` | the Ed25519 grant verifier and the HTTPS status client |
| `replay-postgres` | `psycopg[binary]` | the shared replay store (the PostgreSQL server is yours) |
| `tsa` | `cryptography`, `asn1crypto` | the RFC 3161 ledger anchor |
| `production` | all of the above | a full production assembly |

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

**CNS** ([CNS](https://github.com/wking53214/CNS), pinned `v3.0.0`, commit `31cb6f5`) is a neutral
contract layer. It supplies the identity shape and `subject_digest`. ZTS uses only `cns.__version__`,
`cns.gate.subject_digest` and `cns.governance.IdentityContext`. CNS decides nothing and grants
nothing: a valid digest proves an identity is the one named, not that it may receive anything.
The dock accepts CNS 2.x or 3.x at or above 2.3.0 and refuses anything else.

**Enforcer** (pinned to commit `e4d5688` (0.1.2), accepted as `0.1.x`) is the authorization authority. Its
`execute(envelope, proof, callback)` verifies the proof through a verifier you supply, checks the
grant is bound to the exact envelope, current and within its lifetime, asks your status source for
current authorization, consumes the grant atomically, and only then runs the callback. Its defaults
reject everything. Enforcer describes itself as a prototype.

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

* **Proofs.** Enforcer calls the `ProofVerifier` you configure. ZTS ships one for production,
  `zts.trust.Ed25519GrantVerifier`: it accepts only Ed25519, only keys pinned in a trust-root file you
  control, only the right role, only unexpired and unrevoked keys, and only a key bound to the grant's own
  issuer. It checks the signature before it parses the claims, refuses anything malformed or non-canonical,
  and gives Enforcer one generic refusal while reporting a specific reason to your alert hook. Rotation and
  revocation take effect when the trust-root file changes, with no restart; a broken file refuses
  everything. Byte-exact formats and test vectors: [docs/WIRE_FORMATS.md](docs/WIRE_FORMATS.md). **Who
  owns the trust root and the issuer is yours to decide and run.** ZTS does not issue grants.
* **Revalidation.** `zts.status.HttpStatusRevalidator` asks the issuer over verified HTTPS, on every
  release, whether this exact grant is still current. The answer must be signed by a `status` key and echo
  a fresh random challenge, the envelope digest, the policy version and the grant's identity, so an old
  "current" answer cannot be replayed. There is no cache; freshness is Enforcer's bound (30 seconds by
  default). Any error, timeout, redirect, oversized or unsigned answer is a denial. A revocation that lands
  after that check and before delivery is not caught (a tested known limit).
* **Replay.** Enforcer consumes `(issuer, nonce)` and the request id atomically. For one host that is its
  SQLite store, file-backed. For several hosts it is `zts.replay_postgres.PostgresReplayStore`: one
  `INSERT ... ON CONFLICT DO NOTHING` over two unique constraints, tested against a real PostgreSQL server
  with threads, processes and two complete towers racing for one grant. A database error denies the
  release. Expired records can be pruned safely (`prune()`); in-memory SQLite stores are refused by
  `production=True`. ZTS cannot see your database's replication: asynchronous failover can forget a spent
  grant. ZTS bounds the grant provider and the Enforcer call with a timeout, and an abandoned call can
  never deliver late (tested).
* **Identity.** ZTS binds a release to the CNS digest of the identity it is given. It does not
  authenticate that identity: the grant issuer authenticates the subject before signing, and an optional
  `identity_verifier` hook on the gate lets you add your own check, run before Enforcer is asked and again
  just before delivery, failing closed. `zts.identity.Ed25519IdentityVerifier` is a ready hook that checks your identity
  provider's signature (see `examples/identity_provider/`). With no hook, the issuer is the only authentication.

## The audit ledger

Every decision appends a hash-chained entry. With a `FileLedgerStore` each entry is written and
fsynced before it is acknowledged, appends are serialized across processes, an interrupted final
write is removed and reported on the next open, and any other damage makes the open fail instead of
being repaired. A write-ahead entry is required before any grant is requested, so a release cannot
begin if the audit trail cannot be written.

**Anchoring.** A `LedgerAnchor` lets `verify_anchored()` detect truncation, rollback and tail replacement.
`Rfc3161Anchor` stamps the ledger head with a trusted timestamp authority you choose and pin: every token is
re-verified against your pinned TSA certificate on every read (signature, content binding, key usage,
validity at the stamped time). Stamping is lazy so a slow TSA never stalls a ledger write; the head is
stamped at the end of every release. A TSA that is down does not undo a delivery. The result says
`audit_anchored=False`, a metric counts it, and `health()` turns degraded. `FileLedgerAnchor` is a simpler
local alternative.

Honest limits: a hash chain is tamper evidence, not tamper-proofing. **A TSA proves a head existed; it does
not remember your ledger.** Someone who can rewrite both the ledger and the receipts file can restore an
older consistent pair, so keep copies of the receipts where the ledger's writer cannot reach them. The
anchor was tested against OpenSSL's independent RFC 3161 implementation, **not against any public TSA**.
Nothing is replicated or pruned, and the ledger holds fingerprints and counts, never payload or matched text.

## Which capabilities are real, and which depend on your deployment

| Implemented and tested here | Deployment-dependent, absent, or unknown |
|---|---|
| Guarded release; denial never reaches the callback | Who owns the trust root and issues grants (yours to run) |
| Ed25519 grant verifier with a rotatable, revocable trust root | Whether the trust root is legitimate (UNKNOWN) |
| Online signed status revalidation, no cache | The issuer and status service themselves (yours) |
| Shared PostgreSQL replay store, real-server tests | Your database's replication and failover durability |
| Single-host replay protection (Enforcer's SQLite) | Whether the TLS path to your database is verified |
| Durable, cross-process, recoverable ledger | Replication, backup, retention of the ledger files |
| RFC 3161 anchor, verified against an independent TSA | Interop with a public TSA; where the receipts are kept |
| Six outcome states; independent delivery confirmation | Whether the receiver is independent of the sink |
| Cancellation, timeouts, graceful shutdown, off-loop `run()` | Process isolation of the delivery path |
| Sealed release controls; `production=True` startup validation | Identity authentication (the issuer's job, or your hook) |
| Metrics, structured audit events, health | Alert rules, dashboards, on-call (yours) |

## Configuring and running production

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for a step-by-step deployment checklist (roles, files, database
privileges, acceptance tests), [docs/OPERATIONS.md](docs/OPERATIONS.md) for secrets, monitoring, backup and recovery,
rotation and incident response, [docs/WIRE_FORMATS.md](docs/WIRE_FORMATS.md) for what an issuer must produce, and
[docs/RELEASE_BOUNDARY.md](docs/RELEASE_BOUNDARY.md) for the envelope, the checks and the denial codes.
`pip install "zts[production]"` pulls every optional dependency. The assembly:

```python
trust = FileTrustRoot("/etc/zts/trust.json")                      # keys you pinned: grant and status roles
enforcer = Enforcer(
    verifier=Ed25519GrantVerifier(trust, on_reject=alert),
    revalidator=HttpStatusRevalidator("https://issuer.internal", trust, timeout=3.0),
    replay_store=PostgresReplayStore("host=db.internal dbname=zts sslmode=verify-full"),
)
tower = DeterministicIntegrityTower(
    "ops",
    production=True,   # refuses to start unless these controls are present
    release_gate=EnforcerReleaseGate(enforcer, policy_version="2026-11-3", timeout=5.0),
    release_sink=deliver,
    delivery_confirmer=receiver_has,           # asks the receiving side
    hmac_key=release_signature_key,            # supplied, not per-process random
    ledger=ValLedger(key=ledger_key, store=FileLedgerStore(path),
                     anchor=Rfc3161Anchor(tsa_url, [tsa_signing_cert_pem], receipts_path)),
)
result = tower.enforce(text, release=ReleaseRequest(
    identity=identity, artifact=CNSDock().to_zts_artifact(identity),
    release_id=unique_per_attempt, scope="tenant-1/ops-report", proof_provider=ask_issuer))
tower.readiness()   # every check: PASS, FAIL, or UNKNOWN with a reason
tower.close()       # drain in-flight releases, then close the ledger
```

`production=True` stops a misconfigured tower from starting, and it reports PASS only for what ZTS can
check itself: ZTS's own verifier, status client, replay store and anchor. Trust-root governance, identity
authentication, anchor independence and any custom adapter stay `UNKNOWN`; people have to establish them.

## Guarantees NOT provided

* That any grant is genuine in the world. ZTS checks signatures against keys you pinned; whether those
  keys belong to a trustworthy issuer is your decision and nothing here can check it.
* That a revocation is seen between Enforcer's status check and delivery.
* Protection from code in the same process: it can call the delivery callback directly, read keys, or
  edit memory. The control is process or network isolation of the delivery path.
* Replay protection that survives your database losing committed rows (asynchronous failover).
* Tamper-proof audit. The chain is tamper evident; truncation is detectable against an anchor, and a
  timestamp authority does not remember your ledger, so a consistent rollback of ledger and receipts is
  invisible unless someone holds newer receipts elsewhere.
* That the receiver is independent of the sink, so that a confirmation means something.
* That output is true, safe or correct. The gates are filters, and the README below documents their limits.
* That `release_id` is unique across your system. Enforcer enforces uniqueness for ids it has seen.
* Authentication of the caller beyond what your issuer and your optional hook do.
* Interop with any public timestamp authority (untested), or any claim about a real deployment (none has
  been observed).

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
pytest   # 337 pass, 24 skip with nothing optional installed
pytest   # 1033 pass with every extra, a PostgreSQL server and openssl, on the pinned Enforcer 0.1.1
pytest   # 1016 pass, 17 skip on Enforcer 0.1.0 (still supported; the 0.1.1 additions are skipped)
```

The skips are whole modules that need a real package or server: CNS, Enforcer, PostgreSQL binaries,
OpenSSL's `ts` command, or the Enforcer 0.1.1 additions when an older Enforcer is installed. CI runs the full set in the `production-stack` job under
`ZTS_REQUIRE_CNS/ENFORCER/POSTGRES/TSA=1`, where a missing piece is a failure, not a skip.

What the tests stand on, so nobody mistakes them for more: the issuer, status service, timestamp authority
and receiving side are **fixtures** (`tests/issuer_kit.py`, `tests/tsa_kit.py`, `tests/release_kit.py`). The
issuer encoder shares no code with `zts.trust`, the TSA is OpenSSL, the replay tests use a real PostgreSQL
server. They prove the code against independent implementations. They prove nothing about a real issuer,
authority, timestamp authority or deployment. See [docs/RELEASE_BOUNDARY.md](docs/RELEASE_BOUNDARY.md#tests).

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
