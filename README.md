# ZTS – Zero Trust Stack

A deterministic filtration array for language model output. Seven gates,
`G1` through `G7`, run in ascending cost order so that a cheap syntactic check
rejects a payload before an expensive semantic one has to look at it.

It removes first-person voice, hedging, flattery, and affect vocabulary from
generated text; it detects attempts to overwrite its own governing
instructions; and it holds the result unreleased until something outside the
pipeline authorizes it.

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
                              │
              ┌───────────────┴───────────────┐
              ▼ Thread Alpha                  ▼ Thread Beta
      ┌───────────────┐               ┌───────────────────┐
      │ gate array    │               │ KG  Kinetic       │
      │ (CPU-bound)   │               │ Governor: pacing  │
      └───────┬───────┘               └─────────┬─────────┘
              └───────────────┬─────────────────┘
                              ▼
         ┌─────────────────────────────────────────┐
         │ TAP  The Architect's Protocol   G7       │  out-of-band release
         └────────────────────┬────────────────────┘
                              ▼
                   [ RELEASED OR HELD ]
```

## Install

```bash
pip install -e .
```

No dependencies. Python 3.11+.

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

Wrap a generator and let it retry against the specific constraints it violated:

```python
import asyncio
from zts import DeterministicIntegrityTower

tower = DeterministicIntegrityTower("ops")
result = asyncio.run(tower.run("Summarize last night's incident.", my_llm_call))
result.output       # released text, or '' if held
result.attempts     # rewrite rounds consumed
tower.ledger.verify()  # (True, 'chain intact')
```

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

Execution order is `G6 → G3 → G1 → G5 → G2 → G4`, sorted by cost. `G7` never
runs automatically; it is the capstone and requires a signal from outside the
pipeline. See [ARCHITECTURE.md](ARCHITECTURE.md).

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

## Tests

```bash
pytest        # 98 tests
```

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
