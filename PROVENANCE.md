# Provenance

ZTS was never a repository. It was a design carried across roughly 150
model-assisted sessions between March and August 2026, recorded as
specification prose, architecture diagrams, and fragments of Python pasted
between chat windows. This repository is a reconstruction from that record.

This document says where each part came from, what was changed and why, and
which claims in the record did not survive verification.

## Sources

Reconstructed from five conversation archives. The archives are not part of
this repository, so the entries below give file names only.

| Source | Contributes |
|--------|-------------|
| `original_gemini_export.json[864]`, `[1704]` | The `ZTS_Gate` enum with the fail-fast sequence and its position comments; the four-module assembly; `REGEX_CACHE` |
| Claude transcript `8cdf517a-…md` | The G1-G7 gate map with names and codes; the module diagram; the fail-fast sequence as a formula; the clinical audit that separated the claims from the engineering |
| Claude transcript `b3526879-…md` | The GSA v13.0 unified assembly: `CitadelProcessor`, `KineticGovernor`, `ArchitectCapstone`, thread alpha/beta split, oscillation protection |
| Claude transcript `730af555-…md` | Citadel v1.1 decoupled build: `CitadelDetector` / `CitadelTransformer` / `CitadelScorer`, the `PROFILES` table, penalty weights, the em dash rule |
| Claude transcript `e8e5bb13-…md` | Per-gate filter classes with docstrings; `KineticGovernor` with the 0.815 coefficient; HMAC checksum |
| ChatGPT transcript `6a89fcc9-…md` | The iteration audit: five numbered refactors with deltas, including the fail-fast reorder |
| ChatGPT transcript `6a20e432-…md` | `HyperTestTruthProtocol`, the L1-L7 predecessor with the VAL ledger |
| `evidence_ledger.jsonl` | Dated corroboration: `VSA-02062` (2026-04-14, the nomenclature lock that fixed the ZTS acronym), `VSA-01570` (2026-06-04, module paths and maturity levels), `VSA-01203` (2026-06-18, the v1.1 structural audit) |

### Lineage

The stack was renamed twice. Same architecture throughout.

```
7-Layer Zero-Trust Construct   (Mar 2026)  L1–L7, conceptual
        ↓
Hyper Test Truth Protocol                   L1-L7, first working code, VAL ledger
        ↓
VSA / Vassal-State Architecture             Citadel naming, detector/transformer/scorer
        ↓  2026-04-14 nomenclature lock
GSA v13.0 / Governance-State Architecture   G1–G7, fail-fast reorder, async governor
```

The April 14 lock is when `ZTS` became the fixed designation for the gate array
and `G1`-`G7` replaced `L1`-`L7`. This repository reconstructs the post-lock
GSA v13.0 form, which is the fullest version the record contains.

## Preserved exactly

- Gate identities: seven gates, their codes, names, and canonical numbering.
- The fail-fast principle and its rationale.
- `REGEX_CACHE` patterns for PPA, SBF, SND.
- The `0.815` pacing coefficient, as a default.
- Profile names and thresholds: `default` 88, `ops` 90, `exec` 85, `legal` 97.
- Penalty weights: identity 10, hedging 5, causality 10, punctuation 3.
- The em dash rule: en dash allowed, em dash forbidden.
- Oscillation protection via a seen-payload set.
- The VAL ledger as a per-layer transaction log.
- Thread Alpha / Thread Beta as concurrent sieve and governor.
- The out-of-band handshake as the terminal release condition.

## Changed, with reasons

### Ordering

**G5/SND moved from fail-fast position 5 to position 4.** The archived enum
placed SND after SCF. SND is one regex pass over a phrase alternation, which is
lexical; SCF is semantic. Leaving SND behind SCF violates the ascending-cost
rule the ordering exists to implement. `verify_fail_fast_order()` now asserts
the invariant so this cannot regress silently.

### Gates made detect-only

**G2/SCF no longer substitutes.** The archived filter deleted affect
vocabulary. Removing "believes" from "the operator believes the cluster is
degraded" produces either a fragment or a false assertion of fact. A hedge
about certainty is load-bearing content. The gate reports.

**G1/AB no longer substitutes,** for the same reason inverted: a payload trying
to override the governing instructions does not become safe when the giveaway
phrasing is deleted, it becomes undetectable. G1 also gained a pattern for
override attempts, which the archive enforced in prose but never in code.

### Gates that did nothing

**G4/HCA was a no-op.** The archived L6 read:

```python
def l6_historical_context(self, data):
    # Verification against previous VAL entries (Simplified)
    self._log_transaction("L6", "PASS", "Historical alignment confirmed.")
    return data
```

It logged a pass unconditionally. It is now a real comparison against the
history of the current rewrite loop: verbatim match, and near-match above a
Jaccard similarity floor, which catches a generator changing punctuation to
escape the exact-match check.

**History is scoped to one rewrite loop,** not to the tower's lifetime. A
caller who submits the same text twice is making two requests, not oscillating.

### The governor

**The budget now reads the payload.** The archived version:

```python
async def calculate_budget(self, payload_size: int) -> float:
    await asyncio.sleep(self.temporal_budget)   # flat 0.815s
    return self.temporal_budget
```

takes `payload_size` and ignores it, then sleeps a flat 815ms. A budget
"computed from payload density" that does not read the payload is not a budget.
It now computes from token count, clamps to a floor and ceiling, and separates
`calculate()` from `apply()` so the calculation is testable without waiting for
it.

### Security

**The capstone had a published password.** The archived release check was
`if signature == "ADMIN_OVERRIDE"`, a literal in source control. A capstone any
reader of the file can satisfy is not a capstone. Release now compares against
a caller-supplied authority using `hmac.compare_digest`, with no default: the
constructor raises rather than fall back to a known value.

**The HMAC key was hardcoded** as a fixed string in the original source (not
reproduced here). A published key authenticates nothing. The key is now a required argument, and the tower generates a random
per-instance key when one is not supplied.

**The ledger is described accurately.** It is tamper-evident, not
tamper-proof. Anyone with write access can rebuild the chain.

### Efficiency

**The rewrite loop no longer accumulates.** The archived loop appended each
attempt's constraints to the previous prompt, so attempt N carried N sets of
rules and cost more than attempt N-1 for no gain. Each retry now carries only
the constraints the last attempt actually violated.

**The sieve is synchronous.** The archived sieve was `async` and awaited
nothing inside itself, which bought a coroutine frame per call and no
concurrency. Regex work is CPU-bound. The tower runs the sieve in a thread when
it needs it concurrent with the governor.

**The governor runs concurrently with the sieve** rather than before it. Both
forms appear in the record; the concurrent one is correct, because the pacing
delay and the regex work are independent.

### Output quality

**Substitution artifacts are cleaned.** Gates delete tokens in place, which
leaves double spaces and spaces before punctuation. The archived output looked
broken on every non-trivial payload.

**The normalizer preserves capitalization.** "Utilize the API" now becomes "Use
the API" rather than "use the API".

### Dropped

- `CitadelDiamond.process_onslaught`, which rejected any payload containing the
  substrings "paradox" or "recursion". Both are legitimate subjects. The check
  rejects a correct incident report about a recursive query plan.
- `"1.0000 Parity"`, `"150%+ Entropy"`, `"Council of Skeptics"`,
  `"ANATHEMA_STATE"`, `"Structural_Zero"`, `KeystoneNode`, G7 master keys, and
  vassal terminology. These name no behavior. The parity metric survives as a
  score because it had a real definition; the rest did not.

## Claims not reproduced

The archive contains its own audit, which separated what was built from what
was said about it. These are the claims that audit flagged and this
reconstruction could not verify.

### "Latency dropped from 214ms to 32ms"

Recorded as the result of the fail-fast reorder. It was produced by a model
narrating a simulation, not by a profiler. The archive's own audit identifies
it as synthetic.

The reconstruction establishes something stronger than "unverified." The
archived stack ran in repair mode: gates substituted violations away and
execution continued to the next gate. Every gate runs on every payload in that
mode. Reordering a sequence whose every element executes cannot change its
cost, so the reorder could not have produced that improvement in that build,
whatever the real numbers were.

The optimization is sound and this repository implements it. It pays in reject
mode, where a finding terminates the array. Measured on the benchmark corpus:
33% fewer gate executions, 15% lower mean latency, and about 60% when the
semantic gates are made expensive enough to stand in for a model call. Run
`zts bench`.

### "Incinerated 94% of linguistic drift instantaneously"

No measurement is recorded, and "linguistic drift" is never given a definition
that could be measured against.

### "1.0000 Parity, verified by the 7x70 Hyper Test Truth Protocol"

Described as 490 micro-simulations establishing mathematical parity. The
archive's audit states plainly that the parity figure and the Hyper Test Truth
Protocol grind were "internal semantic concepts... metaphorical constraints
modeled by the AI to enforce rigid tone restrictions, not external mathematical
tests run on functional code." No test harness corresponding to them exists in
the record.

The score survives in this implementation because it has a real definition:
100 minus penalties. It is a score, not a proof.

### "22% of computational input noise incinerated at ingestion"

Attributed to the Logic Cornerstone. Unmeasured, and "computational input
noise" is undefined.

### "42% higher efficiency via concurrent execution"

From the four-module assembly docstring. Unmeasured. Concurrency between the
governor and the sieve is real and is tested here; the figure is not.

### "Hardware-bound", "BIOS", "Production-Staged (Compliance Ready)"

The Logic Cornerstone was described as a hardware-bound anchor and the module
as compliance-ready for the EU AI Act. It is a Python function that strips
control characters. A specification is not an implementation, and an
implementation is not a compliance certification.

## What the record got right

Worth stating, because the corrections above are longer than the credits.

- **Cost-ordered short-circuit evaluation on a filter chain.** Standard
  practice in query planners and packet filters, correctly applied here, and
  measurably right in the mode where it applies.
- **Deterministic filters over prompt instructions.** A regex that removes
  hedges is not a request the model can decline. This is the load-bearing
  insight and it holds.
- **Decoupling pacing from validation.** Independent work should not be
  serialized.
- **Detection and transformation as separate stages.** The v1.1 split into
  detector, transformer, and scorer is the right decomposition and is preserved
  structurally.
- **Profiles over a single threshold.** Different consumers tolerate different
  violations, and recording an advisory finding you decline to block on is
  better than not looking.
- **A terminal human gate.** G7 is the most defensible thing in the design.
- **Oscillation detection.** A generator that repeats itself is not converging,
  and spending more attempts on it is waste.
