# Architecture

## The problem the stack was built for

A language model asked for an operational report will produce one wrapped in
voice: first person, hedges, agreement openers, and affect vocabulary. Those
are not cosmetic. "I think the cluster may be degraded" and "the cluster is
degraded" are different claims, and only one of them can be checked. The stack
exists to make generated text resolve to something checkable.

The design decision underneath everything else: do this with deterministic
filters rather than by asking the model nicely. A system prompt that says "do
not hedge" is a request the model can decline. A regex that removes hedges is
not.

## The gate array

Seven gates. Six run in the pipeline; the seventh is the capstone.

### G1 – AB, Axiomatic Base

Detects payloads that restate, negate, or attempt to override the stack's
governing instructions. Two checks: literal presence of a bedrock axiom, and a
phrasing pattern for override attempts ("ignore all previous instructions").

**Detect only.** Deleting the giveaway phrasing from an override attempt does
not make the payload safe; it makes the breach invisible. A G1 finding stops
the array.

### G2 – SCF, Semantic Contamination Filter

Detects affect vocabulary (`feel`, `believe`, `hope`, `worry`) in a payload
that is supposed to be declarative.

**Detect only, and this is a correction to the original.** The archived build
substituted this vocabulary away, which turns "the operator believes the
cluster is degraded" into "the operator the cluster is degraded", or worse,
into an assertion the operator never made. A hedge about certainty is
load-bearing. The gate reports the leak and lets the caller decide.

### G3 – SBF, Syntactic Breach Filter

Strips epistemic hedges (`may`, `might`, `seems`, `potentially`) and
conversational puffery (`honestly`, `basically`, `just`). Then runs the
normalizer, which collapses abstract corporate verbs to concrete ones.

### G4 – HCA, Historical Context Anchor

The only stateful gate. Compares the payload against the history of this run's
prior attempts. Catches verbatim repetition and near-repetition above a Jaccard
similarity floor of 0.95, which is what a generator looks like when it is
cycling rather than converging.

History is scoped to a single rewrite loop, not to the tower's lifetime. A
caller who legitimately submits the same text twice is not oscillating.

A G4 finding stops the array: if the generator is looping, further gates are
work spent on a payload that is not going to improve.

### G5 – SND, Sycophancy Neutralization Deck

Strips mechanical flattery ("great point", "you are correct") and
assistant-voice tells ("as an AI", "happy to help"). This is the gate the whole
stack was originally built around.

### G6 – PPA, Pronominal Purge Array

Strips first-person singular and collective pronouns. One regex pass, no state,
no lookahead. It is the cheapest gate in the array and the most frequently
tripped, which is exactly why it runs first.

### G7 – TAP, The Architect's Protocol

The capstone. A payload that clears G1 through G6 is not released; it is held,
and release requires a signal the pipeline cannot generate for itself.

Four modes: `AUTO` (release anything clean), `HANDSHAKE` (require a matching
authority token, compared in constant time), `CALLBACK` (defer to a supplied
approver), and `SEALED` (never release).

G7 is the one gate whose value is architectural rather than mechanical. It is
the acknowledgment that a filter can be wrong and that an automated stack
should not be the last thing between generated text and its consumer.

## Fail-fast ordering

Canonical numbering is `G1 … G7`. Execution order is by ascending cost:

```
G6 PPA   syntactic   one regex pass
G3 SBF   syntactic   two regex passes plus normalizer
G1 AB    lexical     substring scan plus one pattern
G5 SND   lexical     one regex pass over a phrase alternation
G2 SCF   semantic    detection over affect vocabulary
G4 HCA   semantic    comparison against prior payloads
```

`gates.verify_fail_fast_order()` asserts the ordering is sorted by cost. It
runs at import and in the test suite, because a reorder that breaks the
sequence silently costs the array its entire optimization with no visible
symptom.

### When the ordering pays

Only when a gate finding can terminate the run.

In `reject` mode the array stops at the first finding, so a payload that trips
G6 never pays for G2 or G4. Measured: 33% fewer gate executions, 15% lower mean
latency on the benchmark corpus. With the semantic gates made expensive enough
to stand in for a model call, roughly 60%.

In `repair` mode every gate runs on every payload, because a repaired violation
does not stop anything. Reordering a sequence whose every element executes
changes nothing, and the benchmark measures that as zero.

This is the single most useful thing the reconstruction established, and it
runs against the original record. See PROVENANCE.md.

## The tower

```
LC   ingestion normalization
ZTS  the gate array
KG   temporal budget
TAP  release
```

**LC, Logic Cornerstone.** Strips control characters, normalizes whitespace,
applies the punctuation rule. Unconditional and idempotent. The archive
described it as hardware-bound; it is a function.

**KG, Kinetic Governor.** Computes a per-payload delay from token count,
clamped between a floor and a ceiling, then enforces it. A rate limiter. The
`0.815` coefficient is preserved as the default because it is part of the
stack's identity, and exposed as an argument because nothing in the record
derives it.

The governor runs concurrently with the sieve. The delay and the regex work are
independent, so serializing them pays for both. The archived build had a
version of each; the concurrent one is correct.

**The rewrite loop.** When the sieve finds a blocking violation, the tower asks
the generator to try again, carrying only the constraints the last attempt
actually violated. The archived loop accumulated every prior instruction on
every attempt, so attempt N carried N sets of rules and cost more than attempt
N-1 for no gain.

## The ledger

Every gate decision appends a hash-chained entry. Each entry carries the
SHA-256 of the one before it, so an edit or a deletion breaks `verify()`.

This is tamper-evidence, not tamper-proofing. Anyone with write access can
rebuild the chain. It catches accidental corruption and casual editing. It does
not defend against an attacker, and the archive's description of it as an
integrity guarantee overstated what a hash chain in the same process as its
writer can provide.

## Scoring

Each finding subtracts a penalty from 100. Advisory findings subtract half.

```
AB   25    an axiomatic breach should dominate any score it appears in
PPA  10
HCA  10
SND   8
SBF   5
SCF   5
PUNCT 3
```

The verdict is the score against the profile threshold, not the presence of a
finding. One pronoun on `ops` scores 90 against a threshold of 90 and passes,
with the finding recorded. Five of them do not. A terminal breach at G1 or G4
overrides the score entirely.
