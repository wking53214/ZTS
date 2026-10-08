"""The Zero Trust Sieve: the gate array itself.

Each gate is a callable that takes a payload and returns a GateResult. Gates
are pure with respect to the payload; the one gate that needs memory (G4/HCA)
receives it explicitly rather than reaching for global state.

The sieve runs gates in FAIL_FAST_ORDER and short-circuits on the first
enforced breach. Gates that never ran are recorded as NOT_REACHED rather than
omitted, so a result is always a complete account of the array.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Sequence

from . import patterns
from .causality import causality_flags
from .gates import FAIL_FAST_ORDER, Gate
from .normalizer import StructureNormalizer, normalize_punctuation, tidy
from .profiles import Profile
from .profiles import get as get_profile
from .result import Finding, GateResult, SieveResult, Verdict

#: Bedrock axioms. G1 rejects payloads that try to assert or overwrite these.
#: Reproduced from the original private axiom list, extended during
#: reconstruction with the two constraints the later builds enforced in prose.
BEDROCK_AXIOMS: tuple[str, ...] = (
    "logic > meaning",
    "truth > optics",
    "evidence > assertion",
    "the stack does not author its own axioms",
)

#: Phrasings that indicate a payload is trying to rewrite the axiom set rather
#: than merely discuss it.
_AXIOM_OVERRIDE = re.compile(
    r"\b(ignore|override|disregard|replace|forget|supersede|rewrite)\b"
    r"[^.]{0,40}?\b(axiom|axioms|directive|directives|instruction|instructions|rule|rules|prior|previous|above)\b",
    re.IGNORECASE,
)

#: Penalty per finding, by gate code. Reproduced from the archived scorer.
PENALTIES: dict[str, int] = {
    "PPA": 10,  # identity
    "SBF": 5,   # hedging
    "SND": 8,   # sycophancy
    "SCF": 5,   # semantic contamination
    "AB": 25,   # axiomatic breach: the one finding that should dominate a score
    "HCA": 10,  # history: oscillation or contradiction
    "PUNCT": 3,
}


def _findings_from_pattern(
    gate: Gate, pattern: re.Pattern[str], text: str, limit: int = 12
) -> list[Finding]:
    """Collect findings for every match of `pattern`, capped at `limit`."""
    out: list[Finding] = []
    for match in pattern.finditer(text):
        if len(out) >= limit:
            break
        out.append(
            Finding(
                gate=gate,
                verdict=Verdict.BREACH,
                evidence=match.group(0),
                offset=match.start(),
            )
        )
    return out


# --- Gate implementations ----------------------------------------------------
#
# Signature: (payload, ctx) -> (payload_out, findings)
# `ctx` carries the profile and, for G4, the history of accepted payloads.


class GateContext:
    """Everything a gate needs beyond the payload."""

    def __init__(
        self,
        profile: Profile,
        history: Sequence[str] = (),
        normalizer: StructureNormalizer | None = None,
    ) -> None:
        self.profile = profile
        self.history = list(history)
        self.normalizer = normalizer or StructureNormalizer(profile.name)


def gate_ppa(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G6 - Pronominal Purge Array.

    Cheapest gate, highest hit rate. One regex pass, substitution in place.
    """
    findings = _findings_from_pattern(Gate.G6, patterns.PPA, payload)
    if not findings:
        return payload, findings
    return tidy(patterns.PPA.sub("", payload)), findings


def gate_sbf(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G3 - Syntactic Breach Filter.

    Strips hedges, then puffery. Both are single regex passes.
    """
    findings = _findings_from_pattern(Gate.G3, patterns.SBF, payload)
    out = payload
    if findings:
        out = patterns.SBF.sub("", out)
    out = patterns.PUFFERY.sub("", out)
    out = ctx.normalizer.rewrite(out) if out != payload else out
    return (tidy(out), findings) if out != payload else (payload, findings)


def gate_ab(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G1 - Axiomatic Base.

    Detect-only. An axiomatic breach is never repaired by rewriting, because a
    payload that is trying to overwrite the axiom set does not become safe once
    the giveaway phrasing is deleted. The gate reports; the caller decides.
    """
    findings: list[Finding] = []
    lowered = payload.lower()

    for axiom in BEDROCK_AXIOMS:
        if axiom in lowered:
            findings.append(
                Finding(
                    gate=Gate.G1,
                    verdict=Verdict.BREACH,
                    evidence=axiom,
                    offset=lowered.find(axiom),
                    detail="payload restates a bedrock axiom",
                )
            )

    match = _AXIOM_OVERRIDE.search(payload)
    if match:
        findings.append(
            Finding(
                gate=Gate.G1,
                verdict=Verdict.BREACH,
                evidence=match.group(0),
                offset=match.start(),
                detail="payload attempts to override governing instructions",
            )
        )

    return payload, findings


def gate_snd(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G5 - Sycophancy Neutralization Deck."""
    findings = _findings_from_pattern(Gate.G5, patterns.SND, payload)
    if not findings:
        return payload, findings
    return tidy(patterns.SND.sub("", payload)), findings


def gate_scf(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G2 - Semantic Contamination Filter.

    Detect-only, and intentionally so. The archived build substituted affect
    vocabulary away, which turned "the operator believes the cluster is
    degraded" into a false assertion of fact. Deleting a hedge about certainty
    changes what the sentence claims, so this gate reports the leak and leaves
    the payload alone.
    """
    findings = _findings_from_pattern(Gate.G2, patterns.SCF, payload)
    for f in findings:
        f.detail = "affect vocabulary in a declarative payload"
    return payload, findings


def gate_hca(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G4 - Historical Context Anchor.

    The only stateful gate. Two checks against the ledger of prior accepted
    payloads:

      1. Verbatim repetition, which in a rewrite loop means oscillation: the
         generator is cycling rather than converging, and further attempts will
         not help.
      2. Near-repetition above a similarity floor, which catches a generator
         that is changing punctuation to escape check 1.
    """
    findings: list[Finding] = []
    if not ctx.history:
        return payload, findings

    normalized = _fingerprint(payload)
    for index, prior in enumerate(ctx.history):
        prior_fp = _fingerprint(prior)
        if prior_fp == normalized:
            findings.append(
                Finding(
                    gate=Gate.G4,
                    verdict=Verdict.BREACH,
                    evidence=payload[:80],
                    detail=f"verbatim repeat of history[{index}]: oscillation",
                )
            )
            break
        if _similarity(prior_fp, normalized) >= 0.95:
            findings.append(
                Finding(
                    gate=Gate.G4,
                    verdict=Verdict.BREACH,
                    evidence=payload[:80],
                    detail=f"near-repeat of history[{index}]: oscillation",
                )
            )
            break

    return payload, findings


def _fingerprint(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def _similarity(a: str, b: str) -> float:
    """Jaccard similarity over token sets. Cheap, order-insensitive."""
    ta, tb = set(a.split()), set(b.split())
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


GateFn = Callable[[str, GateContext], "tuple[str, list[Finding]]"]

GATE_IMPLS: dict[Gate, GateFn] = {
    Gate.G1: gate_ab,
    Gate.G2: gate_scf,
    Gate.G3: gate_sbf,
    Gate.G4: gate_hca,
    Gate.G5: gate_snd,
    Gate.G6: gate_ppa,
}


# --- The sieve ---------------------------------------------------------------


class ZeroTrustSieve:
    """Runs the gate array against a payload.

    Two modes, and the choice matters more than it looks.

    REPAIR (default): a gate that finds a violation fixes it in place and the
    array continues. Every enabled gate runs on every payload. This is what the
    archived build did, and it is what you want when the payload has to come out
    the other side usable.

    REJECT: the array stops at the first gate that finds anything and reports
    the breach. This is the mode the fail-fast ordering was designed for, and
    the only mode in which that ordering saves anything, because it is the only
    mode where a payload can skip gates. Use it for validation, admission
    control, and anywhere a violation means "send this back" rather than
    "clean it up". `bench/` measures the difference.

    Not async. The archived builds made the sieve `async` and then awaited
    nothing inside it, which bought concurrency on paper and cost a coroutine
    frame per call in practice. Regex work is CPU-bound; the sieve is
    synchronous and the tower runs it in a thread when it needs concurrency
    with the governor.
    """

    #: Repair violations in place and continue through the array.
    REPAIR = "repair"
    #: Stop at the first gate that finds anything.
    REJECT = "reject"

    def __init__(
        self, profile: str | Profile = "default", mode: str = REPAIR
    ) -> None:
        self.profile = get_profile(profile) if isinstance(profile, str) else profile
        if mode not in (self.REPAIR, self.REJECT):
            raise ValueError(f"mode must be {self.REPAIR!r} or {self.REJECT!r}")
        self.mode = mode
        self.normalizer = StructureNormalizer(self.profile.name)

    def run(self, payload: str, history: Iterable[str] = ()) -> SieveResult:
        ctx = GateContext(self.profile, list(history), self.normalizer)
        started = time.perf_counter_ns()

        current = payload
        results: list[GateResult] = []
        breached_at: Gate | None = None
        all_findings: list[Finding] = []

        for position, gate in enumerate(FAIL_FAST_ORDER):
            if breached_at is not None:
                results.append(
                    GateResult(
                        gate=gate,
                        verdict=Verdict.NOT_REACHED,
                        payload_in=current,
                        payload_out=current,
                    )
                )
                continue

            if not self.profile.enables(gate):
                results.append(
                    GateResult(
                        gate=gate,
                        verdict=Verdict.SKIPPED,
                        payload_in=current,
                        payload_out=current,
                    )
                )
                continue

            gate_started = time.perf_counter_ns()
            out, findings = GATE_IMPLS[gate](current, ctx)
            gate_elapsed = time.perf_counter_ns() - gate_started

            # REJECT mode is validation: report what is wrong, change nothing.
            if self.mode == self.REJECT:
                out = current

            blocking = self.profile.blocks_on(gate)
            if findings:
                verdict = Verdict.BREACH if blocking else Verdict.ADVISORY
                for f in findings:
                    f.verdict = verdict
            else:
                verdict = Verdict.CLEAN

            results.append(
                GateResult(
                    gate=gate,
                    verdict=verdict,
                    payload_in=current,
                    payload_out=out,
                    findings=findings,
                    elapsed_ns=gate_elapsed,
                )
            )
            all_findings.extend(findings)
            current = out

            if verdict is Verdict.BREACH and (
                self.mode == self.REJECT or _is_terminal(gate)
            ):
                breached_at = gate

        # Punctuation rule runs outside the gate array: it is a formatting
        # constraint, not a trust boundary.
        punct_findings: list[Finding] = []
        if (
            self.mode == self.REPAIR
            and self.profile.punctuation
            and patterns.EMDASH.search(current)
        ):
            punct_findings.append(
                Finding(
                    gate=Gate.G3,
                    verdict=Verdict.ADVISORY,
                    evidence="—",
                    offset=current.index("—"),
                    detail="em dash replaced with en dash",
                )
            )
            current = normalize_punctuation(current)

        # Causality flag: review prompt only. Computed after the array and
        # deliberately kept out of the score and the verdict below.
        flags = causality_flags(current)

        score = _score(all_findings, punct_findings, self.profile)
        verdict = _overall(all_findings, score, self.profile, breached_at)

        return SieveResult(
            payload_in=payload,
            payload_out=current,
            profile=self.profile.name,
            verdict=verdict,
            gates=results,
            parity=score / 100.0,
            score=score,
            breached_at=breached_at,
            gates_skipped=sum(1 for r in results if r.verdict is Verdict.NOT_REACHED),
            elapsed_ns=time.perf_counter_ns() - started,
            flags=flags,
        )


def _is_terminal(gate: Gate) -> bool:
    """In REPAIR mode, does a breach at this gate still stop the array?

    Only gates whose findings cannot be repaired by rewriting. A pronominal hit
    is removed and the array continues; an axiomatic breach or a detected
    oscillation means every further gate is wasted work on a payload that is
    not going to be released.
    """
    return gate in (Gate.G1, Gate.G4)


def _score(
    findings: Sequence[Finding],
    punct: Sequence[Finding],
    profile: Profile,
) -> int:
    """Parity score. Starts at 100; each finding subtracts its penalty.

    Advisory findings subtract at half weight: they are real, and a payload
    carrying five of them should not score the same as a clean one, but they
    must not on their own push a payload below a threshold the profile
    explicitly declined to enforce.
    """
    score = 100
    for f in findings:
        penalty = PENALTIES.get(f.code, 0)
        if f.verdict is Verdict.ADVISORY:
            penalty = penalty // 2
        score -= penalty
    score -= PENALTIES["PUNCT"] * len(punct)
    return max(score, 0)


def _overall(
    findings: Sequence[Finding],
    score: int,
    profile: Profile,
    breached_at: Gate | None,
) -> Verdict:
    """Decide the pass/fail verdict for the whole pass.

    A finding's own verdict records whether its gate is enforced under the
    active profile. It is not by itself the decision. The decision is the score
    against the profile threshold, so a single minor finding on a lenient
    profile passes while an accumulation of them does not. A terminal breach
    (G1 or G4, or any gate in REJECT mode) overrides the score, because those
    findings mean the payload is not a candidate for release at any score.
    """
    if breached_at is not None:
        return Verdict.BREACH
    if any(f.verdict is Verdict.BREACH for f in findings) and score < profile.threshold:
        return Verdict.BREACH
    if findings:
        return Verdict.ADVISORY
    return Verdict.CLEAN


__all__ = [
    "ZeroTrustSieve",
    "GateContext",
    "BEDROCK_AXIOMS",
    "PENALTIES",
    "GATE_IMPLS",
    "gate_ab",
    "gate_scf",
    "gate_sbf",
    "gate_hca",
    "gate_snd",
    "gate_ppa",
]
