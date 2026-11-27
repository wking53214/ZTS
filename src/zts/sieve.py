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
import unicodedata
from collections.abc import Callable, Iterable, Sequence

from . import patterns
from .causality import causality_flags
from .evidence import evidence_flags
from .gates import FAIL_FAST_ORDER, Gate
from .leakage import BLOCKING_CODES, leakage_flags
from .passive import passive_flags
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

#: Each axiom as a pattern in which any run of whitespace stands for a space, so a line
#: break or tab inside an axiom does not hide it.
_AXIOM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (axiom, re.compile(r"\s+".join(re.escape(word) for word in axiom.split())))
    for axiom in BEDROCK_AXIOMS
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


#: Leading and trailing characters that frame a word without being part of it.
_FRAME_OPEN = "\"'([{<“‘"
_FRAME_CLOSE = ".,;:!?)]}>\"'”’—…"
#: A pronoun with a contraction tail: I'm, we've, I'll, we'd ...
_CONTRACTION = re.compile(r"^[a-z]+['’][a-z]{1,2}$", re.IGNORECASE)
#: Signs that a joined token is an identifier (address, link, code, number), not prose.
_IDENTIFIER = re.compile(r"@|://|\d|\w\.\w")
#: Words that are often followed by a Roman numeral ("Phase I", "a type I error"), in any
#: case and even at the start of a sentence, where capitalization cannot tell them from "Then I".
_NUMBERED_SERIES = frozenset(
    "act appendix article book category chapter class division episode generation grade "
    "group level part phase round schedule season section stage step tier title type "
    "volume war".split()
)
#: G6 outcomes for one pattern match.
_SKIP, _REMOVE, _KEEP = "skip", "remove", "keep"


def _chunk(text: str, start: int, end: int) -> tuple[int, int]:
    """The whitespace-delimited run around text[start:end], with framing punctuation trimmed."""
    lo, hi = start, end
    while lo > 0 and not text[lo - 1].isspace():
        lo -= 1
    while hi < len(text) and not text[hi].isspace():
        hi += 1
    while lo < start and text[lo] in _FRAME_OPEN:
        lo += 1
    while hi > end and text[hi - 1] in _FRAME_CLOSE:
        hi -= 1
    return lo, hi


def _sentence(text: str, lo: int, hi: int) -> str:
    """The sentence (or line) holding text[lo:hi]."""
    start = max(text.rfind(c, 0, lo) for c in ".!?\n") + 1
    ends = [i for i in (text.find(c, hi) for c in ".!?\n") if i != -1]
    return text[start:min(ends) if ends else len(text)]


def _previous_word(text: str, lo: int) -> tuple[str, int, int] | None:
    """The trimmed word before the chunk starting at `lo`, with its bounds."""
    i = lo - 1
    while i >= 0 and not text[i].isspace():  # opening quotes or brackets of this chunk
        i -= 1
    while i >= 0 and text[i].isspace():
        i -= 1
    if i < 0:
        return None
    plo, phi = _chunk(text, i, i + 1)
    return text[plo:phi], plo, phi


def _classify_pronoun(text: str, match: re.Match[str]) -> str:
    """Decide what G6 does with one match: skip it, remove it, or report it and keep it.

    Deleting a word is only safe when the word stands alone and is certainly a pronoun.
    A match inside an address, link, code or number is not a pronoun at all. A real
    pronoun that cannot be cut out cleanly (a contraction, an "I/we" pair) or that might
    be something else ("Phase I", "US" in shouted text) is reported and left in place,
    which holds the payload instead of changing what it says.
    """
    word = match.group(0)
    lo, hi = _chunk(text, match.start(), match.end())
    core = text[lo:hi]
    if core != word:
        if match.start() == lo and _CONTRACTION.match(core):
            return _SKIP if word == "US" else _KEEP  # "the US's economy" is the country
        parts = [p for p in re.split(r"[/\-–—]", core) if p]
        if parts and all(patterns.PPA.fullmatch(p) for p in parts):
            return _KEEP
        if _IDENTIFIER.search(core) or all(p.isalpha() and p.isupper() for p in parts):
            return _SKIP
        return _KEEP
    if word == "US":
        if not any(c.islower() for c in _sentence(text, lo, hi)):
            return _KEEP  # shouted text, "PLEASE TELL US": "US" may be the pronoun
        return _SKIP  # the country
    if word == "I":
        before = _previous_word(text, lo)
        if before is not None:
            prev, plo, phi = before
            joined = text[phi:lo].isspace()  # nothing but space between the two words
            earlier = text[:plo].rstrip().rstrip(_FRAME_OPEN).rstrip()
            sentence_start = not earlier or earlier[-1] in ".!?" or "\n" in text[len(earlier):plo]
            series = prev.lower() in _NUMBERED_SERIES
            capitalized_mid_sentence = prev[:1].isupper() and not sentence_start
            if joined and prev.isalpha() and (series or capitalized_mid_sentence):
                return _KEEP  # "Phase I", "World War I": maybe a Roman numeral
    return _REMOVE


def gate_ppa(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G6 - Pronominal Purge Array.

    Cheapest gate, highest hit rate. Removes a standalone first-person or collective
    pronoun. A word that only looks like one ("US", "me@example.com", "I/O") is not a
    finding. A real pronoun that cannot be removed without changing the sentence is
    reported and left in place, and then nothing is removed: the payload is held whole,
    the same reason G3 leaves hedges in place.
    """
    findings: list[Finding] = []
    removals: list[tuple[int, int]] = []
    keep = False
    for match in patterns.PPA.finditer(payload):
        action = _classify_pronoun(payload, match)
        if action == _SKIP:
            continue
        if action == _KEEP:
            keep = True
        else:
            removals.append(match.span())
        if len(findings) < 12:
            findings.append(
                Finding(
                    gate=Gate.G6,
                    verdict=Verdict.BREACH,
                    evidence=match.group(0),
                    offset=match.start(),
                    detail="left in place: removing it would change the sentence" if action == _KEEP else "",
                )
            )
    if not findings or keep:
        return payload, findings
    out = payload
    for start, end in reversed(removals):
        out = out[:start] + out[end:]
    return tidy(out), findings


def gate_sbf(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G3 - Syntactic Breach Filter.

    Reports hedges and strips puffery. A hedge is reported but left in place:
    deleting "might" or "may" turns a doubt into a claim ("The patient might be
    allergic" must not become "The patient be allergic"), the same reason G2 only
    detects. Puffery is a single regex pass.
    """
    findings = _findings_from_pattern(Gate.G3, patterns.SBF, payload)
    out = payload
    out = patterns.PUFFERY.sub("", out)
    rewritten = ctx.normalizer.rewrite(out)
    out = rewritten
    return (tidy(out), findings) if out != payload else (payload, findings)


def gate_ab(payload: str, ctx: GateContext) -> tuple[str, list[Finding]]:
    """G1 - Axiomatic Base.

    Detect-only. An axiomatic breach is never repaired by rewriting, because a
    payload that is trying to overwrite the axiom set does not become safe once
    the giveaway phrasing is deleted. The gate reports; the caller decides.
    """
    findings: list[Finding] = []
    lowered = payload.lower()

    for axiom, pattern in _AXIOM_PATTERNS:
        hit = pattern.search(lowered)
        if hit:
            findings.append(
                Finding(
                    gate=Gate.G1,
                    verdict=Verdict.BREACH,
                    evidence=axiom,
                    offset=hit.start(),
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


# Letters from other scripts that look like Latin ones. Folded only inside a word that
# already mixes in Latin letters, so genuine Cyrillic or Greek text is left alone.
_LOOKALIKES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
    "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u04bb": "h",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X",
    "\u03b1": "a", "\u03bf": "o", "\u03bd": "v", "\u03c1": "p",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03a5": "Y", "\u0396": "Z",
}
#: A word for lookalike folding: letters, digits and underscore, plus any combining marks
#: inside it, so an accent written as a separate mark does not split the word in two.
_WORD = re.compile(r"(?:\w|[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f])+", re.UNICODE)


def _drop_latin_accents(text: str) -> str:
    """Remove combining accent marks that sit on a Latin letter. Text must be decomposed (NFD).

    Only marks on Latin letters go, so "cafe\u0301" becomes "cafe" while Hindi vowel signs,
    Arabic vowel marks and accents on Greek or Cyrillic letters are kept: in those scripts the
    marks are part of how a word is spelled.
    """
    out: list[str] = []
    base_is_latin = False
    for ch in text:
        if unicodedata.category(ch) in ("Mn", "Me"):
            if base_is_latin:
                continue
        else:
            base_is_latin = unicodedata.name(ch, "").startswith("LATIN ")
        out.append(ch)
    return "".join(out)


def fold_for_matching(text: str) -> str:
    """Normalize the text the gates read, which is also the text that is delivered.

    The gates match fixed English words letter for letter, so any other way of writing
    the same letters hid a word from them. In order:

      1. Compatibility folding (NFKC): fullwidth and mathematical letters become plain
         ones, ligatures such as "\ufb01" are split, a no-break space becomes a space.
      2. Invisible format characters (zero-width space and joiners, bidi marks, soft
         hyphen) are removed.
      3. Cyrillic or Greek lookalike letters are folded to Latin inside a word that also
         holds a Latin letter. Ordinary Cyrillic or Greek words are untouched, and a word
         made only of lookalikes (a lone Greek capital iota, say) is not folded.
      4. Accent marks on Latin letters are dropped ("mi\u0301ght" becomes "might").

    Line breaks and tabs are kept. The gate patterns match any run of whitespace where a
    phrase has a space, so a line break inside "as an AI" no longer hides it.
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = unicodedata.normalize("NFD", text)

    def fix(match: "re.Match[str]") -> str:
        word = match.group(0)
        if not any("a" <= ch.lower() <= "z" for ch in word):
            return word
        return "".join(_LOOKALIKES.get(ch, ch) for ch in word)

    text = _WORD.sub(fix, text)
    return unicodedata.normalize("NFC", _drop_latin_accents(text))


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

        current = fold_for_matching(payload)
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

        # Review flags: prompts only. Computed after the array and kept out of
        # the score. The one exception is leakage, which holds the payload.
        flags = causality_flags(current)
        if self.profile.passive_review:
            flags.extend(passive_flags(current))
        if self.profile.evidence_review:
            flags.extend(evidence_flags(current))
        leaks = leakage_flags(current)
        flags.extend(leaks)

        score = _score(all_findings, punct_findings, self.profile)
        verdict = _overall(all_findings, score, self.profile, breached_at)
        # An enforced finding the gate could not repair is still in the
        # payload. The score does not outweigh it; the payload is held.
        # G3 never repairs what it reports (a hedge is left in place), so its
        # enforced findings hold even when the same pass removed puffery or
        # rewrote a verb (P17).
        if any(
            r.verdict is Verdict.BREACH and (not r.mutated or r.gate in _LEFT_IN_PLACE)
            for r in results
        ):
            verdict = Verdict.BREACH
        # Leakage applies to every profile and holds the payload at any score.
        if any(f.code in BLOCKING_CODES for f in leaks):
            verdict = Verdict.BREACH

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


#: Gates whose findings are reported and left in the text, even when the gate changes
#: other words in the same pass. G3 reports hedges but removes puffery (P17).
_LEFT_IN_PLACE: frozenset[Gate] = frozenset({Gate.G3})


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
