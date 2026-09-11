"""Structure normalizer.

Collapses abstract corporate verbs to concrete equivalents and cleans up the
whitespace and orphaned punctuation left behind by gate substitutions.

The substitution table is profile-aware. The archived build carried a full MAP
for `ops`/`default` and a reduced LIGHT_MAP for the profiles where heavier
rewriting distorted meaning more than it gained clarity. Both are preserved.

One behavior is deliberate and worth calling out: substitution runs on word
boundaries with case preserved for the first character, so "Utilize the API"
becomes "Use the API" rather than "use the API". The archived version dropped
capitalization, which produced malformed sentences at the head of a payload.
"""

from __future__ import annotations

import re

from . import patterns

#: Full table. Used by `default` and `ops`.
MAP: dict[str, str] = {
    "methodology": "approach",
    "suboptimal": "inefficient",
    "utilize": "use",
    "utilizes": "uses",
    "utilizing": "using",
    "leverage": "apply",
    "leverages": "applies",
    "leveraging": "applying",
    "functionality": "features",
    "prioritize": "rank",
    "facilitate": "help",
    "facilitates": "helps",
}

#: Reduced table. Used by `exec` and `legal`, where rewriting is riskier.
LIGHT_MAP: dict[str, str] = {
    "utilize": "use",
    "utilizes": "uses",
    "utilizing": "using",
    "leverage": "use",
    "leverages": "uses",
}

_FULL_TABLE_PROFILES = frozenset({"default", "ops"})


def _match_case(source: str, replacement: str) -> str:
    """Carry the source token's capitalization onto the replacement."""
    if source.isupper():
        return replacement.upper()
    if source[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


class StructureNormalizer:
    """Profile-aware lexical normalizer."""

    def __init__(self, profile: str = "default") -> None:
        self.profile = profile
        self._map = MAP if profile in _FULL_TABLE_PROFILES else LIGHT_MAP
        self._pattern = re.compile(
            r"\b(" + "|".join(re.escape(k) for k in self._map) + r")\b",
            re.IGNORECASE,
        )

    def rewrite(self, text: str) -> str:
        """Apply the substitution table, then tidy."""
        text = self._pattern.sub(
            lambda m: _match_case(m.group(0), self._map[m.group(0).lower()]),
            text,
        )
        return tidy(text)


def tidy(text: str) -> str:
    """Clean up artifacts left by regex substitution.

    Gate transforms delete tokens in place, which reliably leaves double
    spaces, spaces before punctuation, and leading/trailing whitespace. Without
    this pass the output of a clean run looks like a bug.
    """
    text = patterns.ORPHAN_PUNCT.sub(r"\1", text)
    text = patterns.WHITESPACE.sub(" ", text)
    text = re.sub(r"([,;:])\1+", r"\1", text)
    text = re.sub(r"^[\s,;:]+", "", text)
    return text.strip()


def normalize_punctuation(text: str) -> str:
    """Em dash to en dash. The archive's punctuation rule, verbatim."""
    return patterns.EMDASH.sub("–", text)


__all__ = ["StructureNormalizer", "MAP", "LIGHT_MAP", "tidy", "normalize_punctuation"]
