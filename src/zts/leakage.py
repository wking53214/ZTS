"""Leakage check: finds card numbers and credentials in a payload, and holds it.

A payload that carries a live card number or a credential must not be released.
Any hit sets the sieve verdict to BREACH, so the tower withholds the output.
The check never rewrites text. Redacting would hide the problem and could break
the payload, so the payload is held as it is, for a person to deal with.

Design rules:

  - The flag never stores the secret. Evidence is masked: a card shows only its
    last four digits, and a credential shows only its name.
  - Card numbers must pass the Luhn checksum. Random digit runs, phone numbers,
    and order numbers are not flagged.
  - The check reads a folded copy of the text (compatibility forms such as
    fullwidth letters and colons become plain ones, invisible format
    characters are dropped). Offsets still point into the text as given.

What it covers and what it does not is listed in README.md under "The leakage
check". It is a pattern check: a secret in a format it does not know passes.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Final

from .result import Flag

#: Characters accepted between the digits of a card number: a space, a tab, a dot, a
#: slash, a hyphen or any dash (en dash included), or a line break. A no-break space
#: arrives here as a space, because the text is folded first.
_DASHES: Final = r"\-\u2010-\u2015\u2212"
_CARD_SEP: Final = rf"(?:\r?\n|[ \t./{_DASHES}])"

#: Candidate card number: 13 to 19 digits, with at most one separator between digits.
_CARD_CANDIDATE: Final = re.compile(
    rf"(?<![\w{_DASHES}])(?:\d{_CARD_SEP}?){{12,18}}\d(?![\w{_DASHES}])"
)

#: Words that name a credential. The name in an assignment must end with one of them.
_CREDENTIAL_WORD: Final = (
    r"(?:api[_-]?key|secret[_-]?key|access[_-]?key|secret|token|password|passwd|pwd)"
)

#: Assignment of a credential-like name to a value (for example "api_key = ..."). The
#: name may carry a prefix joined by underscores or hyphens ("aws_secret_access_key",
#: "db_password") and may be quoted, as a JSON key is.
_KEY_VALUE: Final = re.compile(
    r"(?<![A-Za-z0-9])(?P<name>(?:[A-Za-z0-9]+[_-])*" + _CREDENTIAL_WORD + r")"
    r"[\"']?\s*[:=]\s*[\"']?(?P<value>[^\s\"',;]{8,})",
    re.IGNORECASE,
)

#: Credential formats with a recognizable prefix or header.
_PREFIXED: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("api_key_sk", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    # Any PEM or PGP private key header: RSA, EC, DSA, OPENSSH, ENCRYPTED, PGP ... BLOCK.
    ("private_key_block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    # An HTTP Authorization header with a known scheme.
    (
        "authorization_header",
        re.compile(
            r"\bauthorization\s*:\s*(?:bearer|basic|digest|token|negotiate|ntlm|apikey|bot|hawk|aws4-hmac-sha256)"
            r"\s+[A-Za-z0-9._~+/-]{8,}=*",
            re.IGNORECASE,
        ),
    ),
    # A bearer token outside a header. Needs 16 or more token characters including a
    # digit or punctuation, so "bearer" in ordinary prose is not flagged.
    (
        "bearer_token",
        re.compile(r"\bbearer\s+(?=[A-Za-z0-9._~+/-]*[0-9._~+/-])[A-Za-z0-9._~+/-]{16,}=*", re.IGNORECASE),
    ),
)

MAX_FLAGS: Final = 10

#: Flag codes that hold a payload. Any other review flag stays advisory.
BLOCKING_CODES: Final = frozenset({"CARD_NUMBER", "CREDENTIAL"})


def luhn_valid(digits: str) -> bool:
    """Return True when a digit string passes the Luhn checksum used by card numbers."""
    total = 0
    for position, char in enumerate(reversed(digits)):
        value = int(char)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_card(digits: str) -> str:
    return "*" * (len(digits) - 4) + digits[-4:]


def _fold(text: str) -> tuple[str, list[int]]:
    """Return a matching copy of `text` and, for each of its characters, the index it came from.

    Each character is folded on its own with NFKC, so fullwidth letters, digits and
    colons, mathematical letters and no-break spaces become their plain forms.
    Invisible format characters are dropped. The text itself is not changed.
    """
    out: list[str] = []
    origin: list[int] = []
    for index, char in enumerate(text):
        if unicodedata.category(char) == "Cf":
            continue
        folded = unicodedata.normalize("NFKC", char)
        out.append(folded)
        origin.extend([index] * len(folded))
    return "".join(out), origin


def leakage_flags(text: str) -> list[Flag]:
    """Return review flags for card numbers and credentials in `text`.

    Capped at MAX_FLAGS so a pathological payload cannot flood the result.
    """
    folded, origin = _fold(text)
    flags: list[Flag] = []
    #: Spans already flagged as a credential, so one secret is reported once.
    taken: list[tuple[int, int]] = []

    def at(position: int) -> int:
        return origin[position] if position < len(origin) else len(text)

    for match in _CARD_CANDIDATE.finditer(folded):
        digits = re.sub(r"\D", "", match.group(0))
        if not 13 <= len(digits) <= 19 or not luhn_valid(digits):
            continue
        flags.append(
            Flag(
                code="CARD_NUMBER",
                evidence=_mask_card(digits),
                offset=at(match.start()),
                detail="card number that passes the checksum; check for real account data",
            )
        )
        if len(flags) >= MAX_FLAGS:
            return flags

    for match in _KEY_VALUE.finditer(folded):
        taken.append(match.span())
        flags.append(
            Flag(
                code="CREDENTIAL",
                evidence=f"{match.group('name')}=****",
                offset=at(match.start()),
                detail="credential-style assignment; check whether this value is live",
            )
        )
        if len(flags) >= MAX_FLAGS:
            return flags

    for label, pattern in _PREFIXED:
        for match in pattern.finditer(folded):
            start, end = match.span()
            if any(start < t_end and t_start < end for t_start, t_end in taken):
                continue
            taken.append((start, end))
            flags.append(
                Flag(
                    code="CREDENTIAL",
                    evidence=f"{label}=****",
                    offset=at(start),
                    detail="credential format match; check whether this value is live",
                )
            )
            if len(flags) >= MAX_FLAGS:
                return flags

    return sorted(flags, key=lambda f: f.offset)


__all__ = ["leakage_flags", "luhn_valid", "MAX_FLAGS"]
