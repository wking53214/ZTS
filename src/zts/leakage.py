"""Leakage check: finds card numbers and credentials in a payload, and holds it.

A payload that carries a live card number or a credential must not be released.
Any hit sets the sieve verdict to BREACH, so the tower withholds the output.
The check never rewrites text. Redacting would hide the problem and could break
the payload, so the payload is held as it is, for a person to deal with.

Design rules:

  - The hit never stores the secret. Evidence is masked: a card shows only its
    last four digits, and a credential shows only its name.

  - The flag never stores the secret. Evidence is masked: a card shows only its
    last four digits, and a credential shows only its name.
  - Card numbers must pass the Luhn checksum. Random digit runs, phone numbers,
    and order numbers are not flagged.
"""

from __future__ import annotations

import re
from typing import Final

from .result import Flag

#: Candidate card number: 13 to 19 digits, optionally separated by spaces or dashes.
_CARD_CANDIDATE: Final = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")

#: Assignment of a credential-like name to a value (for example "api_key = ...").
_KEY_VALUE: Final = re.compile(
    r"\b(?P<name>api[_-]?key|secret[_-]?key|access[_-]?key|secret|token|password|passwd|pwd)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"',;]{8,})",
    re.IGNORECASE,
)

#: Credential formats with a recognizable prefix or header.
_PREFIXED: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("api_key_sk", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
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


def leakage_flags(text: str) -> list[Flag]:
    """Return review flags for card numbers and credentials in `text`.

    Capped at MAX_FLAGS so a pathological payload cannot flood the result.
    """
    flags: list[Flag] = []

    for match in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group(0))
        if not 13 <= len(digits) <= 19 or not luhn_valid(digits):
            continue
        flags.append(
            Flag(
                code="CARD_NUMBER",
                evidence=_mask_card(digits),
                offset=match.start(),
                detail="card number that passes the checksum; check for real account data",
            )
        )
        if len(flags) >= MAX_FLAGS:
            return flags

    for match in _KEY_VALUE.finditer(text):
        flags.append(
            Flag(
                code="CREDENTIAL",
                evidence=f"{match.group('name')}=****",
                offset=match.start(),
                detail="credential-style assignment; check whether this value is live",
            )
        )
        if len(flags) >= MAX_FLAGS:
            return flags

    for label, pattern in _PREFIXED:
        for match in pattern.finditer(text):
            flags.append(
                Flag(
                    code="CREDENTIAL",
                    evidence=f"{label}=****",
                    offset=match.start(),
                    detail="credential format match; check whether this value is live",
                )
            )
            if len(flags) >= MAX_FLAGS:
                return flags

    return sorted(flags, key=lambda f: f.offset)


__all__ = ["leakage_flags", "luhn_valid", "MAX_FLAGS"]
