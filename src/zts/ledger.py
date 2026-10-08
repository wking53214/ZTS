"""VAL ledger: the transaction log.

Every gate decision appends an entry. The ledger is what makes a run auditable
after the fact and what G4 reads to detect oscillation.

Entries are chained: each carries the SHA-256 of the previous entry, so a
deleted or edited entry breaks verification. This is a tamper-evidence
mechanism, not a tamper-proof one. Anyone who can write the ledger can rebuild
the whole chain. It detects accidental corruption and casual editing; it does
not defend against an attacker with write access.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

#: Where the ledger key lives on Linux when a caller asks for the default.
DEFAULT_KEY_PATH = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "zts" / "ledger.key"


class LedgerKeyError(RuntimeError):
    """The ledger key file is missing, malformed, or readable by someone else."""


@dataclass
class LedgerEntry:
    """One recorded decision."""

    sequence: int
    timestamp: float
    layer: str
    status: str
    detail: str
    payload_digest: str
    previous: str
    digest: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def compute_digest(self) -> str:
        body = json.dumps(
            {
                "sequence": self.sequence,
                "timestamp": self.timestamp,
                "layer": self.layer,
                "status": self.status,
                "detail": self.detail,
                "payload_digest": self.payload_digest,
                "previous": self.previous,
                "extra": self.extra,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


class ValLedger:
    """Append-only hash-chained transaction log.

    Each entry stores a keyed fingerprint of its payload (HMAC-SHA256), never the
    payload text. Without the key, a fingerprint cannot be matched against guesses
    of a low-entropy value such as a card number. The chain itself is checked
    without the key.
    """

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key or secrets.token_bytes(32)
        self._entries: list[LedgerEntry] = []

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    @property
    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

    @property
    def head(self) -> str:
        return self._entries[-1].digest if self._entries else GENESIS

    def log(
        self,
        layer: str,
        status: str,
        detail: str = "",
        payload: str = "",
        **extra: Any,
    ) -> LedgerEntry:
        entry = LedgerEntry(
            sequence=len(self._entries),
            timestamp=time.time(),
            layer=layer,
            status=status,
            detail=detail,
            payload_digest=self._fingerprint(payload),
            previous=self.head,
            extra=dict(extra),
        )
        entry.digest = entry.compute_digest()
        self._entries.append(entry)
        return entry

    def _fingerprint(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def payload_matches(self, entry: LedgerEntry, payload: str) -> bool:
        """Does `payload` match the fingerprint stored on `entry`? Needs the ledger key."""
        return hmac.compare_digest(entry.payload_digest, self._fingerprint(payload))

    def verify(self) -> tuple[bool, str]:
        """Walk the chain. Returns (ok, reason). Does not need the key."""
        previous = GENESIS
        for entry in self._entries:
            if entry.previous != previous:
                return False, f"entry {entry.sequence}: broken link"
            if entry.digest != entry.compute_digest():
                return False, f"entry {entry.sequence}: digest mismatch"
            previous = entry.digest
        return True, "chain intact"

    def to_jsonl(self) -> str:
        return "\n".join(
            json.dumps(asdict(e), sort_keys=True) for e in self._entries
        )


def load_or_create_ledger_key(path: str | Path = DEFAULT_KEY_PATH) -> bytes:
    """Return the ledger key stored at `path`, creating it on first use.

    The file holds 32 random bytes and must be owned by the current user with
    no permissions for group or others (mode 0600). A key that others can read
    lets them match fingerprints against guessed card numbers, so a file that
    fails this check is refused rather than used.
    """
    path = Path(path)
    try:
        return _read_key(path)
    except FileNotFoundError:
        pass

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = secrets.token_bytes(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process created it between the read and the create. Use theirs.
        return _read_key(path)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
        handle.flush()
        os.fsync(handle.fileno())
    return key


def _read_key(path: Path) -> bytes:
    info = path.stat()
    if info.st_uid != os.getuid():
        raise LedgerKeyError(f"{path} is not owned by the current user")
    if info.st_mode & 0o077:
        raise LedgerKeyError(f"{path} is readable by other users; set its mode to 600")
    key = path.read_bytes()
    if len(key) != 32:
        raise LedgerKeyError(f"{path} does not hold a 32-byte key")
    return key


def checksum(payload: str, key: bytes) -> str:
    """HMAC-SHA384 over a released payload.

    Reproduced from the archived build, which hardcoded the key as a module
    constant. A hardcoded HMAC key authenticates nothing, so the key is a
    required argument here and the tower generates a per-instance random key
    when one is not supplied.
    """
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha384).hexdigest()


__all__ = [
    "ValLedger",
    "LedgerEntry",
    "LedgerKeyError",
    "checksum",
    "load_or_create_ledger_key",
    "DEFAULT_KEY_PATH",
    "GENESIS",
]
