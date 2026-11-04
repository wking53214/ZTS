"""VAL ledger: the transaction log.

Every gate decision appends an entry. The ledger is what makes a run auditable
after the fact and what G4 reads to detect oscillation.

Entries are chained: each carries the SHA-256 of the previous entry, so a
deleted or edited entry breaks verification. This is a tamper-evidence
mechanism, not a tamper-proof one. Anyone who can write the ledger can rebuild
the whole chain. It detects accidental corruption and casual editing; it does
not defend against an attacker with write access.

Two properties were added for the release boundary, and their limits are stated
here so nothing downstream claims more:

  * Writes are serialized by a lock, so concurrent callers in one process cannot
    fork the chain (two entries with one sequence number or one predecessor).
    The lock is per ledger object and per process. It says nothing about two
    processes writing one store, and this ledger has no store.
  * An optional :class:`LedgerAnchor` receives the new head before each entry is
    appended. A ledger whose anchor lives outside the writer's control can tell
    a truncated or replaced chain from the real one (:meth:`ValLedger.verify_anchored`).
    ZTS ships the interface and, in zts.ledger_store, a file-backed anchor. Whoever
    can also write the anchor can rewrite both.
  * With a ``store`` (zts.ledger_store.FileLedgerStore) the chain is persisted:
    every entry is written and fsynced before log() returns, and an entry that
    could not be persisted raises instead of being acknowledged. Without one the
    ledger is in memory and is lost when the process ends. ``durable`` says which.
"""

from __future__ import annotations

import hashlib
import hmac
import contextlib
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

GENESIS = "0" * 64

def default_key_path() -> Path:
    """Where the ledger key lives by default: ~/.config/zts/ledger.key (or $XDG_CONFIG_HOME)."""
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "zts" / "ledger.key"


class LedgerAnchorError(RuntimeError):
    """The external anchor refused or lost a head, so the entry was not appended."""


@runtime_checkable
class LedgerAnchor(Protocol):
    """Somewhere outside the ledger's writer that retains the latest head.

    ``publish`` must durably record ``(sequence, head)`` or raise. ``latest``
    returns the most recent pair it holds, or None if it holds nothing. The
    protocol provides no security by itself: an anchor the writer can rewrite
    anchors nothing. Production needs one the writer cannot (an append-only
    service, a separate trust domain). None is bundled.
    """

    def publish(self, sequence: int, head: str) -> None: ...

    def latest(self) -> tuple[int, str] | None: ...


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
    #: ID of the key that made payload_digest. Empty only on entries written
    #: before key IDs were recorded; those still verify, as the chain is unchanged.
    key_id: str = ""

    def compute_digest(self) -> str:
        fields: dict[str, Any] = {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "layer": self.layer,
            "status": self.status,
            "detail": self.detail,
            "payload_digest": self.payload_digest,
            "previous": self.previous,
            "extra": self.extra,
        }
        # Included only when set, so entries written before key IDs still verify.
        if self.key_id:
            fields["key_id"] = self.key_id
        body = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode("utf-8")).hexdigest()


class ValLedger:
    """Append-only hash-chained transaction log.

    Each entry stores a keyed fingerprint of its payload (HMAC-SHA256), never the
    payload text. Without the key, a fingerprint cannot be matched against guesses
    of a low-entropy value such as a card number. The chain itself is checked
    without the key.
    """

    def __init__(
        self,
        key: bytes | None = None,
        key_id: str | None = None,
        anchor: LedgerAnchor | None = None,
        store: Any = None,
    ) -> None:
        self._key = key or secrets.token_bytes(32)
        self.key_id = key_id or key_id_for(self._key)
        self._entries: list[LedgerEntry] = []
        self._anchor = anchor
        self._store = store
        self._lock = threading.RLock()
        #: What opening the store found (torn tail removed, entry count). None without a store.
        self.recovery = None
        if store is not None:
            self._entries = store.load()
            self.recovery = store.recovery

    @property
    def durable(self) -> bool:
        """True only when every acknowledged entry has been fsynced to a store."""
        return bool(getattr(self._store, "durable", False))

    @property
    def anchored(self) -> bool:
        return self._anchor is not None

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    @property
    def entries(self) -> list[LedgerEntry]:
        with self._lock:
            return list(self._entries)

    @property
    def head(self) -> str:
        with self._lock:
            return self._entries[-1].digest if self._entries else GENESIS

    def log(
        self,
        layer: str,
        status: str,
        detail: str = "",
        payload: str = "",
        **extra: Any,
    ) -> LedgerEntry:
        with self._lock, self._exclusive():
            if self._store is not None:
                # Another process may have appended since we last wrote.
                self._entries.extend(self._store.read_new(self.head, len(self._entries)))
            entry = LedgerEntry(
                sequence=len(self._entries),
                timestamp=time.time(),
                layer=layer,
                status=status,
                detail=detail,
                payload_digest=self._fingerprint(payload),
                previous=self.head,
                extra=dict(extra),
                key_id=self.key_id,
            )
            entry.digest = entry.compute_digest()
            if self._anchor is not None:
                # Publish first. If the anchor fails, nothing is appended, so
                # the ledger never holds an entry the anchor has not seen.
                try:
                    self._anchor.publish(entry.sequence, entry.digest)
                except Exception as exc:
                    raise LedgerAnchorError("the ledger anchor did not accept the head") from exc
            if self._store is not None:
                # Persist before acknowledging. If this raises the entry is not in
                # memory, and the anchor may be exactly one head ahead of the file.
                self._store.append(entry)
            self._entries.append(entry)
            return entry

    def _exclusive(self) -> Any:
        return self._store.exclusive() if self._store is not None else contextlib.nullcontext()

    def _fingerprint(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def payload_matches(self, entry: LedgerEntry, payload: str) -> bool:
        """Does `payload` match the fingerprint stored on `entry`? Needs the ledger key."""
        return hmac.compare_digest(entry.payload_digest, self._fingerprint(payload))

    def verify(self, expected_head: str | None = None) -> tuple[bool, str]:
        """Walk the chain. Returns (ok, reason). Does not need the key.

        A walk alone cannot see entries removed from the tail. Pass the head
        digest recorded earlier as `expected_head` and the walk also fails
        when the chain no longer ends there.
        """
        previous = GENESIS
        for entry in self.entries:
            if entry.previous != previous:
                return False, f"entry {entry.sequence}: broken link"
            if entry.digest != entry.compute_digest():
                return False, f"entry {entry.sequence}: digest mismatch"
            previous = entry.digest
        if expected_head is not None and previous != expected_head:
            return False, "head mismatch: chain truncated or replaced"
        return True, "chain intact"

    def verify_anchored(self) -> tuple[bool, str]:
        """Walk the chain, then compare it with the head the anchor retained.

        Fails when there is no anchor, when the anchor holds nothing for a
        non-empty ledger, or when the chain no longer contains the anchored
        entry at the anchored position. That catches truncation and
        replacement for as long as the anchor itself is out of the writer's
        reach. It does not catch entries appended after the last publish by a
        writer that skips the anchor, and it proves nothing about an anchor
        the attacker controls.
        """
        if self._anchor is None:
            return False, "no anchor configured"
        ok, reason = self.verify()
        if not ok:
            return False, reason
        try:
            latest = self._anchor.latest()
        except Exception:
            return False, "anchor unavailable"
        with self._lock:
            if self._store is not None:
                with self._exclusive():
                    self._entries.extend(self._store.read_new(self.head, len(self._entries)))
            entries = list(self._entries)
        if latest is None:
            return (False, "anchor holds no head") if entries else (True, "empty ledger, empty anchor")
        sequence, head = latest
        if isinstance(sequence, int) and sequence == len(entries):
            return False, "anchor is one entry ahead of the chain: truncated, or a write was interrupted"
        if not isinstance(sequence, int) or sequence < 0 or sequence >= len(entries):
            return False, "chain is shorter than the anchored head: truncated"
        if entries[sequence].digest != head:
            return False, "anchored head not found at its position: chain replaced"
        return True, "chain intact and contains the anchored head"

    def to_jsonl(self) -> str:
        return "\n".join(
            json.dumps(asdict(e), sort_keys=True) for e in self.entries
        )


def load_or_create_ledger_key(path: str | Path | None = None) -> bytes:
    """Return the ledger key stored at `path` (default: default_key_path()), creating it on first use.

    The file holds 32 random bytes and must be owned by the current user with
    no permissions for group or others (mode 0600). A key that others can read
    lets them match fingerprints against guessed card numbers, so a file that
    fails this check is refused rather than used.
    """
    path = Path(path) if path is not None else default_key_path()
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


#: The algorithm name stored beside every release signature.
SIGNATURE_ALGORITHM = "hmac-sha256"


def key_id_for(key: bytes) -> str:
    """A public identifier for a key: a short hash of it, never the key itself.

    Verifiers use it to pick the right key. It is derived, so the same key
    always gets the same ID, and it reveals nothing useful about the key.
    """
    return "key-" + hashlib.sha256(b"zts-key-id|" + key).hexdigest()[:12]


def checksum(payload: str, key: bytes) -> str:
    """HMAC-SHA256 over a released payload.

    Reproduced from the archived build, which hardcoded the key as a module
    constant. A hardcoded HMAC key authenticates nothing, so the key is a
    required argument here and the tower generates a per-instance random key
    when one is not supplied.
    """
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_legacy_checksum(payload: str, key: bytes, value: str) -> bool:
    """LEGACY, VERIFY-ONLY. Checks a checksum made before the move to HMAC-SHA256.

    Releases made before key IDs were recorded carry an HMAC-SHA384 checksum
    under the same key. This re-checks them so existing payloads still verify.
    It never produces a checksum; new releases use :func:`signature_block`.
    """
    expected = hmac.new(key, payload.encode("utf-8"), hashlib.sha384).hexdigest()
    return isinstance(value, str) and hmac.compare_digest(expected, value)


def signature_block(payload: str, key: bytes, key_id: str | None = None) -> dict[str, str]:
    """The release signature as it is stored: algorithm, key ID and value together."""
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id or key_id_for(key),
        "value": checksum(payload, key),
    }


__all__ = [
    "ValLedger",
    "LedgerEntry",
    "LedgerAnchor",
    "LedgerAnchorError",
    "LedgerKeyError",
    "checksum",
    "verify_legacy_checksum",
    "load_or_create_ledger_key",
    "default_key_path",
    "GENESIS",
]
