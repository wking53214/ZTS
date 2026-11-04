"""Durable storage for the VAL ledger, and a file-backed anchor.

What this is. A local, append-only, one-entry-per-line file that survives a
restart, plus a second file that records the latest head. Each append is written
and fsynced before it returns, so a write that returned is on the disk the
operating system reports. Appends are serialized across processes with a POSIX
``flock``, so several processes can share one chain.

What this is not, so nothing downstream claims more:

  * Not tamper-proof. Whoever can write the file can rewrite it. The hash chain
    detects edits and the anchor detects truncation, and the anchor only helps if
    the writer cannot also rewrite the anchor (a different account, a different
    volume, or a different machine). ZTS cannot see where a path is mounted, so
    whether an anchor is independent is a deployment fact, not a property of this
    class.
  * Not replicated. One file on one volume. Backup is the operator's.
  * ``flock`` is advisory and unreliable on some network filesystems. Do not
    share a ledger file across hosts over NFS and treat that as coordination.
  * POSIX only. Where ``fcntl`` is missing the classes refuse to open rather
    than run without the lock.

Recovery. A crash during an append can leave a final line without its newline.
That entry was never acknowledged, so opening the store removes it (after
copying the fragment to ``<path>.torn`` for inspection) and reports it. Anything
else wrong with the file, a line that does not parse, a broken link, a digest
mismatch, is corruption or tampering. The store refuses to open and does not
repair it.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .ledger import GENESIS, LedgerEntry

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - exercised only off POSIX
    fcntl = None  # type: ignore[assignment]


class LedgerStoreError(RuntimeError):
    """The store could not complete a read or write. Callers must treat it as a failed write."""


class LedgerCorruptionError(LedgerStoreError):
    """The file does not hold a valid chain. Not repaired: tampering and damage look alike."""


@dataclass(frozen=True)
class RecoveryReport:
    """What opening the store found."""

    entries: int
    #: Bytes of an unacknowledged final line that were removed. 0 means a clean file.
    torn_tail_bytes: int = 0
    #: Where the removed fragment was copied, if any.
    torn_copy: str = ""


def _require_posix() -> None:
    if fcntl is None:
        raise LedgerStoreError("the durable ledger needs POSIX file locking and is unavailable here")


def _check_file(path: Path) -> None:
    """Owner-only and not writable by others, the same rule the ledger key file follows."""
    info = path.stat()
    if info.st_uid != os.getuid():
        raise LedgerStoreError(f"{path} is not owned by the current user")
    if info.st_mode & 0o022:
        raise LedgerStoreError(f"{path} is writable by other users; set its mode to 600")


def _open(path: Path) -> int:
    _require_posix()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existed = path.exists()
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    if not existed:
        _fsync_dir(path.parent)
    try:
        _check_file(path)
    except LedgerStoreError:
        os.close(fd)
        raise
    return fd


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise LedgerStoreError("short write")
        view = view[written:]


class _Locked:
    """Holds an exclusive flock on a descriptor for the duration of a with block."""

    def __init__(self, fd: int) -> None:
        self._fd = fd

    def __enter__(self) -> "_Locked":
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc: object) -> None:
        fcntl.flock(self._fd, fcntl.LOCK_UN)


def _read_from(fd: int, offset: int) -> bytes:
    chunks = []
    position = offset
    while True:
        chunk = os.pread(fd, 1 << 20, position)
        if not chunk:
            break
        chunks.append(chunk)
        position += len(chunk)
    return b"".join(chunks)


def entry_from_line(line: bytes) -> LedgerEntry:
    try:
        raw = json.loads(line)
        return LedgerEntry(**raw)
    except (ValueError, TypeError) as exc:
        raise LedgerCorruptionError("a ledger line does not parse as an entry") from exc


class FileLedgerStore:
    """Append-only JSONL ledger file. ``durable`` is True: each append is fsynced."""

    durable = True

    def __init__(self, path: str | Path, *, repair_torn_tail: bool = True) -> None:
        self.path = Path(path)
        self._fd = _open(self.path)
        self._offset = 0
        self._repair = repair_torn_tail
        self.recovery = RecoveryReport(entries=0)

    # -- opening ---------------------------------------------------------------

    def load(self) -> list[LedgerEntry]:
        """Read and verify the whole chain, repairing only an unacknowledged torn tail."""
        with self.exclusive():
            data = _read_from(self._fd, 0)
            torn = 0
            torn_copy = ""
            if data and not data.endswith(b"\n"):
                cut = data.rfind(b"\n") + 1
                fragment = data[cut:]
                if not self._repair:
                    raise LedgerCorruptionError("the file ends in an unfinished line and repair is off")
                torn = len(fragment)
                torn_copy = str(self.path) + ".torn"
                with open(torn_copy, "ab") as handle:
                    handle.write(fragment + b"\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.ftruncate(self._fd, cut)
                os.fsync(self._fd)
                data = data[:cut]
            entries: list[LedgerEntry] = []
            previous = GENESIS
            for number, line in enumerate(data.splitlines()):
                entry = entry_from_line(line)
                _check_link(entry, previous, number)
                entries.append(entry)
                previous = entry.digest
            self._offset = len(data)
            self.recovery = RecoveryReport(entries=len(entries), torn_tail_bytes=torn, torn_copy=torn_copy)
            return entries

    # -- writing and catching up -------------------------------------------------

    def exclusive(self) -> _Locked:
        """Serialize against every other process using this file."""
        return _Locked(self._fd)

    def read_new(self, previous: str, next_sequence: int) -> list[LedgerEntry]:
        """Entries another writer appended since this store last looked. Call inside exclusive().

        Raises LedgerCorruptionError if the file is now shorter than what this store has
        already seen: someone removed acknowledged entries while we were running, and
        appending onto what is left would turn truncation into a corrupt chain.
        """
        if os.fstat(self._fd).st_size < self._offset:
            raise LedgerCorruptionError("the file is shorter than what was already written: truncated")
        data = _read_from(self._fd, self._offset)
        if not data:
            return []
        if not data.endswith(b"\n"):
            raise LedgerCorruptionError("another writer left an unfinished line")
        entries = []
        for line in data.splitlines():
            entry = entry_from_line(line)
            _check_link(entry, previous, next_sequence)
            entries.append(entry)
            previous, next_sequence = entry.digest, next_sequence + 1
        self._offset += len(data)
        return entries

    def append(self, entry: LedgerEntry) -> None:
        """Write one entry and fsync. Call inside exclusive(). Raises LedgerStoreError on any failure."""
        line = (json.dumps(asdict(entry), sort_keys=True) + "\n").encode("utf-8")
        try:
            _write_all(self._fd, line)
            os.fsync(self._fd)
        except OSError as exc:
            raise LedgerStoreError("the ledger entry could not be written durably") from exc
        self._offset += len(line)

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1


def _check_link(entry: LedgerEntry, previous: str, expected_sequence: int) -> None:
    if entry.sequence != expected_sequence:
        raise LedgerCorruptionError(f"entry {expected_sequence}: sequence is {entry.sequence}")
    if entry.previous != previous:
        raise LedgerCorruptionError(f"entry {expected_sequence}: broken link")
    if entry.digest != entry.compute_digest():
        raise LedgerCorruptionError(f"entry {expected_sequence}: digest mismatch")


class FileLedgerAnchor:
    """Records the latest ``(sequence, head)`` in its own file, fsynced.

    Whether this anchors anything depends on where the file lives. On the same
    volume and account as the ledger it adds a second copy to rewrite, not
    independence. Mount it where the ledger's writer has append-only access
    (a WORM volume, another account, another host) to get the property.
    """

    durable = True

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fd = _open(self.path)

    def publish(self, sequence: int, head: str) -> None:
        line = (json.dumps({"head": head, "sequence": sequence}, sort_keys=True) + "\n").encode("utf-8")
        with _Locked(self._fd):
            try:
                _write_all(self._fd, line)
                os.fsync(self._fd)
            except OSError as exc:
                raise LedgerStoreError("the anchor could not be written durably") from exc

    def latest(self) -> tuple[int, str] | None:
        """The last complete line. An unfinished final line was never acknowledged and is ignored."""
        with _Locked(self._fd):
            data = _read_from(self._fd, 0)
        if data and not data.endswith(b"\n"):
            data = data[: data.rfind(b"\n") + 1]
        last: tuple[int, str] | None = None
        for line in data.splitlines():
            try:
                raw: dict[str, Any] = json.loads(line)
                sequence, head = raw["sequence"], raw["head"]
            except (ValueError, KeyError, TypeError) as exc:
                raise LedgerCorruptionError("the anchor file holds a line that does not parse") from exc
            if not isinstance(sequence, int) or not isinstance(head, str):
                raise LedgerCorruptionError("the anchor file holds a malformed record")
            last = (sequence, head)
        return last

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1


def _stat_mode(path: Path) -> str:  # for diagnostics in tests and health checks
    return stat.filemode(path.stat().st_mode)


@contextlib.contextmanager
def opened(path: str | Path) -> Iterator[FileLedgerStore]:
    store = FileLedgerStore(path)
    try:
        yield store
    finally:
        store.close()


__all__ = [
    "FileLedgerAnchor",
    "FileLedgerStore",
    "LedgerCorruptionError",
    "LedgerStoreError",
    "RecoveryReport",
    "entry_from_line",
    "opened",
]
