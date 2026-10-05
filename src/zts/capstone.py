"""G7: The Architect's Protocol.

The capstone is the one gate the pipeline cannot satisfy on its own. A payload
that clears G1 through G6 is not released; it is held, and release requires an
out-of-band signal from a human.

Why this is the interesting gate. Everything below it is a filter, and a filter
can be wrong. G7 is the acknowledgment that an automated stack should not be
the last thing standing between a generated payload and its consumer. Whether
that trade is worth making depends entirely on what the payload is for, which
is why the default is AUTO and the strict modes are opt-in.

The earlier private version released whenever the presented signature equalled
a literal string written into the source, which is a hardcoded password in
source control, and a capstone that any reader of the file can satisfy is not a
capstone. This implementation compares against a caller-supplied authority
using a constant-time comparison, and has no default value to fall back to.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum


class ReleaseMode(Enum):
    """How the capstone decides."""

    #: Release anything that cleared the array. No human in the loop.
    AUTO = "auto"
    #: Hold unless a matching authority token is presented.
    HANDSHAKE = "handshake"
    #: Hold unless a supplied callback approves. For interactive review.
    CALLBACK = "callback"
    #: Never release. Useful for dry runs and for testing the held path.
    SEALED = "sealed"


@dataclass
class ReleaseDecision:
    released: bool
    mode: ReleaseMode
    reason: str


class ArchitectsProtocol:
    """The G7 capstone."""

    def __init__(
        self,
        mode: ReleaseMode | str = ReleaseMode.AUTO,
        authority: str | None = None,
        approver: Callable[[str], bool] | None = None,
    ) -> None:
        self.mode = ReleaseMode(mode) if isinstance(mode, str) else mode
        self._authority = authority
        self._approver = approver

        if self.mode is ReleaseMode.HANDSHAKE and not authority:
            raise ValueError(
                "HANDSHAKE mode requires an `authority` token. There is no "
                "default; a capstone with a known default is not a capstone."
            )
        if self.mode is ReleaseMode.CALLBACK and approver is None:
            raise ValueError("CALLBACK mode requires an `approver` callable")

    def authorize(
        self, payload: str, signature: str | None = None
    ) -> ReleaseDecision:
        """Decide whether `payload` may be released."""
        if self.mode is ReleaseMode.AUTO:
            return ReleaseDecision(True, self.mode, "auto-release: no handshake configured")

        if self.mode is ReleaseMode.SEALED:
            return ReleaseDecision(False, self.mode, "sealed: release is disabled")

        if self.mode is ReleaseMode.CALLBACK:
            assert self._approver is not None
            ok = bool(self._approver(payload))
            return ReleaseDecision(
                ok, self.mode, "approver granted" if ok else "approver declined"
            )

        # HANDSHAKE
        if signature is None:
            return ReleaseDecision(False, self.mode, "impedance state: no signature presented")
        assert self._authority is not None
        if hmac.compare_digest(signature, self._authority):
            return ReleaseDecision(True, self.mode, "handshake verified")
        return ReleaseDecision(False, self.mode, "impedance state: signature rejected")

    @staticmethod
    def generate_authority(nbytes: int = 32) -> str:
        """Mint a handshake token."""
        return secrets.token_urlsafe(nbytes)


__all__ = ["ArchitectsProtocol", "ReleaseMode", "ReleaseDecision"]
