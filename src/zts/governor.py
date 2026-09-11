"""Kinetic Governor: the temporal budget.

What it is, plainly: a rate limiter that computes a per-payload delay from
payload size, then enforces it. Calling it a "mechanical rev-limiter" does not
change what it does, and the archived description of it as a defense against
"API thermal runaway" oversells a sleep call. What it genuinely provides is
predictable pacing in front of a metered API, which is a real operational
concern and the reason it is kept.

The 0.815 constant is preserved because it is part of the stack's identity, but
it is worth being accurate about what it is: a pacing coefficient with no
derivation recorded anywhere in the archive. It is a tuning knob. It is exposed
as a constructor argument so it can be tuned.

One correction against the archived build. That version had:

    self.temporal_budget = 0.815
    async def calculate_budget(self, payload_size):
        await asyncio.sleep(self.temporal_budget)
        return self.temporal_budget

which ignores payload_size entirely and sleeps a flat 815ms on every call. A
"budget computed from payload density" that does not read the payload is not a
budget. This implementation computes the delay from token count, clamps it to a
configured floor and ceiling, and returns the value it actually waited.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

#: The archived pacing coefficient. No derivation is recorded; treat as tunable.
CONSTANT: float = 0.815


@dataclass
class Budget:
    """The computed pacing decision for one payload."""

    seconds: float
    tokens: int
    floor: float
    ceiling: float
    clamped: bool

    @property
    def ms(self) -> float:
        return self.seconds * 1000


class KineticGovernor:
    """Computes and enforces a per-payload temporal budget."""

    def __init__(
        self,
        constant: float = CONSTANT,
        per_token_seconds: float = 0.002,
        floor_seconds: float = 0.0,
        ceiling_seconds: float = 0.200,
    ) -> None:
        if ceiling_seconds < floor_seconds:
            raise ValueError("ceiling_seconds must be >= floor_seconds")
        self.constant = constant
        self.per_token = per_token_seconds
        self.floor = floor_seconds
        self.ceiling = ceiling_seconds

    def calculate(self, payload: str) -> Budget:
        """Compute the budget without waiting. Pure, cheap, testable."""
        tokens = len(payload.split())
        raw = tokens * self.per_token * self.constant
        clamped_value = max(self.floor, min(raw, self.ceiling))
        return Budget(
            seconds=clamped_value,
            tokens=tokens,
            floor=self.floor,
            ceiling=self.ceiling,
            clamped=clamped_value != raw,
        )

    async def apply(self, budget: Budget) -> float:
        """Wait out the budget. Returns the actual elapsed seconds."""
        if budget.seconds <= 0:
            return 0.0
        started = time.perf_counter()
        await asyncio.sleep(budget.seconds)
        return time.perf_counter() - started

    async def pace(self, payload: str) -> Budget:
        """Calculate and enforce in one call."""
        budget = self.calculate(payload)
        await self.apply(budget)
        return budget


__all__ = ["KineticGovernor", "Budget", "CONSTANT"]
