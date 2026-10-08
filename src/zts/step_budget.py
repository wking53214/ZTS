"""Step budget: a hard cap on how many steps one chain of reasoning may take.

The Kinetic Governor paces payloads by time. This module bounds work by count.
A chain that cannot finish inside its budget stops with an error. It never runs on.
"""

from __future__ import annotations

from dataclasses import dataclass


class StepBudgetExhausted(Exception):
    """Raised when spending a step would pass the budget."""


@dataclass
class StepBudget:
    """Counts steps against a fixed limit."""

    max_steps: int = 512
    steps_used: int = 0

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be at least 1")

    def spend(self, n: int = 1) -> None:
        """Consume budget. Raises StepBudgetExhausted once the limit is passed."""
        if n < 1:
            raise ValueError("n must be at least 1")
        self.steps_used += n
        if self.steps_used > self.max_steps:
            raise StepBudgetExhausted(
                f"step budget {self.max_steps} exhausted after {self.steps_used} steps"
            )

    @property
    def remaining(self) -> int:
        return max(0, self.max_steps - self.steps_used)

    @property
    def exhausted(self) -> bool:
        return self.steps_used >= self.max_steps

    def reset(self) -> None:
        self.steps_used = 0


__all__ = ["StepBudget", "StepBudgetExhausted"]
