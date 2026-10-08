"""Telemetry dashboard for the Deterministic Integrity Tower.

The dashboard records what the tower decided and how long each run took. It
only reads finished results. It never changes a decision, so attaching one to
a tower is safe for any deployment.

What it counts:

  - runs released, and runs held, split by where the hold happened
  - which gates produced blocking findings, counted once per run
  - rewrite attempts used, on average
  - latency over a rolling window of recent runs (average and 95th percentile)
"""

from __future__ import annotations

import math
import threading
from collections import Counter, deque
from typing import Any

from .result import TowerResult, Verdict

#: How many recent runs the latency figures are computed over.
DEFAULT_WINDOW = 1000

RELEASED = "released"
HELD_BY_SIEVE = "held_by_sieve"
HELD_BY_RELEASE = "held_by_release"


class TelemetryDashboard:
    """Counts tower outcomes. Safe to share across threads."""

    def __init__(self, window: int = DEFAULT_WINDOW) -> None:
        if window < 1:
            raise ValueError("window must be at least 1")
        self._lock = threading.Lock()
        self._latencies_ms: deque[float] = deque(maxlen=window)
        self._total = 0
        self._outcomes: Counter[str] = Counter()
        self._breaches_by_gate: Counter[str] = Counter()
        self._attempts_total = 0

    def record(self, result: TowerResult) -> None:
        """Count one finished run."""
        if result.released:
            outcome = RELEASED
        elif result.sieve.verdict is Verdict.BREACH:
            outcome = HELD_BY_SIEVE
        else:
            outcome = HELD_BY_RELEASE

        with self._lock:
            self._total += 1
            self._outcomes[outcome] += 1
            self._attempts_total += result.attempts
            self._latencies_ms.append(result.elapsed_ms)
            # Count each gate once per run that produced a blocking finding.
            blocking = {f.gate_id for f in result.sieve.findings if f.verdict is Verdict.BREACH}
            for gate_id in blocking:
                self._breaches_by_gate[gate_id] += 1

    def snapshot(self) -> dict[str, Any]:
        """Return the current figures as a plain dictionary."""
        with self._lock:
            total = self._total
            outcomes = dict(self._outcomes)
            breaches = dict(self._breaches_by_gate)
            attempts_total = self._attempts_total
            latencies = sorted(self._latencies_ms)

        released = outcomes.get(RELEASED, 0)
        return {
            "total_runs": total,
            "released": released,
            "held_by_sieve": outcomes.get(HELD_BY_SIEVE, 0),
            "held_by_release": outcomes.get(HELD_BY_RELEASE, 0),
            "release_rate": round(released / total, 4) if total else 0.0,
            "breaches_by_gate": breaches,
            "avg_attempts": round(attempts_total / total, 4) if total else 0.0,
            "window_runs": len(latencies),
            "avg_latency_ms": (
                round(sum(latencies) / len(latencies), 4) if latencies else 0.0
            ),
            "p95_latency_ms": _percentile(latencies, 0.95),
        }


def _percentile(sorted_values: list[float], q: float) -> float:
    """Nearest-rank percentile of an already sorted list. Empty gives 0.0."""
    if not sorted_values:
        return 0.0
    rank = math.ceil(q * len(sorted_values))
    index = min(len(sorted_values) - 1, max(0, rank - 1))
    return round(sorted_values[index], 4)


__all__ = ["TelemetryDashboard", "DEFAULT_WINDOW", "RELEASED", "HELD_BY_SIEVE", "HELD_BY_RELEASE"]
