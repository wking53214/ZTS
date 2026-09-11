"""Measure the fail-fast ordering.

The archive claims the fail-fast refactor moved the array from 214ms to 32ms.
Those numbers were narrated by a language model describing a simulation it did
not run. This module measures the real thing on the machine you are on.

What is measured: the same gate array, same payloads, same implementations, run
once in ascending-cost order (fail-fast) and once in descending-cost order
(worst case). The difference is attributable to ordering alone.

There are two modes, and the distinction is the single most important thing
this benchmark established.

REJECT mode: the array stops at the first gate that finds anything. Cost
ordering matters, because a payload that trips G6 never pays for G2 or G4.

REPAIR mode: a gate that finds something fixes it and the array continues to
the next gate. Every gate runs on every payload. Cost ordering is irrelevant,
because the total work is the sum of all gates either way.

The archived stack ran in REPAIR mode. It substituted violations away and kept
going. That means the fail-fast reorder it credited with a 214ms -> 32ms
improvement could not have produced that improvement in that build: reordering
a sequence whose every element executes does not change its cost. The
optimization is sound, and this repository implements it, but it only pays in
REJECT mode. Run the benchmark and the two modes separate cleanly.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from .gates import FAIL_FAST_ORDER, Cost, Gate
from .profiles import get as get_profile
from .sieve import GATE_IMPLS, GateContext

#: Payloads chosen so that most trip an early, cheap gate. That distribution is
#: the premise of the optimization, and it is the distribution the archive
#: reported seeing: identity and hedging dominate real violations.
CORPUS: tuple[str, ...] = (
    "I think we should probably look at this.",
    "As an AI, I may be wrong about the throughput numbers.",
    "Great point. We could potentially leverage this methodology.",
    "The cluster dropped 12% of writes because the primary lost quorum.",
    "My sense is that our approach might generally work.",
    "Latency rose 40ms after the index rebuild, driven by cold cache pages.",
    "Honestly, I feel like this seems suboptimal to me.",
    "Disk utilization reached 94% on node 3 at 02:17 UTC.",
    "You are correct, and I agree that we should prioritize it.",
    "Requests per second fell from 8100 to 5400 following the deploy.",
)

SIMULATED_DELAY_S = 0.0


@dataclass
class BenchResult:
    label: str
    order: tuple[Gate, ...]
    iterations: int
    mean_us: float
    median_us: float
    p95_us: float
    gates_executed: int

    @property
    def gates_per_payload(self) -> float:
        return self.gates_executed / self.iterations


def _run_order(
    order: tuple[Gate, ...],
    iterations: int,
    mode: str = "reject",
    semantic_delay_s: float = 0.0,
) -> tuple[list[float], int]:
    """Execute `order` over the corpus `iterations` times.

    mode="reject": stop at the first gate that finds anything.
    mode="repair": let each gate fix what it finds and continue.
    """
    profile = get_profile("ops")
    ctx = GateContext(profile)
    samples: list[float] = []
    executed = 0
    corpus = CORPUS
    n = len(corpus)

    for i in range(iterations):
        payload = corpus[i % n]
        started = time.perf_counter_ns()
        current = payload
        for gate in order:
            if semantic_delay_s and gate.cost.value >= Cost.SEMANTIC.value:
                time.sleep(semantic_delay_s)
            current, findings = GATE_IMPLS[gate](current, ctx)
            executed += 1
            if findings and mode == "reject":
                break
        samples.append((time.perf_counter_ns() - started) / 1000)

    return samples, executed


def _summarize(label: str, order: tuple[Gate, ...], samples: list[float], executed: int) -> BenchResult:
    ordered = sorted(samples)
    return BenchResult(
        label=label,
        order=order,
        iterations=len(samples),
        mean_us=statistics.fmean(samples),
        median_us=statistics.median(samples),
        p95_us=ordered[int(len(ordered) * 0.95)],
        gates_executed=executed,
    )


def run_bench(iterations: int = 20000, mode: str = "reject") -> dict[str, BenchResult]:
    """Run fail-fast ordering against worst-case ordering."""
    fail_fast = FAIL_FAST_ORDER
    worst_case = tuple(reversed(FAIL_FAST_ORDER))

    # Warm the regex engine and the branch predictor before measuring.
    _run_order(fail_fast, min(2000, iterations), mode)

    ff_samples, ff_exec = _run_order(fail_fast, iterations, mode)
    wc_samples, wc_exec = _run_order(worst_case, iterations, mode)

    return {
        "mode": mode,
        "fail_fast": _summarize("fail-fast (ascending cost)", fail_fast, ff_samples, ff_exec),
        "worst_case": _summarize("worst case (descending cost)", worst_case, wc_samples, wc_exec),
    }


def run_bench_with_expensive_semantics(
    iterations: int = 200, semantic_delay_ms: float = 5.0, mode: str = "reject"
) -> dict[str, BenchResult]:
    """Re-run with the semantic gates made expensive.

    Stands in for G2/G4 backed by a model call rather than a regex. This is the
    regime the ordering was designed for, and the one where the difference is
    large rather than marginal.
    """
    delay = semantic_delay_ms / 1000
    fail_fast = FAIL_FAST_ORDER
    worst_case = tuple(reversed(FAIL_FAST_ORDER))

    ff_samples, ff_exec = _run_order(fail_fast, iterations, mode, delay)
    wc_samples, wc_exec = _run_order(worst_case, iterations, mode, delay)

    return {
        "mode": mode,
        "fail_fast": _summarize("fail-fast (ascending cost)", fail_fast, ff_samples, ff_exec),
        "worst_case": _summarize("worst case (descending cost)", worst_case, wc_samples, wc_exec),
    }


def format_bench(results: dict) -> str:
    mode = results.get("mode", "reject")
    ff = results["fail_fast"]
    wc = results["worst_case"]
    lines = [
        f"ZTS fail-fast benchmark  [mode={mode}]",
        "",
        f"{'ordering':<30} {'mean':>11} {'median':>11} {'p95':>11} {'gates/payload':>15}",
        "-" * 81,
    ]
    for result in (ff, wc):
        lines.append(
            f"{result.label:<30} "
            f"{result.mean_us:>10.2f}u {result.median_us:>10.2f}u {result.p95_us:>10.2f}u "
            f"{result.gates_per_payload:>15.2f}"
        )

    delta = (wc.mean_us - ff.mean_us) / wc.mean_us * 100 if wc.mean_us else 0.0
    work = (wc.gates_per_payload - ff.gates_per_payload) / wc.gates_per_payload * 100 \
        if wc.gates_per_payload else 0.0
    lines += [
        "",
        f"iterations: {ff.iterations} per ordering",
        f"latency:    fail-fast {delta:+.1f}% vs worst case",
        f"gate work:  fail-fast {work:+.1f}% fewer gate executions per payload",
    ]
    if mode == "repair":
        lines += [
            "",
            "In repair mode every gate runs on every payload, so ordering changes",
            "nothing. This is the mode the archived build ran in, which is why its",
            "214ms -> 32ms claim could not have come from the reorder.",
        ]
    else:
        lines += [
            "",
            "u = microseconds, measured on this machine on this run. These numbers",
            "replace the archived 214ms -> 32ms claim, which was never measured.",
        ]
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    print(format_bench(run_bench(mode="reject")))
    print()
    print(format_bench(run_bench(mode="repair")))
    print()
    print("Semantic gates at 5ms each, standing in for a model call:")
    print(format_bench(run_bench_with_expensive_semantics()))
