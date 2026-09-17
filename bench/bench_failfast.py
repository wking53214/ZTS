#!/usr/bin/env python3
"""Run the fail-fast benchmark.

    python bench/bench_failfast.py

Equivalent to `zts bench`. Kept as a script so the measurement is runnable
without installing the package.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from zts.bench import (  # noqa: E402
    format_bench,
    run_bench,
    run_bench_with_expensive_semantics,
)

if __name__ == "__main__":
    print(format_bench(run_bench(mode="reject")))
    print()
    print(format_bench(run_bench(mode="repair")))
    print()
    print("Semantic gates at 5ms each, standing in for a model call:")
    print(format_bench(run_bench_with_expensive_semantics()))
