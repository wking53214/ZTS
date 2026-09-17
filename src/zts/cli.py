"""Command-line interface.

    zts scrub "text"              filter text, print the result
    zts audit "text" --json       full findings as JSON
    zts gates                     print the gate array
    zts bench                     measure fail-fast on this machine
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from . import __version__, audit as audit_text
from .gates import CANONICAL_ORDER, FAIL_FAST_ORDER
from .profiles import PROFILES
from .result import SieveResult, Verdict


def _result_dict(result: SieveResult) -> dict:
    return {
        "verdict": result.verdict.value,
        "profile": result.profile,
        "score": result.score,
        "parity": round(result.parity, 4),
        "elapsed_ms": round(result.elapsed_ms, 4),
        "breached_at": result.breached_at.value.gate_id if result.breached_at else None,
        "gates_not_reached": result.gates_skipped,
        "payload_in": result.payload_in,
        "payload_out": result.payload_out,
        "findings": [
            {
                "gate": f.gate_id,
                "code": f.code,
                "verdict": f.verdict.value,
                "evidence": f.evidence,
                "offset": f.offset,
                "detail": f.detail,
            }
            for f in result.findings
        ],
        "gates": [
            {
                "gate": g.gate.value.gate_id,
                "code": g.gate.code,
                "verdict": g.verdict.value,
                "findings": len(g.findings),
                "mutated": g.mutated,
                "elapsed_us": round(g.elapsed_ns / 1000, 2),
            }
            for g in result.gates
        ],
    }


def _read_text(args: argparse.Namespace) -> str:
    if args.text:
        return " ".join(args.text)
    if not sys.stdin.isatty():
        return sys.stdin.read()
    raise SystemExit("zts: no input. Pass text as an argument or on stdin.")


def cmd_scrub(args: argparse.Namespace) -> int:
    result = audit_text(_read_text(args), args.profile)
    print(result.payload_out)
    if args.strict and result.verdict is Verdict.BREACH:
        print(f"zts: {result.summary()}", file=sys.stderr)
        return 1
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    result = audit_text(_read_text(args), args.profile)
    if args.json:
        print(json.dumps(_result_dict(result), indent=2))
    else:
        print(result.summary())
        print()
        for gate_result in result.gates:
            mark = {
                Verdict.CLEAN: "  ok  ",
                Verdict.ADVISORY: " note ",
                Verdict.BREACH: "BREACH",
                Verdict.SKIPPED: " skip ",
                Verdict.NOT_REACHED: "  --  ",
            }[gate_result.verdict]
            spec = gate_result.gate.value
            print(f"[{mark}] {spec.gate_id}/{spec.code:<4} {spec.name}")
            for f in gate_result.findings:
                detail = f" ({f.detail})" if f.detail else ""
                print(f"           -> {f.evidence!r}{detail}")
        print()
        print("payload:", result.payload_out)
    if args.strict and result.verdict is Verdict.BREACH:
        return 1
    return 0


def cmd_gates(args: argparse.Namespace) -> int:
    order = FAIL_FAST_ORDER if args.order == "fail-fast" else CANONICAL_ORDER
    print(f"Gate array ({args.order} order)\n")
    for position, gate in enumerate(order, 1):
        spec = gate.value
        print(f"{position}. {spec.gate_id}/{spec.code} - {spec.name}  [{spec.cost.name}]")
        for line in _wrap(spec.summary, 72):
            print(f"     {line}")
        print()
    if args.order == "fail-fast":
        print("G7/TAP is excluded: it is the manual capstone and never runs automatically.")
    return 0


def cmd_profiles(args: argparse.Namespace) -> int:
    for name, profile in sorted(PROFILES.items()):
        enforced = ", ".join(sorted(g.value.gate_id for g in profile.enforced)) or "none"
        advisory = ", ".join(sorted(g.value.gate_id for g in profile.advisory)) or "none"
        print(f"{name:<8} threshold={profile.threshold:<3} retries={profile.max_retries}")
        print(f"         enforced: {enforced}")
        print(f"         advisory: {advisory}")
        print()
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from .bench import run_bench, format_bench

    print(format_bench(run_bench(iterations=args.iterations)))
    return 0


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zts", description="Zero Trust Stack")
    parser.add_argument("--version", action="version", version=f"zts {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, handler, helptext in (
        ("scrub", cmd_scrub, "filter text and print the cleaned payload"),
        ("audit", cmd_audit, "filter text and report every gate decision"),
    ):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("text", nargs="*", help="text to filter (or pipe on stdin)")
        p.add_argument(
            "-p", "--profile", default="default", choices=sorted(PROFILES), help="enforcement profile"
        )
        p.add_argument("--strict", action="store_true", help="exit 1 on breach")
        if name == "audit":
            p.add_argument("--json", action="store_true", help="machine-readable output")
        p.set_defaults(func=handler)

    p = sub.add_parser("gates", help="print the gate array")
    p.add_argument(
        "--order", default="fail-fast", choices=["fail-fast", "canonical"]
    )
    p.set_defaults(func=cmd_gates)

    p = sub.add_parser("profiles", help="print the enforcement profiles")
    p.set_defaults(func=cmd_profiles)

    p = sub.add_parser("bench", help="measure fail-fast ordering on this machine")
    p.add_argument("-n", "--iterations", type=int, default=20000)
    p.set_defaults(func=cmd_bench)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
