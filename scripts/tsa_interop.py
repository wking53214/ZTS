#!/usr/bin/env python3
"""Stamp one head with a REAL RFC 3161 timestamp authority and verify the answer, using ZTS's own anchor.

Why this exists. ZTS's tests check its RFC 3161 client against OpenSSL's independent TSA. They cannot check a
public or corporate authority, because that needs your network and the authority's signing certificate. Run this
once from the host that will release, before you rely on the anchor:

    python scripts/tsa_interop.py https://tsa.example/ --cert tsa-signing-chain.pem

``--cert`` is the authority's signing certificate (and any chain the token omits), PEM, which you obtained and checked
out of band. It is the trust anchor: nothing is fetched or trusted automatically. ``--cafile`` is only for the TLS
connection to an https authority. Exit status 0 means a token came back, verified against your pinned certificate, bound to
the digest and nonce this run sent, and the stamped time is within ``--max-skew`` seconds of this host's clock.

Nothing is written outside a temporary directory, and no ledger is touched.
"""

from __future__ import annotations

import argparse
import ssl
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from zts.anchor_tsa import Rfc3161Anchor, TimestampError


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("url", help="the timestamp authority URL (http or https)")
    ap.add_argument("--cert", action="append", required=True, type=Path,
                    help="PEM file with the authority's signing certificate (repeat for a chain)")
    ap.add_argument("--cafile", type=Path, help="CA bundle for the TLS connection, if the system store will not do")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--max-skew", type=float, default=300.0, help="largest accepted difference from this host's clock")
    args = ap.parse_args(argv)

    context = ssl.create_default_context(cafile=str(args.cafile)) if args.cafile else None
    with tempfile.TemporaryDirectory() as tmp:
        anchor = Rfc3161Anchor(args.url, [p.read_bytes() for p in args.cert], Path(tmp) / "receipts.jsonl",
                               timeout=args.timeout, ssl_context=context, min_interval=0)
        before = datetime.now(timezone.utc)
        try:
            anchor.publish(1, "interop-check-" + before.strftime("%Y%m%dT%H%M%S"))
            anchor.flush()
            stamped = anchor.verify_all()
        except TimestampError as exc:
            print(f"FAIL: {exc}")
            return 1
        after = datetime.now(timezone.utc)
    if not stamped:
        print("FAIL: no receipt was produced")
        return 1
    _, _, when = stamped[-1]
    skew = max((before - when).total_seconds(), (when - after).total_seconds(), 0.0)
    print(f"stamped at {when.isoformat()} by {args.url} (skew from this host: {skew:.1f}s)")
    if skew > args.max_skew:
        print(f"FAIL: the stamped time is {skew:.0f}s away from this host's clock (limit {args.max_skew:.0f}s)")
        return 1
    print("PASS: token verified against the pinned certificate, bound to this request")
    return 0


if __name__ == "__main__":
    sys.exit(main())
