#!/usr/bin/env python3
"""Review a trust-root file before it goes live, and show exactly what an edit changes.

    python scripts/trust_root_review.py NEW.json                      # is it valid, and what does it trust?
    python scripts/trust_root_review.py NEW.json --previous OLD.json  # and what changed from the live one?

This is the tool for the edit procedure in docs/DEPLOYMENT.md section 2: one person prepares the file, a second runs this
on it and signs off on the output. It applies ZTS's own parser (strict JSON, no repeated keys, no NaN, key ids derived
from the keys), so a file it accepts is a file ZTS will load. It cannot say whether the keys are the right ones: that is
the review.

With ``--previous`` it refuses (exit 1) an edit that
  * does not raise ``serial`` (a serial store would refuse it as a rollback, and a missing one cannot be ordered),
  * brings back a key that was revoked (the most dangerous edit: it un-revokes a key by editing a file), or
  * changes the public key, role, issuer or window of a key id that already existed (impossible for an honest edit,
    because the key id is derived from the key; shown so a hand-edited window is not missed).
Warnings (exit 0) cover a role with no usable key, keys that expire soon, and an active key already past its end.

``expected_sha256`` for ``FileTrustRoot`` is the SHA-256 of the file's bytes, printed below.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from zts.trust import MAX_TRUST_BYTES, ROLE_GRANT, ROLE_STATUS, Rejected, TrustRoot, TrustRootError, strict_json


def load(path: Path) -> tuple[TrustRoot, str]:
    raw = path.read_bytes() if path.stat().st_size <= MAX_TRUST_BYTES else b""
    if not raw:
        raise TrustRootError(f"{path.name} is empty or larger than {MAX_TRUST_BYTES} bytes")
    try:
        doc = strict_json(raw)
    except Rejected as exc:
        raise TrustRootError(f"{path.name} is not valid strict JSON ({exc.reason})") from None
    return TrustRoot.from_dict(doc), hashlib.sha256(raw).hexdigest()


def describe(key, now) -> str:
    state = "revoked" if key.status == "revoked" else ("usable" if key.usable_at(now) else "not usable now")
    return (f"{key.kid}  {key.role:<6}  issuer={key.issuer_id}  "
            f"{key.not_before.date()} .. {key.not_after.date()}  {key.status}, {state}")


def review(new_path: Path, previous_path: Path | None, now: datetime, soon_days: int) -> tuple[list[str], list[str], list[str]]:
    """Returns (report lines, problems that fail the review, warnings)."""
    out: list[str] = []
    problems: list[str] = []
    warnings: list[str] = []
    new, file_sha = load(new_path)
    out += [f"file          {new_path.name}", f"sha256        {file_sha}   (use as expected_sha256 to pin this exact file)",
            f"serial        {new.serial if new.serial is not None else 'none'}", f"keys          {len(new.keys)}"]
    for key in sorted(new.keys.values(), key=lambda k: (k.role, k.kid)):
        out.append("  " + describe(key, now))
        if key.status == "active" and key.not_after < now:
            warnings.append(f"{key.kid} is marked active but its window ended {key.not_after.date()}")
        elif key.usable_at(now) and key.not_after - now < timedelta(days=soon_days):
            warnings.append(f"{key.kid} ({key.role}) expires in under {soon_days} days ({key.not_after.date()})")
    for role in (ROLE_GRANT, ROLE_STATUS):
        if not any(k.role == role and k.usable_at(now) for k in new.keys.values()):
            warnings.append(f"no usable {role} key: every {role} verification will be refused")
    if new.serial is None:
        warnings.append("no serial: a serial store cannot be used with this file, and edits cannot be ordered")

    if previous_path is not None:
        old, _ = load(previous_path)
        out.append("")
        out.append(f"changes from  {previous_path.name}")
        if new.serial is None or old.serial is None or new.serial <= old.serial:
            problems.append(f"serial must rise (was {old.serial}, now {new.serial})")
        added, removed = sorted(set(new.keys) - set(old.keys)), sorted(set(old.keys) - set(new.keys))
        for kid in added:
            out.append("  + " + describe(new.keys[kid], now))
        for kid in removed:
            out.append("  - " + describe(old.keys[kid], now))
            if old.keys[kid].status == "revoked":
                warnings.append(f"{kid} was revoked and is now absent: absent is also untrusted, but the revocation record is gone")
        for kid in sorted(set(new.keys) & set(old.keys)):
            before, after = old.keys[kid], new.keys[kid]
            if before == after:
                continue
            out.append(f"  ~ {kid}: " + "; ".join(
                f"{f} {getattr(before, f)!s} -> {getattr(after, f)!s}"
                for f in ("issuer_id", "role", "not_before", "not_after", "status", "public_key")
                if getattr(before, f) != getattr(after, f)))
            if before.status == "revoked" and after.status == "active":
                problems.append(f"{kid} was REVOKED and is ACTIVE again")
            if (before.role, before.issuer_id, before.public_key) != (after.role, after.issuer_id, after.public_key):
                problems.append(f"{kid} changed its role, issuer or key")
            if after.not_after > before.not_after:
                warnings.append(f"{kid} has a longer window than before (ends {after.not_after.date()})")
        if not (added or removed) and all(old.keys[k] == new.keys[k] for k in new.keys):
            out.append("  no key changed")
    return out, problems, warnings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("new", type=Path)
    ap.add_argument("--previous", type=Path, help="the trust-root file that is live now")
    ap.add_argument("--soon-days", type=int, default=30)
    args = ap.parse_args(argv)
    try:
        out, problems, warnings = review(args.new, args.previous, datetime.now(timezone.utc), args.soon_days)
    except (TrustRootError, OSError) as exc:
        print(f"REFUSED: {exc}")
        return 1
    print("\n".join(out))
    for w in warnings:
        print(f"WARNING: {w}")
    for p in problems:
        print(f"PROBLEM: {p}")
    print("RESULT: " + ("FAIL" if problems else "OK (a person must still decide the keys are the right ones)"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
