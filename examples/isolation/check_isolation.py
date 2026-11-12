#!/usr/bin/env python3
"""Acceptance test 14: try the forbidden things as the application's account, and report which ones worked.

Run it AS THE APPLICATION'S ACCOUNT (never as root, which passes every file check and so proves nothing):

    sudo -u zts-app python3 check_isolation.py isolation-check.json

PASS means the attempt was refused. FAIL means the application's account can do something it must not (fix the permissions,
do not ignore it). ERROR means the check proves nothing (the path does not exist, or the file is malformed), which is not a pass.

It never changes anything that already exists: writes are tried with a plain open-for-write (no create, no truncate) and
closed at once; a directory is tried by creating a temporary file and deleting it.

Run it a second time AS THE SERVICE ACCOUNT with --expect-access. That is the control that shows your paths and addresses are
real, so a PASS above means "refused" and not "typo". In that mode the files in must_not_read must be readable and the addresses
in must_not_connect must answer; the paths in must_not_write and must_not_write_in only have to exist (the service is not meant
to write its own trust root, so it is not asked to).
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import sys
import tempfile

PASS, FAIL, ERROR = "PASS", "FAIL", "ERROR"


def probe_read(path: str) -> tuple[bool | None, str]:
    """(accessible?, detail). None means the probe proves nothing."""
    try:
        os.stat(path)
    except FileNotFoundError:
        return None, "does not exist (as seen from this account)"
    except PermissionError:
        return False, "cannot reach it (permission denied)"
    try:
        fd = os.open(path, os.O_RDONLY)
    except PermissionError:
        return False, "permission denied"
    except OSError as exc:
        return None, f"could not be tried: {exc.strerror}"
    os.close(fd)
    return True, "opened for reading"


def probe_write(path: str) -> tuple[bool | None, str]:
    try:
        os.stat(path)
    except FileNotFoundError:
        return None, "does not exist (as seen from this account)"
    except PermissionError:
        return False, "cannot reach it (permission denied)"
    try:
        fd = os.open(path, os.O_WRONLY)  # no O_CREAT, O_TRUNC or O_APPEND: nothing is changed
    except PermissionError:
        return False, "permission denied"
    except OSError as exc:
        if exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
            return False, exc.strerror
        return None, f"could not be tried: {exc.strerror}"
    os.close(fd)
    return True, "opened for writing"


def probe_write_dir(path: str) -> tuple[bool | None, str]:
    if not os.path.isdir(path):
        try:
            os.stat(path)
        except PermissionError:
            return False, "cannot reach it (permission denied)"
        except FileNotFoundError:
            return None, "does not exist (as seen from this account)"
        return None, "is not a directory"
    try:
        handle = tempfile.NamedTemporaryFile(dir=path, prefix=".isolation-check-")
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
            return False, exc.strerror
        return None, f"could not be tried: {exc.strerror}"
    handle.close()  # deletes the temporary file
    return True, "created (and removed) a file"


def probe_connect(address: str) -> tuple[bool | None, str]:
    try:
        if address.startswith("unix:"):
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(2)
                s.connect(address[5:])
        else:
            host, _, port = address.rpartition(":")
            if not host or not port.isdigit():
                return None, "not host:port or unix:/path"
            with socket.create_connection((host, int(port)), timeout=2):
                pass
    except (ConnectionRefusedError, socket.timeout, TimeoutError):
        return False, "refused or no answer"
    except PermissionError:
        return False, "permission denied"
    except FileNotFoundError:
        return False, "no such socket"
    except OSError as exc:
        return False, exc.strerror or "unreachable"
    return True, "connected"


PROBES = (("must_not_read", "read", probe_read), ("must_not_write", "write", probe_write),
          ("must_not_write_in", "create a file in", probe_write_dir), ("must_not_connect", "connect to", probe_connect))


def probe_exists(path: str) -> tuple[bool | None, str]:
    try:
        os.stat(path)
    except FileNotFoundError:
        return None, "does not exist (as seen from this account)"
    except PermissionError:
        return False, "cannot reach it (permission denied)"
    return True, "exists"


def run(config: dict, expect_access: bool) -> list[tuple[str, str, str]]:
    results = []
    unknown = set(config) - {key for key, _, _ in PROBES}
    if unknown:
        return [(ERROR, "config", f"unknown keys: {sorted(unknown)}")]
    for key, verb, probe in PROBES:
        items = config.get(key, [])
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            results.append((ERROR, key, "must be a list of strings"))
            continue
        if expect_access and key in ("must_not_write", "must_not_write_in"):
            probe = probe_exists
        for item in items:
            accessible, detail = probe(item)
            if accessible is None:
                status = ERROR
            elif accessible == expect_access:
                status = PASS
            else:
                status = FAIL
            results.append((status, f"{verb} {item}", detail))
    if not results:
        results.append((ERROR, "config", "nothing to check"))
    return results


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("config", help="JSON: must_not_read, must_not_write, must_not_write_in, must_not_connect (lists)")
    ap.add_argument("--expect-access", action="store_true",
                    help="control run, as the service account: readable files and addresses must answer, other paths must exist")
    args = ap.parse_args(argv)
    if os.geteuid() == 0:
        print("ERROR: running as root proves nothing. Run this as the application's account.")
        return 1
    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    print(f"running as uid={os.geteuid()} gid={os.getegid()} groups={sorted(os.getgroups())}")
    results = run(config, args.expect_access)
    for status, what, detail in results:
        print(f"{status:<5} {'can' if args.expect_access else 'must not'} {what}: {detail}")
    bad = [r for r in results if r[0] != PASS]
    print("RESULT: " + ("PASS" if not bad else f"NOT PASSED ({len(bad)} item(s) need attention)"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
