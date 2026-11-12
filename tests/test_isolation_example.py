"""examples/isolation: the setup script, the isolation check and the systemd unit.

The check is exercised for real: the layout is built by the setup script, then the check runs as two different operating-system
accounts (`nobody` as the application, `daemon` as the service). Needs root, those two accounts and `runuser`; skips otherwise.
"""

from __future__ import annotations

import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "isolation"
UNIT = (EXAMPLE / "zts-release.service").read_text(encoding="utf-8")


def users_available() -> bool:
    try:
        pwd.getpwnam("nobody")
        pwd.getpwnam("daemon")
    except KeyError:
        return False
    return os.geteuid() == 0 and shutil.which("runuser") is not None and Path("/usr/bin/python3").exists()


needs_accounts = pytest.mark.skipif(not users_available(), reason="needs root, the nobody and daemon accounts and runuser")


# ------------------------------------------------------------------------ the unit


def directive(name):
    return re.findall(rf"^{name}=(.*)$", UNIT, re.M)


@pytest.mark.parametrize("name,value", [
    ("User", "zts-release"), ("NoNewPrivileges", "true"), ("ProtectSystem", "strict"), ("ProtectHome", "true"),
    ("PrivateTmp", "true"), ("PrivateDevices", "true"), ("CapabilityBoundingSet", ""), ("UMask", "0077"),
    ("RestrictSUIDSGID", "true"), ("ProtectKernelTunables", "true"), ("ReadOnlyPaths", "/etc/zts"),
    ("ReadWritePaths", "/var/lib/zts"), ("IPAddressDeny", "any"), ("StateDirectoryMode", "0700"),
])
def test_the_unit_keeps_its_hardening_directives(name, value):
    assert directive(name) == [value], (name, directive(name))


def test_the_service_may_write_only_its_own_state_and_not_the_trust_root():
    assert directive("ReadWritePaths") == ["/var/lib/zts"] and "/etc/zts" not in directive("ReadWritePaths")


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="needs systemd-analyze")
def test_systemd_accepts_the_unit_and_scores_its_exposure_low():
    verify = subprocess.run(["systemd-analyze", "verify", str(EXAMPLE / "zts-release.service")], capture_output=True, text=True)
    # systemd-analyze also reports on the machine's own units (a CI runner prints warnings about them), so look only at ours.
    ours = [line for line in (verify.stdout + verify.stderr).splitlines() if "zts-release.service" in line]
    assert all("is not executable" in line for line in ours), ours  # only the placeholder program is missing
    security = subprocess.run(["systemd-analyze", "security", "--offline=true", str(EXAMPLE / "zts-release.service")],
                              capture_output=True, text=True)
    match = re.search(r"exposure level for .*?: ([0-9.]+) ", security.stdout)
    if match is None:
        pytest.skip("this systemd-analyze cannot score a unit offline")
    assert float(match.group(1)) <= 2.5, security.stdout[-400:]


# ------------------------------------------------------------- the layout and the check


@pytest.fixture
def world():
    root = Path(tempfile.mkdtemp(dir="/tmp", prefix="zts-iso-"))
    os.chmod(root, 0o755)  # the application account must be able to walk down to the paths, or every check would "pass"
    env = {**os.environ, "PREFIX": str(root), "SERVICE_USER": "daemon", "APP_USER": "nobody", "CREATE_USERS": "0"}
    done = subprocess.run(["bash", str(EXAMPLE / "setup_accounts.sh")], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    daemon = pwd.getpwnam("daemon")
    for name in ("delivery.cred", "replay.dsn", "release-signing.key"):
        f = root / "etc/zts/secrets" / name
        f.write_bytes(b"secret")
        os.chown(f, daemon.pw_uid, daemon.pw_gid)
        os.chmod(f, 0o600)
    trust = root / "etc/zts/trust-root.json"
    trust.write_text("{}")
    os.chmod(trust, 0o644)
    for name in ("ledger.jsonl", "receipts.jsonl"):
        f = root / "var/lib/zts" / name
        f.write_text("x")
        os.chown(f, daemon.pw_uid, daemon.pw_gid)
        os.chmod(f, 0o600)
    config = {
        "must_not_read": [str(root / "etc/zts/secrets" / n) for n in ("delivery.cred", "replay.dsn", "release-signing.key")]
        + [str(root / "var/lib/zts/ledger.key")],
        "must_not_write": [str(root / "etc/zts/trust-root.json"), str(root / "var/lib/zts/ledger.jsonl"),
                           str(root / "var/lib/zts/receipts.jsonl"), str(root / "var/lib/zts/ledger.key")],
        "must_not_write_in": [str(root / "etc/zts"), str(root / "var/lib/zts")],
        "must_not_connect": [],
    }
    shutil.copy(EXAMPLE / "check_isolation.py", root / "check_isolation.py")
    os.chmod(root / "check_isolation.py", 0o755)
    yield root, config
    shutil.rmtree(root, ignore_errors=True)


def run_as(user, root, config, *extra):
    cfg = root / f"cfg-{user}.json"
    cfg.write_text(json.dumps(config))
    os.chmod(cfg, 0o644)
    done = subprocess.run(["runuser", "-u", user, "--", "/usr/bin/python3", str(root / "check_isolation.py"), str(cfg), *extra],
                          capture_output=True, text=True, cwd="/")
    return done.returncode, done.stdout + done.stderr


@needs_accounts
def test_the_layout_the_script_builds_passes_the_check_as_the_application(world):
    root, config = world
    code, out = run_as("nobody", root, config)
    assert code == 0, out
    assert "FAIL" not in out and "ERROR" not in out and "RESULT: PASS" in out


@needs_accounts
def test_the_same_paths_are_real_and_reachable_as_the_service_account(world):
    """The control: without it, 'permission denied' could just be a typo in a path."""
    root, config = world
    code, out = run_as("daemon", root, config, "--expect-access")
    assert code == 0, out


@needs_accounts
def test_the_layout_has_the_owners_and_modes_it_documents(world):
    root, _ = world
    daemon, nobody = pwd.getpwnam("daemon"), pwd.getpwnam("nobody")
    expected = {"etc/zts": (0, 0o755), "etc/zts/secrets": (daemon.pw_uid, 0o700), "var/lib/zts": (daemon.pw_uid, 0o700),
                "var/lib/zts/ledger.key": (daemon.pw_uid, 0o600)}
    for rel, (uid, mode) in expected.items():
        info = (root / rel).stat()
        assert (info.st_uid, info.st_mode & 0o7777) == (uid, mode), rel
    assert nobody.pw_uid not in {(root / rel).stat().st_uid for rel in expected}
    assert len((root / "var/lib/zts/ledger.key").read_bytes()) == 32


@needs_accounts
def test_each_loosened_permission_is_found_and_only_those(world):
    root, config = world
    os.chmod(root / "etc/zts/secrets", 0o755)            # the directory opens up...
    os.chmod(root / "etc/zts/secrets/delivery.cred", 0o644)   # ...and one secret becomes world-readable
    os.chmod(root / "var/lib/zts", 0o755)
    os.chmod(root / "var/lib/zts/ledger.jsonl", 0o666)    # a ledger anyone can write
    os.chmod(root / "etc/zts", 0o777)                     # a configuration directory anyone can add to
    code, out = run_as("nobody", root, config)
    failed = sorted(re.findall(r"^FAIL +must not (.+?):", out, re.M))
    assert code == 1
    assert failed == sorted([f"read {root}/etc/zts/secrets/delivery.cred", f"write {root}/var/lib/zts/ledger.jsonl",
                             f"create a file in {root}/etc/zts"]), out


@needs_accounts
def test_the_check_changes_nothing_even_when_it_finds_a_hole(world):
    root, config = world
    os.chmod(root / "var/lib/zts", 0o755)
    os.chmod(root / "var/lib/zts/ledger.jsonl", 0o666)
    os.chmod(root / "etc/zts", 0o777)
    before = {p: p.read_bytes() for p in (root / "var/lib/zts").iterdir()}
    listing = sorted(p.name for p in (root / "etc/zts").iterdir())
    code, _ = run_as("nobody", root, config)
    assert code == 1
    assert {p: p.read_bytes() for p in (root / "var/lib/zts").iterdir()} == before
    assert sorted(p.name for p in (root / "etc/zts").iterdir()) == listing


@needs_accounts
def test_a_path_that_does_not_exist_is_an_error_never_a_pass(world):
    root, config = world
    config["must_not_read"].append(str(root / "etc/zts/secrets/typo.cred"))
    os.chmod(root / "etc/zts/secrets", 0o755)  # visible, so the typo is distinguishable from a permission refusal
    code, out = run_as("nobody", root, config)
    assert code == 1 and re.search(r"^ERROR +must not read .*typo.cred", out, re.M)


@needs_accounts
def test_a_reachable_address_fails_and_an_unreachable_one_passes(world):
    root, config = world
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    open_port = listener.getsockname()[1]
    threading.Thread(target=lambda: listener.accept(), daemon=True).start()
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        config["must_not_connect"] = [f"127.0.0.1:{open_port}", f"127.0.0.1:{closed_port}"]
        code, out = run_as("nobody", root, config)
    finally:
        listener.close()
    assert code == 1
    assert re.search(rf"^FAIL +must not connect to 127.0.0.1:{open_port}: connected", out, re.M)
    assert re.search(rf"^PASS +must not connect to 127.0.0.1:{closed_port}", out, re.M)


@needs_accounts
def test_running_as_root_is_refused_because_it_proves_nothing(world):
    root, config = world
    cfg = root / "cfg-root.json"
    cfg.write_text(json.dumps(config))
    done = subprocess.run(["/usr/bin/python3", str(root / "check_isolation.py"), str(cfg)], capture_output=True, text=True)
    assert done.returncode == 1 and "proves nothing" in done.stdout


def test_an_unknown_key_or_an_empty_config_is_an_error_not_a_pass(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_isolation", EXAMPLE / "check_isolation.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.run({"must_not_reed": ["/x"]}, False)[0][0] == "ERROR"
    assert mod.run({}, False)[0][0] == "ERROR"
    assert mod.run({"must_not_read": "/etc/shadow"}, False)[0][0] == "ERROR"
