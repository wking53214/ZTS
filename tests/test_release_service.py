"""examples/release_service: the protocol, the caller check, the socket and the reference delivery.

The service is exercised twice: `process()` directly (every refusal, without a socket) and over a real Unix socket, including from a
different operating-system account where this runs as root. The delivery module is tested against a local TLS receiver.
"""

from __future__ import annotations

import base64
import json
import os
import pwd
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from issuer_kit import make_tls
from release_kit import SCOPE, TEXT, build, static_grant

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "release_service"


@pytest.fixture(autouse=True)
def _path(monkeypatch):
    monkeypatch.syspath_prepend(str(EXAMPLE))
    for name in ("service", "delivery", "assemble_example", "client"):
        sys.modules.pop(name, None)


def mods():
    import delivery
    import service
    return service, delivery


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def identity_fields(identity):
    level = getattr(identity.trust_level, "value", identity.trust_level)
    return {"tenant_id": identity.tenant_id, "subject_id": identity.subject_id, "roles": list(identity.roles),
            "trust_level": level, "authentication_method": identity.authentication_method, "verified": identity.verified,
            "signature": identity.signature}


def body(s, **over):
    req = {"release_id": "rel-1", "scope": SCOPE, "text": TEXT, "grant": b64(static_grant(s)),
           "identity": identity_fields(s.identity)}
    req.update(over)
    return json.dumps(req).encode()


def policy(service, uid, tenants=("tenant-1",), subjects=("subject-1",)):
    return service.CallerPolicy.from_config({str(uid): {"tenants": list(tenants), "subjects": list(subjects)}})


@pytest.fixture
def world(tmp_path):
    service, _ = mods()
    s = build(tmp_path)
    svc = service.ReleaseService(s.tower, policy(service, 1001), require_ready=False)
    return s, svc, service


# ------------------------------------------------------------------------- one request


def test_a_valid_request_from_an_allowed_account_is_released_once(world):
    s, svc, _ = world
    answer = svc.process(1001, body(s))
    assert answer["released"] is True and answer["authorized"] is True and answer["reason_code"] == "VERIFIED_ACTION_BOUND_GRANT"
    assert len(s.sink.calls) == 1 and s.sink.calls[0][0] == TEXT


def test_the_answer_carries_four_fields_and_nothing_that_was_sent(world):
    s, svc, _ = world
    answer = svc.process(1001, body(s))
    assert set(answer) == {"released", "outcome", "reason_code", "authorized"}
    text = json.dumps(answer)
    assert TEXT not in text and "sig-1" not in text and s.identity.subject_id not in text


def test_an_account_that_is_not_listed_is_refused_and_the_grant_is_not_spent(world):
    s, svc, _ = world
    request = body(s)
    assert svc.process(4242, request) == {"released": False, "outcome": "refused", "reason_code": "CALLER_NOT_ALLOWED",
                                          "authorized": False}
    assert s.sink.calls == []
    assert svc.process(1001, request)["released"] is True, "the refused attempt must not have used the grant up"


@pytest.mark.parametrize("tenants,subjects,ok", [
    (("tenant-1",), ("subject-1",), True), (("*",), ("*",), True), (("tenant-1",), ("someone-else",), False),
    (("other-tenant",), ("subject-1",), False), (("tenant-1",), ("*",), True), (("*",), ("someone-else",), False),
])
def test_an_account_may_present_only_the_tenants_and_subjects_listed_for_it(tmp_path, tenants, subjects, ok):
    service, _ = mods()
    s = build(tmp_path)
    svc = service.ReleaseService(s.tower, policy(service, 7, tenants, subjects), require_ready=False)
    assert (svc.process(7, body(s))["released"]) is ok
    assert bool(s.sink.calls) is ok


@pytest.mark.parametrize("make", [
    lambda s: b"{ nope", lambda s: b"[]", lambda s: b"null", lambda s: b"\xff\xfe",
    lambda s: b'{"release_id":"a","release_id":"b"}',
    lambda s: json.dumps({**json.loads(body(s)), "extra": 1}).encode(),
    lambda s: json.dumps({k: v for k, v in json.loads(body(s)).items() if k != "grant"}).encode(),
    lambda s: body(s, release_id=""), lambda s: body(s, release_id=5), lambda s: body(s, text=""), lambda s: body(s, scope=None),
    lambda s: body(s, grant="not base64!!"), lambda s: body(s, grant=""), lambda s: body(s, grant=b64(b"x" * 9000)),
    lambda s: body(s, identity={**identity_fields(s.identity), "verified": "true"}),
    lambda s: body(s, identity={**identity_fields(s.identity), "roles": "reader"}),
    lambda s: body(s, identity={**identity_fields(s.identity), "roles": [1, 2]}),
    lambda s: body(s, identity={**identity_fields(s.identity), "extra": 1}),
    lambda s: body(s, identity={k: v for k, v in identity_fields(s.identity).items() if k != "signature"}),
    lambda s: body(s, identity="alice"),
])
def test_a_malformed_request_is_refused_before_the_tower_is_asked(world, make):
    s, svc, _ = world
    asked = []
    original = s.tower.enforce
    s.tower.enforce = lambda *a, **k: (asked.append(1), original(*a, **k))[1]
    answer = svc.process(1001, make(s))
    assert answer["outcome"] == "refused" and answer["reason_code"] == "BAD_REQUEST" and asked == [] and s.sink.calls == []


def test_a_trust_level_cns_does_not_know_is_refused_not_a_crash(world):
    s, svc, _ = world
    bad = body(s, identity={**identity_fields(s.identity), "trust_level": "godlike"})
    assert svc.process(1001, bad)["reason_code"] == "IDENTITY_INVALID" and s.sink.calls == []


def test_a_request_over_the_size_limit_is_refused(tmp_path):
    service, _ = mods()
    s = build(tmp_path)
    svc = service.ReleaseService(s.tower, policy(service, 1), max_request_bytes=1000, require_ready=False)
    assert svc.process(1, body(s, text="x" * 2000))["reason_code"] == "TOO_LARGE"


def test_changed_text_with_the_old_grant_is_denied_by_the_tower(world):
    s, svc, _ = world
    answer = svc.process(1001, body(s, text=TEXT + " and a secret"))
    assert answer["released"] is False and answer["outcome"] != "refused" and s.sink.calls == []


def test_a_different_subject_than_the_grant_was_issued_for_is_denied(tmp_path):
    service, _ = mods()
    s = build(tmp_path)
    svc = service.ReleaseService(s.tower, policy(service, 1, subjects=("*",)), require_ready=False)
    swapped = {**identity_fields(s.identity), "subject_id": "mallory"}
    answer = svc.process(1, body(s, identity=swapped))
    assert answer["released"] is False and s.sink.calls == []


def test_the_same_grant_a_second_time_is_a_replay(world):
    s, svc, _ = world
    request = body(s)
    assert svc.process(1001, request)["released"] is True
    again = svc.process(1001, request)
    assert again["released"] is False and again["reason_code"] == "GRANT_REPLAYED" and len(s.sink.calls) == 1


def test_an_unexpected_failure_tells_the_caller_nothing_about_it(world):
    s, svc, _ = world

    def boom(*a, **k):
        raise RuntimeError("the database password is hunter2")

    s.tower.enforce = boom
    answer = svc.process(1001, body(s))
    assert answer == {"released": False, "outcome": "service_error", "reason_code": "SERVICE_ERROR", "authorized": False}
    assert "hunter2" not in json.dumps(answer)


# ------------------------------------------------------------------------- readiness at start


def test_the_service_refuses_to_start_on_a_tower_that_is_not_ready_or_has_no_gate(tmp_path):
    service, _ = mods()
    s = build(tmp_path)
    with pytest.raises(RuntimeError, match="not ready"):
        service.ReleaseService(s.tower, policy(service, 1))  # the test tower is not a production tower

    class NoGate:
        release_gate = None

        def enforce(self, *a, **k):
            raise AssertionError

    with pytest.raises(RuntimeError, match="no Enforcer release gate"):
        service.ReleaseService(NoGate(), policy(service, 1))
    with pytest.raises(TypeError):
        service.ReleaseService(object(), policy(service, 1))


# ------------------------------------------------------------------------------ the policy


@pytest.mark.parametrize("bad", [
    {}, None, [], {"abc": {"tenants": ["t"], "subjects": ["s"]}}, {"1": {"tenants": ["t"]}}, {"1": {"tenants": [], "subjects": ["s"]}},
    {"1": {"tenants": ["t"], "subjects": [""]}}, {"1": {"tenants": "t", "subjects": ["s"]}},
    {"1": {"tenants": ["t"], "subjects": ["s"], "extra": 1}}, {"1": "everything"},
])
def test_a_caller_list_that_is_empty_or_unclear_is_refused_at_start(bad):
    service, _ = mods()
    with pytest.raises(ValueError):
        service.CallerPolicy.from_config(bad)


# ------------------------------------------------------------------------------ the socket


@pytest.fixture
def running(tmp_path):
    """A service listening on a real Unix socket, called by this process's own account."""
    service, _ = mods()
    s = build(tmp_path)
    run_dir = Path(tempfile.mkdtemp(dir="/tmp", prefix="zts-svc-"))
    os.chmod(run_dir, 0o755)
    path = str(run_dir / "release.sock")
    svc = service.ReleaseService(s.tower, policy(service, os.getuid()), require_ready=False, read_timeout=1.5, max_concurrent=2)
    svc.bind(path, mode=0o660)
    thread = threading.Thread(target=svc.serve_forever, daemon=True)
    thread.start()
    yield s, svc, path, service
    svc.stop()
    thread.join(3)
    shutil.rmtree(run_dir, ignore_errors=True)


def call(path, raw, *, newline=True, timeout=5, peer_may_hang_up=False):
    with socket.socket(socket.AF_UNIX) as c:
        c.settimeout(timeout)
        c.connect(path)
        return exchange(c, raw, newline=newline, peer_may_hang_up=peer_may_hang_up)


def exchange(c, raw, *, newline=True, peer_may_hang_up=False):
    """Send one request on a connected socket and read the one-line answer.

    peer_may_hang_up: the service answers BUSY and closes without reading, so a send that lands after
    that close fails with a broken pipe while the answer is still there to read. Only a caller that
    expects that answer (the BUSY probe) sets it; every other call still fails loudly on a broken pipe.
    """
    try:
        c.sendall(raw + (b"\n" if newline else b""))
    except BrokenPipeError:
        if not peer_may_hang_up:
            raise
    data = b""
    while not data.endswith(b"\n"):
        chunk = c.recv(65536)
        if not chunk:
            break
        data += chunk
    return json.loads(data) if data else None


def wait_for_hang_up(c, timeout=5):
    """Block until the far end of a Unix socket has closed (Linux POLLRDHUP), however slow the machine."""
    poller = select.poll()
    poller.register(c, select.POLLRDHUP | select.POLLHUP)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for _, events in poller.poll(50):
            if events & (select.POLLRDHUP | select.POLLHUP):
                return
    raise AssertionError("the service did not hang up")


def test_a_request_over_the_real_socket_is_released_and_the_caller_is_read_from_the_kernel(running):
    s, _, path, _ = running
    assert call(path, body(s))["released"] is True and len(s.sink.calls) == 1


def test_an_account_not_in_the_list_is_refused_over_the_socket(tmp_path):
    service, _ = mods()
    s = build(tmp_path)
    run_dir = Path(tempfile.mkdtemp(dir="/tmp", prefix="zts-svc-"))
    os.chmod(run_dir, 0o755)
    svc = service.ReleaseService(s.tower, policy(service, os.getuid() + 1), require_ready=False)
    svc.bind(str(run_dir / "r.sock"))
    threading.Thread(target=svc.serve_forever, daemon=True).start()
    try:
        assert call(str(run_dir / "r.sock"), body(s))["reason_code"] == "CALLER_NOT_ALLOWED" and s.sink.calls == []
    finally:
        svc.stop()
        shutil.rmtree(run_dir, ignore_errors=True)


def test_a_request_with_no_newline_and_no_more_data_times_out_and_the_service_carries_on(running):
    s, _, path, _ = running
    with socket.socket(socket.AF_UNIX) as stuck:
        stuck.settimeout(5)  # so a service with no read timeout fails this test quickly instead of hanging it
        stuck.connect(path)
        stuck.sendall(b'{"half a request')
        time.sleep(2.0)  # past the read timeout: the service dropped it
        assert stuck.recv(10) == b"", "the service closes a connection that stalls instead of waiting forever"
    assert call(path, body(s))["released"] is True


def test_a_request_that_never_ends_is_cut_off_at_the_size_limit(running):
    _, _, path, _ = running
    assert call(path, b"x" * (300 * 1024), newline=False)["reason_code"] == "TOO_LARGE"


def test_when_every_slot_is_busy_a_new_caller_is_told_so_immediately(running):
    _, _, path, _ = running
    holders = []
    try:
        for _ in range(2):  # max_concurrent is 2
            c = socket.socket(socket.AF_UNIX)
            c.connect(path)
            holders.append(c)
        # Wait for the service to have taken both slots, however loaded the machine is. The probe is an empty request, which can never
        # release anything: it is answered BAD_REQUEST while a slot is free and BUSY once none is.
        deadline, answer = time.monotonic() + 5, None
        while time.monotonic() < deadline:
            answer = call(path, b"{}", timeout=2, peer_may_hang_up=True)
            if answer["reason_code"] == "BUSY":
                break
            time.sleep(0.05)
        assert answer["reason_code"] == "BUSY", answer
    finally:
        for c in holders:
            c.close()


def test_a_busy_answer_is_read_even_when_the_service_hangs_up_before_the_probe_sends(running):
    # Regression: CI failed with BrokenPipeError in the BUSY probe. Here that order is forced, not hoped for:
    # each probe connection sends only after the service has answered BUSY and closed it.
    _, _, path, _ = running

    def hung_up_busy_connection():
        c = socket.socket(socket.AF_UNIX)
        c.settimeout(2)
        c.connect(path)
        wait_for_hang_up(c)
        if b'"BUSY"' in c.recv(65536, socket.MSG_PEEK):
            return c
        c.close()  # a slot had come free, so this connection was served instead
        return None

    for _attempt in range(5):  # a fresh pair of slot holders each time, in case a slow machine let them time out
        holders = []
        try:
            for _ in range(2):  # max_concurrent is 2
                c = socket.socket(socket.AF_UNIX)
                c.connect(path)
                holders.append(c)
            deadline = time.monotonic() + 5
            while call(path, b"{}", timeout=2, peer_may_hang_up=True)["reason_code"] != "BUSY":
                assert time.monotonic() < deadline, "the service never filled both slots"
                time.sleep(0.05)
            old, new = hung_up_busy_connection(), hung_up_busy_connection()
            if old is None or new is None:
                for c in (old, new):
                    if c is not None:
                        c.close()
                continue
            with old, new:
                with pytest.raises(BrokenPipeError):
                    exchange(old, b"{}")  # the probe as it was: crashes although the answer is waiting
                assert exchange(new, b"{}", peer_may_hang_up=True)["reason_code"] == "BUSY"
            return
        finally:
            for c in holders:
                c.close()
    pytest.fail("could not hold both slots long enough to probe them")


@pytest.mark.skipif(os.getuid() != 0 or not pwd.getpwnam("nobody"), reason="needs root and the nobody account")
def test_another_operating_system_account_is_identified_by_the_kernel_and_by_the_socket_mode(tmp_path):
    service, _ = mods()
    s = build(tmp_path)
    nobody = pwd.getpwnam("nobody").pw_uid
    run_dir = Path(tempfile.mkdtemp(dir="/tmp", prefix="zts-svc-"))
    os.chmod(run_dir, 0o755)
    path = str(run_dir / "r.sock")
    client = run_dir / "client.py"
    client.write_text("import socket,sys\nc=socket.socket(socket.AF_UNIX)\nc.connect(sys.argv[1])\nc.sendall(open(sys.argv[2],'rb').read()+b'\\n')\n"
                      "d=b''\nwhile not d.endswith(b'\\n'):\n    x=c.recv(65536)\n    if not x: break\n    d+=x\nprint(d.decode())\n")
    req = run_dir / "req.json"
    req.write_bytes(body(s))
    os.chmod(client, 0o644)
    os.chmod(req, 0o644)

    def as_nobody():
        done = subprocess.run(["runuser", "-u", "nobody", "--", "/usr/bin/python3", str(client), path, str(req)],
                              capture_output=True, text=True, cwd="/")
        return done.returncode, done.stdout + done.stderr

    svc = service.ReleaseService(s.tower, policy(service, nobody), require_ready=False)
    svc.bind(path, mode=0o660)  # owner root only
    threading.Thread(target=svc.serve_forever, daemon=True).start()
    try:
        code, out = as_nobody()
        assert code != 0 and "Permission denied" in out, "the socket file's own mode is the first lock"
        os.chmod(path, 0o666)
        code, out = as_nobody()
        assert code == 0 and json.loads(out)["released"] is True, out
    finally:
        svc.stop()
        shutil.rmtree(run_dir, ignore_errors=True)


def test_a_socket_is_not_created_in_an_unsafe_place(tmp_path):
    service, _ = mods()
    s = build(tmp_path)
    svc = service.ReleaseService(s.tower, policy(service, 1), require_ready=False)
    open_dir = Path(tempfile.mkdtemp(dir="/tmp", prefix="zts-open-"))
    os.chmod(open_dir, 0o777)
    try:
        with pytest.raises(RuntimeError, match="writable by group or others"):
            svc.bind(str(open_dir / "r.sock"))
        safe = Path(tempfile.mkdtemp(dir="/tmp", prefix="zts-safe-"))
        os.chmod(safe, 0o755)
        (safe / "file").write_text("x")
        with pytest.raises(RuntimeError, match="not a socket"):
            svc.bind(str(safe / "file"))
        stale = socket.socket(socket.AF_UNIX)
        stale.bind(str(safe / "stale.sock"))
        stale.close()  # a socket file nobody listens on
        svc.bind(str(safe / "stale.sock"))
        assert (safe / "stale.sock").exists()
        other = service.ReleaseService(s.tower, policy(service, 1), require_ready=False)
        live = socket.socket(socket.AF_UNIX)
        live.bind(str(safe / "live.sock"))
        live.listen(1)
        try:
            with pytest.raises(RuntimeError, match="in use"):
                other.bind(str(safe / "live.sock"))
        finally:
            live.close()
    finally:
        svc.stop()  # it did bind stale.sock; stop() closes that listening socket
        shutil.rmtree(open_dir, ignore_errors=True)


def _resource_warnings(action):
    """Run action, collect every ResourceWarning it causes (a leaked file or socket is reported when collected)."""
    import gc
    import warnings
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        action()
        gc.collect()
    return [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)]


def test_reading_the_credential_closes_the_file(tmp_path):
    # P10: read_credential used a bare open().read(), leaving the credential file open for the garbage collector.
    _, delivery = mods()
    cred = tmp_path / "delivery.cred"
    cred.write_text("a-long-enough-bearer-token\n")
    os.chmod(cred, 0o600)
    got = []
    assert _resource_warnings(lambda: got.append(delivery.read_credential(str(cred)))) == []
    assert got == ["a-long-enough-bearer-token"]


def test_a_bind_that_fails_part_way_closes_its_socket(tmp_path):
    # P10: a bind that failed after the socket was created (here: an unknown group) left that socket open.
    service, _ = mods()
    s = build(tmp_path)
    svc = service.ReleaseService(s.tower, policy(service, 1), require_ready=False)
    safe = Path(tempfile.mkdtemp(dir="/tmp", prefix="zts-safe-"))
    os.chmod(safe, 0o755)
    try:
        def failing_bind():
            with pytest.raises(LookupError):
                svc.bind(str(safe / "r.sock"), group="zts-no-such-group-p10")
        assert _resource_warnings(failing_bind) == []
        assert svc._server is None, "a failed bind must not leave a half-made listener behind"
    finally:
        shutil.rmtree(safe, ignore_errors=True)


# ----------------------------------------------------------------------------- configuration


def write_config(tmp_path, mode=0o644, **over):
    cfg = {"socket_path": "/run/zts/release.sock", "callers": {"1": {"tenants": ["t"], "subjects": ["s"]}},
           "tower_factory": "assemble_example:build_tower"}
    cfg.update(over)
    p = tmp_path / "svc.json"
    p.write_text(json.dumps(cfg))
    os.chmod(p, mode)
    return str(p)


def test_a_good_config_loads_and_the_example_config_is_good():
    service, _ = mods()
    assert service.load_config(str(EXAMPLE / "release-service.example.json"))["socket_path"] == "/run/zts/release.sock"


@pytest.mark.parametrize("over,message", [
    ({"extra": 1}, "unknown"), ({"socket_path": "relative.sock"}, "absolute"), ({"tower_factory": "nocolon"}, "module:function"),
    ({"tower_factory": 5}, "module:function"),
])
def test_a_config_with_unknown_or_malformed_values_is_refused(tmp_path, over, message):
    service, _ = mods()
    with pytest.raises(ValueError, match=message):
        service.load_config(write_config(tmp_path, **over))


def test_a_config_missing_a_required_key_or_writable_by_others_is_refused(tmp_path):
    service, _ = mods()
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"socket_path": "/run/x.sock"}))
    os.chmod(p, 0o644)
    with pytest.raises(ValueError, match="missing"):
        service.load_config(str(p))
    with pytest.raises(ValueError, match="writable"):
        service.load_config(write_config(tmp_path, mode=0o666))


def test_the_example_tower_factory_is_importable_and_has_the_expected_shape():
    pytest.importorskip("enforcer")
    pytest.importorskip("cryptography")
    pytest.importorskip("psycopg")
    import assemble_example
    assert callable(assemble_example.build_tower)


# ---------------------------------------------------------------------- reference delivery


class Receiver:
    def __init__(self, tmp_path):
        self.seen, self.confirm_answer, self.status = [], b'{"held":true}', 200
        ca, cert, key = make_tls(tmp_path)
        self.ca = ca
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.seen.append((self.path, self.headers.get("Authorization"), data))
                answer = outer.confirm_answer if self.path.endswith("/confirm") else b"ok"
                self.send_response(outer.status)
                self.send_header("Content-Length", str(len(answer)))
                self.end_headers()
                self.wfile.write(answer)

        self.server = HTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://localhost:{self.server.server_port}/release"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def context(self):
        return ssl.create_default_context(cafile=str(self.ca))

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver(tmp_path):
    r = Receiver(tmp_path)
    cred = tmp_path / "delivery.cred"
    cred.write_text("a-long-enough-bearer-token\n")
    os.chmod(cred, 0o600)
    yield r, str(cred)
    r.close()


def test_delivery_posts_the_text_with_the_credential_and_confirmation_needs_an_exact_yes(receiver):
    r, cred = receiver
    _, delivery = mods()
    d = delivery.HttpsReceiver(r.url, cred, ssl_context=r.context())
    d.deliver("the text", {"algorithm": "x", "key_id": "k", "value": "v"})
    path, auth, data = r.seen[0]
    assert path == "/release" and auth == "Bearer a-long-enough-bearer-token" and data["output"] == "the text"
    assert d.confirm("rel-1", "ab" * 32) is True and r.seen[1][2] == {"release_id": "rel-1", "sha256": "ab" * 32}
    for answer in (b'{"held":false}', b'{"held":"true"}', b'{"held":true,"x":1}', b"yes", b"[]", b""):
        r.confirm_answer = answer
        assert d.confirm("rel-1", "ab" * 32) is False, answer


def test_a_receiver_that_refuses_or_is_down_is_a_failed_delivery_and_an_unconfirmed_one(receiver):
    r, cred = receiver
    _, delivery = mods()
    d = delivery.HttpsReceiver(r.url, cred, ssl_context=r.context())
    r.status = 503
    with pytest.raises(delivery.DeliveryError, match="answered 503"):
        d.deliver("x", {})
    assert d.confirm("rel-1", "00" * 32) is False
    down = delivery.HttpsReceiver("https://127.0.0.1:1/release", cred, timeout=1)
    with pytest.raises(delivery.DeliveryError):
        down.deliver("x", {})


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o604])
def test_a_credential_file_others_can_read_is_refused(receiver, mode):
    r, cred = receiver
    _, delivery = mods()
    os.chmod(cred, mode)
    with pytest.raises(delivery.DeliveryError, match="mode 600"):
        delivery.HttpsReceiver(r.url, cred, ssl_context=r.context()).deliver("x", {})
    assert r.seen == []


@pytest.mark.parametrize("content", ["", "short", "has spaces in the middle of it", "\n\n"])
def test_a_credential_that_is_not_a_usable_token_is_refused(receiver, content):
    r, cred = receiver
    _, delivery = mods()
    Path(cred).write_text(content)
    os.chmod(cred, 0o600)
    with pytest.raises(delivery.DeliveryError, match="usable token"):
        delivery.HttpsReceiver(r.url, cred, ssl_context=r.context()).deliver("x", {})


@pytest.mark.parametrize("url", ["http://x.example/release", "x.example", "https://x.example/release/", "", None])
def test_only_a_plain_https_url_is_accepted(url, tmp_path):
    _, delivery = mods()
    with pytest.raises(ValueError):
        delivery.HttpsReceiver(url, str(tmp_path / "c"))


def test_the_credential_and_url_never_appear_in_an_error(receiver):
    r, cred = receiver
    _, delivery = mods()
    d = delivery.HttpsReceiver("https://127.0.0.1:1/secret-path", cred, timeout=1)
    with pytest.raises(delivery.DeliveryError) as info:
        d.deliver("x", {})
    assert "secret-path" not in str(info.value) and "bearer-token" not in str(info.value)


# ------------------------------------------------------------------------------- the client


def test_the_example_client_gets_the_same_answer_as_a_raw_request(running):
    s, _, path, _ = running
    import client
    answer = client.release(path, release_id="rel-1", scope=SCOPE, text=TEXT, grant=static_grant(s),
                            identity=identity_fields(s.identity))
    assert answer["released"] is True and len(s.sink.calls) == 1
    again = client.release(path, release_id="rel-1", scope=SCOPE, text=TEXT, grant=static_grant(s),
                           identity=identity_fields(s.identity))
    assert again["released"] is False  # the tower refuses a second release with the same release id and grant


def test_the_client_refuses_an_answer_that_is_not_the_documented_shape(tmp_path):
    import client
    path = str(Path(tempfile.mkdtemp(dir="/tmp", prefix="zts-cl-")) / "x.sock")
    server = socket.socket(socket.AF_UNIX)
    server.bind(path)
    server.listen(1)

    def reply():
        conn, _ = server.accept()
        conn.recv(65536)
        conn.sendall(b'{"released": true}\n')
        conn.close()

    threading.Thread(target=reply, daemon=True).start()
    try:
        with pytest.raises(ValueError, match="unexpected"):
            client.release(path, release_id="r", scope="s", text="t", grant=b"g", identity={})
    finally:
        server.close()
