"""The reference receiver for off-box receipts (examples/receipt_receiver/receiver.py).

The S3 code is tested against a stand-in client that records what it was asked, never against real S3.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from issuer_kit import make_tls
from tsa_kit import Tsa
from zts.anchor_tsa import Rfc3161Anchor
from zts.receipts import HttpsReceiptExporter

SCRIPT = Path(__file__).resolve().parents[1] / "examples" / "receipt_receiver" / "receiver.py"
spec = importlib.util.spec_from_file_location("receiver", SCRIPT)
rx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rx)

TOKEN = "t" * 40
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def receipt(seq=1, head="h", token=None):
    return {"gen_time": "2026-11-12T12:00:00+00:00", "head": head, "sequence": seq,
            "token": token or base64.b64encode(b"tok").decode()}


def post(r, body, headers=AUTH):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return r.handle(raw, headers)


@pytest.fixture
def receiver(tmp_path):
    return rx.Receiver(rx.LocalStore(str(tmp_path / "bucket")), TOKEN)


def test_a_receipt_is_stored_and_the_same_one_again_is_accepted(receiver):
    assert post(receiver, receipt()) == (200, "stored")
    assert post(receiver, receipt()) == (200, "already stored")


def test_a_different_receipt_for_a_stored_sequence_is_refused_and_the_first_is_kept(receiver, tmp_path):
    assert post(receiver, receipt(head="real"))[0] == 200
    assert post(receiver, receipt(head="forged"))[0] == 409
    stored = json.loads(rx.LocalStore(str(tmp_path / "bucket")).get("000000000001.json"))
    assert stored["head"] == "real"


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong" + "x" * 30}, {"Authorization": TOKEN},
                                     {"Authorization": f"Basic {TOKEN}"}, {"authorization": "Bearer "}])
def test_a_missing_or_wrong_token_is_refused_and_nothing_is_stored(receiver, tmp_path, headers):
    assert post(receiver, receipt(), headers)[0] == 401
    assert not (tmp_path / "bucket").exists() or list((tmp_path / "bucket").iterdir()) == []


def test_header_names_are_case_insensitive(receiver):
    assert post(receiver, receipt(), {"authorization": f"Bearer {TOKEN}"})[0] == 200


@pytest.mark.parametrize("body", [
    b"{ nope", b"[]", b"null", b'{"sequence":1}', b"\xff\xfe",
    json.dumps({**receipt(), "extra": 1}).encode(),
    json.dumps({**receipt(), "sequence": -1}).encode(),
    json.dumps({**receipt(), "sequence": True}).encode(),
    json.dumps({**receipt(), "sequence": "1"}).encode(),
    json.dumps({**receipt(), "sequence": 10**12}).encode(),
    json.dumps({**receipt(), "head": ""}).encode(),
    json.dumps({**receipt(), "head": "x" * 300}).encode(),
    json.dumps({**receipt(), "gen_time": "yesterday"}).encode(),
    json.dumps({**receipt(), "gen_time": "2026-11-12T12:00:00"}).encode(),
    json.dumps({**receipt(), "token": "not base64!!"}).encode(),
    b'{"gen_time":"2026-11-12T12:00:00+00:00","head":"h","sequence":1,"sequence":2,"token":"dG9r"}',
    b'{"gen_time":"2026-11-12T12:00:00+00:00","head":"h","sequence":NaN,"token":"dG9r"}',
])
def test_a_malformed_receipt_is_refused(receiver, body):
    assert post(receiver, body)[0] == 400


def test_an_oversized_body_is_refused(receiver):
    assert post(receiver, b" " * (rx.MAX_BODY + 1))[0] == 413


def test_a_short_token_is_refused_at_construction(tmp_path):
    with pytest.raises(ValueError, match="32 characters"):
        rx.Receiver(rx.LocalStore(str(tmp_path / "b")), "short")


def test_a_store_failure_is_a_500_not_a_stored(tmp_path):
    class Broken:
        def put_if_absent(self, key, data):
            raise OSError("disk")

        def get(self, key):
            raise OSError("disk")

    assert rx.Receiver(Broken(), TOKEN).handle(json.dumps(receipt()).encode(), AUTH)[0] == 500


# ------------------------------------------------------------------ with the real token check


def test_a_real_timestamp_token_is_accepted_and_a_forged_one_is_refused(tmp_path):
    tsa = Tsa(tmp_path)
    other = Tsa(tmp_path, "impostor")
    try:
        real = Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "a.jsonl", min_interval=0)
        forged = Rfc3161Anchor(other.url, [other.pem.read_bytes()], tmp_path / "b.jsonl", min_interval=0)
        real.publish(1, "head-1")
        forged.publish(2, "head-2")
        r = rx.Receiver(rx.LocalStore(str(tmp_path / "bucket")), TOKEN, verifier=rx.tsa_verifier([tsa.pem.read_bytes()]))
        assert post(r, real.receipts()[0]) == (200, "stored")
        assert post(r, forged.receipts()[0])[0] == 422
        swapped = dict(real.receipts()[0], head="another-head")
        assert post(r, swapped)[0] == 422
        assert [f.name for f in (tmp_path / "bucket").iterdir()] == ["000000000001.json"]
    finally:
        tsa.close()
        other.close()


# ------------------------------------------------------------------------- the S3 store


class ClientError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class FakeS3:
    """Records the requests and behaves like a bucket that refuses to overwrite."""

    def __init__(self):
        self.objects, self.calls = {}, []

    def put_object(self, **kw):
        self.calls.append(kw)
        if kw["Key"] in self.objects:
            raise ClientError("PreconditionFailed")
        self.objects[kw["Key"]] = kw["Body"]

    def get_object(self, Bucket, Key):
        import io
        return {"Body": io.BytesIO(self.objects[Key])}


def test_s3_writes_are_conditional_and_locked_in_compliance_mode():
    s3 = FakeS3()
    store = rx.S3Store(s3, "audit-bucket", retain_days=400)
    assert store.put_if_absent("000000000001.json", b"{}") is True
    call = s3.calls[0]
    assert call["IfNoneMatch"] == "*" and call["ObjectLockMode"] == "COMPLIANCE"
    assert call["Bucket"] == "audit-bucket" and call["Key"] == "receipts/000000000001.json"
    days = (call["ObjectLockRetainUntilDate"] - datetime.now(timezone.utc)) / timedelta(days=1)
    assert 399 < days <= 400


def test_s3_reports_an_existing_key_as_not_written_and_other_errors_as_errors():
    s3 = FakeS3()
    store = rx.S3Store(s3, "b", retain_days=1)
    assert store.put_if_absent("k", b"1") is True
    assert store.put_if_absent("k", b"2") is False
    assert store.get("k") == b"1"

    class Denied(FakeS3):
        def put_object(self, **kw):
            raise ClientError("AccessDenied")

    with pytest.raises(ClientError):
        rx.S3Store(Denied(), "b", retain_days=1).put_if_absent("k", b"1")
    assert rx.Receiver(rx.S3Store(Denied(), "b", retain_days=1), TOKEN).handle(
        json.dumps(receipt()).encode(), AUTH)[0] == 500


@pytest.mark.parametrize("days", [0, -1, True, "30", None])
def test_retention_must_be_a_positive_whole_number_of_days(days):
    with pytest.raises(ValueError):
        rx.S3Store(FakeS3(), "b", retain_days=days)


def test_a_conflict_through_s3_is_a_409_and_a_resend_is_a_200():
    r = rx.Receiver(rx.S3Store(FakeS3(), "b", retain_days=30), TOKEN)
    assert post(r, receipt(head="a"))[0] == 200
    assert post(r, receipt(head="a"))[0] == 200
    assert post(r, receipt(head="b"))[0] == 409


# --------------------------------------------------- the real exporter talking to the real receiver


def test_the_zts_exporter_delivers_to_the_receiver_over_tls_including_a_resend(tmp_path):
    ca, cert, key = make_tls(tmp_path)
    r = rx.Receiver(rx.LocalStore(str(tmp_path / "bucket")), TOKEN)
    seen = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            status, text = r.handle(body, dict(self.headers))
            seen.append(status)
            self.send_response(status)
            self.send_header("Content-Length", str(len(text)))
            self.end_headers()
            self.wfile.write(text.encode())

    server = HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tsa = Tsa(tmp_path)
    try:
        exporter = HttpsReceiptExporter(f"https://localhost:{server.server_port}/", headers=AUTH,
                                        ssl_context=ssl.create_default_context(cafile=str(ca)))
        anchor = Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "r.jsonl", min_interval=0,
                               on_receipt=exporter)
        for seq in range(3):
            anchor.publish(seq, f"head-{seq}")
        assert exporter.resend(anchor) == 3  # everything again: the receiver must call each one a repeat
        assert seen == [200] * 6
        assert len(list((tmp_path / "bucket").iterdir())) == 3
    finally:
        server.shutdown()
        tsa.close()


def test_the_lock_mode_is_compliance_by_default_and_governance_only_when_asked():
    for mode, expected in ((None, "COMPLIANCE"), ("GOVERNANCE", "GOVERNANCE")):
        s3 = FakeS3()
        store = rx.S3Store(s3, "b", retain_days=1) if mode is None else rx.S3Store(s3, "b", retain_days=1, mode=mode)
        store.put_if_absent("k", b"1")
        assert s3.calls[0]["ObjectLockMode"] == expected
    with pytest.raises(ValueError, match="COMPLIANCE or GOVERNANCE"):
        rx.S3Store(FakeS3(), "b", retain_days=1, mode="NONE")
