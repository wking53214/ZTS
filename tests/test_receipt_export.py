"""HttpsReceiptExporter: one bounded HTTPS POST per receipt, and a resend that leaves no gap."""

from __future__ import annotations

import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from issuer_kit import make_tls
from tsa_kit import Tsa
from zts.anchor_tsa import Rfc3161Anchor
from zts.receipts import HttpsReceiptExporter, ReceiptExportError


class Destination:
    """An https receiver that records what it was sent. ``mode`` picks how it behaves."""

    def __init__(self, tmp_path):
        self.got, self.mode, self.auth = [], "ok", []
        ca, cert, key = make_tls(tmp_path)
        self.ca = ca
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                data = self.rfile.read(int(self.headers["Content-Length"]))
                outer.auth.append(self.headers.get("Authorization"))
                if outer.mode == "slow":
                    time.sleep(2)
                if outer.mode == "down":
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                outer.got.append(json.loads(data))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        self.server = HTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(key))
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://localhost:{self.server.server_port}/receipts"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def client_context(self):
        return ssl.create_default_context(cafile=str(self.ca))

    def close(self):
        self.server.shutdown()


@pytest.fixture
def dest(tmp_path):
    d = Destination(tmp_path)
    yield d
    d.close()


def anchor_with(tmp_path, tsa, exporter, **kw):
    return Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "receipts.jsonl", min_interval=0,
                         on_receipt=exporter, **kw)


def test_every_receipt_reaches_the_destination_as_the_json_the_anchor_wrote(tmp_path, dest):
    tsa = Tsa(tmp_path)
    try:
        exporter = HttpsReceiptExporter(dest.url, ssl_context=dest.client_context(),
                                        headers={"Authorization": "Bearer t0ken"})
        anchor = anchor_with(tmp_path, tsa, exporter)
        for seq in range(3):
            anchor.publish(seq, f"head-{seq}")
        assert [r["sequence"] for r in dest.got] == [0, 1, 2]
        assert dest.got == anchor.receipts()
        assert set(dest.auth) == {"Bearer t0ken"}
        assert anchor.export_failures == 0 and anchor.last_export_error is None
    finally:
        tsa.close()


def test_a_destination_that_refuses_is_reported_and_never_stops_the_stamp(tmp_path, dest):
    tsa = Tsa(tmp_path)
    try:
        dest.mode = "down"
        exporter = HttpsReceiptExporter(dest.url, ssl_context=dest.client_context())
        anchor = anchor_with(tmp_path, tsa, exporter)
        anchor.publish(1, "head-1")
        assert anchor.published == 1 and anchor.export_failures == 1
        assert anchor.last_export_error == "ReceiptExportError"
        with pytest.raises(ReceiptExportError, match="answered 503"):
            exporter({"sequence": 9})
    finally:
        tsa.close()


def test_a_slow_destination_is_cut_at_the_deadline(tmp_path, dest):
    dest.mode = "slow"
    exporter = HttpsReceiptExporter(dest.url, timeout=0.5, ssl_context=dest.client_context())
    start = time.monotonic()
    with pytest.raises(ReceiptExportError, match="did not answer within"):
        exporter({"sequence": 1})
    assert time.monotonic() - start < 2.0


def test_resend_after_an_outage_sends_the_missing_receipts_oldest_first_with_no_gap(tmp_path, dest):
    tsa = Tsa(tmp_path)
    try:
        exporter = HttpsReceiptExporter(dest.url, ssl_context=dest.client_context())
        anchor = anchor_with(tmp_path, tsa, exporter)
        anchor.publish(0, "head-0")
        dest.mode = "down"
        anchor.publish(1, "head-1")
        anchor.publish(2, "head-2")
        assert [r["sequence"] for r in dest.got] == [0] and anchor.export_failures == 2
        dest.mode = "ok"
        assert exporter.resend(anchor, after_sequence=0) == 2
        assert [r["sequence"] for r in dest.got] == [0, 1, 2]
    finally:
        tsa.close()


def test_resend_stops_at_the_first_failure_so_the_destination_has_no_gap(tmp_path, dest):
    tsa = Tsa(tmp_path)
    try:
        anchor = anchor_with(tmp_path, tsa, None)
        for seq in range(3):
            anchor.publish(seq, f"head-{seq}")
        calls = []

        class Flaky(HttpsReceiptExporter):
            def __call__(self, receipt):
                calls.append(receipt["sequence"])
                if receipt["sequence"] == 1:
                    raise ReceiptExportError("down")

        with pytest.raises(ReceiptExportError):
            Flaky(dest.url).resend(anchor)
        assert calls == [0, 1], "it must not skip ahead to 2"
    finally:
        tsa.close()


@pytest.mark.parametrize("url", ["http://x.example/", "ftp://x.example/", "x.example", "", None, 5])
def test_only_an_https_url_is_accepted(url):
    with pytest.raises(ValueError, match="https"):
        HttpsReceiptExporter(url)


@pytest.mark.parametrize("name", ["Content-Type", "content-length", "Host"])
def test_headers_cannot_override_the_framing(name):
    with pytest.raises(ValueError, match="may not set"):
        HttpsReceiptExporter("https://x.example/", headers={name: "x"})


def test_the_url_never_appears_in_an_error(tmp_path):
    exporter = HttpsReceiptExporter("https://127.0.0.1:1/secret-path?token=abc", timeout=1)
    with pytest.raises(ReceiptExportError) as info:
        exporter({"sequence": 1})
    assert "secret-path" not in str(info.value) and "token" not in str(info.value)
