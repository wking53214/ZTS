"""Phase 2 audit, L3: the status and timestamp clients have ONE deadline for the whole exchange.

The audit's finding: `timeout` limited each wait, not the exchange. A server that sent one byte
every 0.4 s kept a 1 s timeout from ever firing; the call was still blocked 12 s later and an
abandoned release thread stayed blocked with it. Now a watchdog closes the socket at the deadline.

The servers here are fixtures that misbehave on purpose.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time

import pytest

from issuer_kit import IssuerKey, make_tls, trust_doc
from release_kit import Clock  # noqa: F401  (skips this module when Enforcer is not installed)
from zts.anchor_tsa import TimestampError, http_post
from zts.status import HttpStatusRevalidator, StatusUnavailable, https_post
from zts.trust import TrustRoot

DEADLINE = 0.8
SLACK = 1.5  # scheduling slack on a loaded CI machine; the point is "about 1 s", not "about 12 s"


class Misbehaving:
    """A server that accepts one connection and behaves badly in the chosen way."""

    def __init__(self, behaviour: str, *, tls_dir=None, interval: float = 0.25) -> None:
        self.behaviour, self.interval = behaviour, interval
        self.sent = 0
        self.client_gone = threading.Event()
        self._stop = threading.Event()
        self.ca = None
        ctx = None
        if tls_dir is not None:
            self.ca, cert, pkey = make_tls(tls_dir)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(pkey))
        self._ctx = ctx
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.port = self._srv.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def client_context(self):
        return ssl.create_default_context(cafile=str(self.ca))

    def close(self) -> None:
        self._stop.set()
        self._srv.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                self._srv.settimeout(0.2)
                raw, _ = self._srv.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw) -> None:
        try:
            if self.behaviour == "stall":  # never speaks: a TLS client waits for the server's hello
                raw.settimeout(0.2)
                while not self._stop.is_set():
                    try:
                        if raw.recv(4096) == b"":
                            break
                    except socket.timeout:
                        continue
                self.client_gone.set()
                return
            conn = self._ctx.wrap_socket(raw, server_side=True) if self._ctx else raw
            data = b""
            while b"\r\n\r\n" not in data:
                data += conn.recv(4096)
            head, _, rest = data.partition(b"\r\n\r\n")  # read the whole request, or closing resets the connection
            need = int([h for h in head.split(b"\r\n") if h.lower().startswith(b"content-length")][0].split(b":")[1])
            while len(rest) < need:
                rest += conn.recv(4096)
            if self.behaviour == "fast":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                return
            if self.behaviour == "drip_body":
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n")
            else:  # drip_headers: the status line, then header bytes forever, never the blank line
                conn.sendall(b"HTTP/1.1 200 OK\r\n")
            while not self._stop.is_set():
                conn.sendall(b"A" if self.behaviour == "drip_body" else b"X: y\r\n")
                self.sent += 1
                time.sleep(self.interval)
        except (OSError, ssl.SSLError):
            self.client_gone.set()  # our send or recv failed: the client closed the connection


def timed(fn):
    start = time.monotonic()
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        return exc, time.monotonic() - start
    return None, time.monotonic() - start


@pytest.mark.parametrize("behaviour", ["drip_body", "drip_headers", "stall"])
def test_the_status_client_gives_up_at_its_deadline_however_the_server_stalls(tmp_path, behaviour):
    srv = Misbehaving(behaviour, tls_dir=tmp_path)
    try:
        err, took = timed(lambda: https_post(f"https://localhost:{srv.port}/v1/status", b"{}", DEADLINE,
                                              srv.client_context()))
        assert isinstance(err, StatusUnavailable) and "did not answer within" in str(err), err
        assert DEADLINE - 0.1 <= took <= DEADLINE + SLACK, took
        assert srv.client_gone.wait(3), "the connection is closed, not left open"
    finally:
        srv.close()


@pytest.mark.parametrize("behaviour", ["drip_body", "drip_headers", "stall"])
def test_the_timestamp_client_gives_up_at_its_deadline_however_the_server_stalls(behaviour):
    srv = Misbehaving(behaviour)
    try:
        err, took = timed(lambda: http_post(f"http://127.0.0.1:{srv.port}/", b"q", DEADLINE))
        assert isinstance(err, TimestampError) and "did not answer within" in str(err), err
        assert DEADLINE - 0.1 <= took <= DEADLINE + SLACK, took
        assert srv.client_gone.wait(3)
    finally:
        srv.close()


def test_a_dripped_body_is_never_returned_as_if_it_were_an_answer(tmp_path):
    """When the watchdog closes the socket, a blocked read returns what it had. That is a fragment."""
    srv = Misbehaving("drip_body", tls_dir=tmp_path, interval=0.05)  # many bytes arrive before the deadline
    try:
        err, _ = timed(lambda: https_post(f"https://localhost:{srv.port}/", b"{}", DEADLINE, srv.client_context()))
        assert isinstance(err, StatusUnavailable) and srv.sent > 5
    finally:
        srv.close()


def test_a_prompt_answer_still_comes_back_whole(tmp_path):
    secure = Misbehaving("fast", tls_dir=tmp_path)
    plain = Misbehaving("fast")
    try:
        assert https_post(f"https://localhost:{secure.port}/", b"{}", 5, secure.client_context()) == b"ok"
        assert http_post(f"http://127.0.0.1:{plain.port}/", b"q", 5) == b"ok"
    finally:
        secure.close()
        plain.close()


def test_the_revalidator_inherits_the_deadline(tmp_path):
    from types import SimpleNamespace

    srv = Misbehaving("drip_body", tls_dir=tmp_path)
    clock = Clock()
    root = TrustRoot.from_dict(trust_doc(IssuerKey("issuer-a", "status").entry(clock)))
    rv = HttpStatusRevalidator(f"https://localhost:{srv.port}", root, timeout=DEADLINE,
                               ssl_context=srv.client_context(), clock=clock)
    try:
        err, took = timed(lambda: rv.revalidate(SimpleNamespace(envelope_sha256="0" * 64, policy_version="p"),
                                                SimpleNamespace(issuer_id="issuer-a", nonce="n")))
        assert isinstance(err, StatusUnavailable) and took <= DEADLINE + SLACK, (err, took)
    finally:
        srv.close()


def test_the_existing_refusals_are_unchanged():
    with pytest.raises(StatusUnavailable, match="must be https"):
        https_post("http://example.test/", b"", 1)
    with pytest.raises(TimestampError, match="must be http or https"):
        http_post("ftp://example.test/", b"", 1)
    with pytest.raises(StatusUnavailable, match="could not be reached"):
        https_post("https://127.0.0.1:1/", b"", 1)
