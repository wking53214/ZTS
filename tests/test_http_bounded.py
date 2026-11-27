"""The shared bounded HTTP POST (src/zts/_http.py) on its own: it closes what it opens on every way out (P11)."""

from __future__ import annotations

import http.client
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cleanup_kit import resource_warnings
from zts._http import HttpFailure, bounded_post


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 (http.server's name)
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        status, body = self.server.answer  # type: ignore[attr-defined]
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(params=["http", "https"])
def server(request, tmp_path):
    make_tls = pytest.importorskip("issuer_kit").make_tls if request.param == "https" else None
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    srv.scheme, srv.client_context = request.param, None
    if make_tls is not None:  # the release path's callers use TLS; that is where the leak showed
        ca, cert, key = make_tls(tmp_path)
        server_side = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_side.load_cert_chain(cert, key)
        srv.socket = server_side.wrap_socket(srv.socket, server_side=True)
        srv.client_context = ssl.create_default_context(cafile=str(ca))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()
    t.join(5)


def post(srv, max_bytes=16):
    return bounded_post(f"{srv.scheme}://127.0.0.1:{srv.server_address[1]}/", b"{}", 5.0, srv.client_context,
                        schemes=("http", "https"),
                        headers={"Content-Type": "application/json"}, service="test service",
                        response_noun="test answer", max_bytes=max_bytes)


def test_a_good_answer_is_returned(server):
    server.answer = (200, b"ok")
    assert post(server) == b"ok"


@pytest.fixture
def responses(monkeypatch):
    """Every response object bounded_post receives, so a test can check it was closed."""
    seen = []
    real = http.client.HTTPConnection.getresponse

    def capture(self):
        r = real(self)
        seen.append(r)
        return r

    monkeypatch.setattr(http.client.HTTPConnection, "getresponse", capture)
    return seen


@pytest.mark.parametrize("answer,error", [((200, b"x" * 4096), "too large"), ((500, b"no"), "answered 500")],
                         ids=["too-large", "not-200"])
def test_a_refused_answer_is_closed_and_leaves_no_socket_open(server, responses, answer, error):
    # Before P11 the response was never closed. The server here answers HTTP/1.0, so http.client hands the
    # socket to the response, and closing the connection alone does not close it; the socket was left for the
    # garbage collector (the anchor tests showed it as "unclosed <socket.socket [closed] ...>").
    server.answer = answer

    def refused():
        with pytest.raises(HttpFailure, match=error):
            post(server)

    assert resource_warnings(refused) == []
    (response,) = responses
    assert response.isclosed(), "the response holds the socket; it must be closed on the way out"
