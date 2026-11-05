"""TEST-ONLY issuer. Throwaway Ed25519 keys; signs grants and status documents.

Written without importing anything from zts.trust, so a mistake in ZTS's encoding or
parsing cannot hide itself by being mirrored here. It is a fixture: it proves the
verifier against an independent encoder, not that any real issuer is sound.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta
from typing import Any

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class IssuerKey:
    def __init__(self, issuer_id: str = "issuer-a", role: str = "grant") -> None:
        self.private = Ed25519PrivateKey.generate()
        self.raw = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.kid = "ed25519-" + hashlib.sha256(self.raw).hexdigest()[:16]
        self.issuer_id = issuer_id
        self.role = role

    def entry(self, clock, *, before: float = -3600, after: float = 86400, status: str = "active") -> dict:
        now = clock()
        return {
            "kid": self.kid, "issuer_id": self.issuer_id, "role": self.role, "public_key": b64(self.raw),
            "not_before": (now + timedelta(seconds=before)).isoformat(),
            "not_after": (now + timedelta(seconds=after)).isoformat(), "status": status,
        }


def trust_doc(*entries: dict) -> dict:
    return {"version": 1, "keys": list(entries)}


def sign_blob(prefix: str, header: dict, body: dict, key: IssuerKey, *, raw_body: bytes | None = None) -> bytes:
    h = b64(json.dumps(header, sort_keys=True).encode())
    b = b64(raw_body if raw_body is not None else json.dumps(body, sort_keys=True).encode())
    sig = key.private.sign(prefix.encode() + b"\x00" + h.encode() + b"." + b.encode())
    return f"{prefix}.{h}.{b}.{b64(sig)}".encode()


GRANT_FIELDS = ("subject_id", "action", "target_type", "target_id", "evidence_sha256",
                "request_id", "parameters_sha256", "policy_version", "schema_version")


def grant_claims(envelope, clock, key: IssuerKey, *, lifetime: float = 60, issued_offset: float = 0,
                 nonce: str = "n-1", **overrides: Any) -> dict:
    issued = clock() + timedelta(seconds=issued_offset)
    claims = {f: getattr(envelope, f) for f in GRANT_FIELDS}
    claims.update(issuer_id=key.issuer_id, nonce=nonce, issued_at=issued.isoformat(),
                  expires_at=(issued + timedelta(seconds=lifetime)).isoformat())
    claims.update(overrides)
    return claims


def sign_grant(envelope, clock, key: IssuerKey, *, header: dict | None = None, **kw: Any) -> bytes:
    hdr = {"alg": "Ed25519", "kid": key.kid, "typ": "zts-grant-1"}
    hdr.update(header or {})
    return sign_blob("zts-grant-1", hdr, grant_claims(envelope, clock, key, **kw), key)


# ---------------------------------------------------------------- TLS and a status service

import datetime as _dt  # noqa: E402
import ipaddress  # noqa: E402
import json as _json  # noqa: E402
import ssl  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_tls(directory, hosts=("localhost", "127.0.0.1")):
    """A throwaway CA and a server certificate for ``hosts``. Returns (ca_pem, cert_pem, key_pem) paths."""
    now = _dt.datetime.now(_dt.timezone.utc)
    ca_key, srv_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("zts test ca")).issuer_name(_name("zts test ca"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - _dt.timedelta(hours=1)).not_valid_after(now + _dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    sans = [x509.IPAddress(ipaddress.ip_address(h)) if h[0].isdigit() else x509.DNSName(h) for h in hosts]
    cert = (x509.CertificateBuilder().subject_name(_name(hosts[0])).issuer_name(ca.subject)
            .public_key(srv_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(hours=1)).not_valid_after(now + _dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(srv_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_p, cert_p, key_p = (directory / n for n in ("ca.pem", "srv.pem", "srv.key"))
    ca_p.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(srv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    return ca_p, cert_p, key_p


class StatusService:
    """A TEST-ONLY HTTPS status service. ``mode`` picks how it answers; it signs with ``key``."""

    def __init__(self, directory, key: IssuerKey, clock, *, hosts=("localhost", "127.0.0.1")) -> None:
        self.key, self.clock, self.mode = key, clock, "current"
        self.requests: list[dict] = []
        self.last_response = b""
        self.other_key: IssuerKey | None = None
        self.role_key: IssuerKey | None = None
        self.cross_key: IssuerKey | None = None
        ca, cert, pkey = make_tls(directory, hosts)
        self.ca = ca
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silence
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                req = _json.loads(body)
                outer.requests.append(req)
                mode = outer.mode
                if mode == "http500":
                    return self._send(500, b"boom")
                if mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "https://localhost:1/elsewhere")
                    self.end_headers()
                    return
                if mode == "slow":
                    time.sleep(1.5)
                if mode == "huge":
                    return self._send(200, b"A" * 200_000)
                if mode == "garbage":
                    return self._send(200, b"not a signed document")
                if mode == "replay" and outer.last_response:
                    return self._send(200, outer.last_response)
                self._send(200, outer.answer(req, mode))

            def _send(self, code, data):
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert), str(pkey))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}"

    def client_context(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.ca))

    def answer(self, req: dict, mode: str) -> bytes:
        now = self.clock()
        status = {"revoked": "REVOKED", "unknown": "UNKNOWN", "unknown-status": "MAYBE"}.get(mode, "CURRENT")
        body = {"status": status, "challenge": req["challenge"], "envelope_sha256": req["envelope_sha256"],
                "policy_version": req["policy_version"], "issuer_id": req["issuer_id"], "nonce": req["nonce"],
                "checked_at": now.isoformat(), "valid_until": (now + _dt.timedelta(seconds=20)).isoformat()}
        if mode == "stale":
            body["checked_at"] = (now - _dt.timedelta(seconds=300)).isoformat()
            body["valid_until"] = (now - _dt.timedelta(seconds=280)).isoformat()
        elif mode == "bad-challenge":
            body["challenge"] = "AAAAAAAAAAAAAAAAAAAAAA"
        elif mode == "bad-envelope":
            body["envelope_sha256"] = "0" * 64
        elif mode == "bad-policy":
            body["policy_version"] = "other-policy"
        elif mode == "bad-nonce":
            body["nonce"] = "other"
        elif mode == "wrong-issuer":
            body["issuer_id"] = "issuer-z"
        elif mode == "naive-time":
            body["checked_at"] = "2026-11-04T12:00:00"
        elif mode == "extra-field":
            body["extra"] = 1
        signer = (self.other_key if mode == "unknown-key" else self.role_key if mode == "wrong-role"
                  else self.cross_key if mode == "cross-issuer" else self.key)
        hdr = {"alg": "Ed25519", "kid": signer.kid, "typ": "zts-status-1"}
        if mode == "wrong-alg":
            hdr["alg"] = "HS256"
        if mode == "unsigned":
            return b"zts-status-1." + b64(_json.dumps(hdr).encode()).encode() + b"." + \
                b64(_json.dumps(body).encode()).encode() + b"." + b64(b"\x00" * 64).encode()
        blob = sign_blob("zts-status-1", hdr, body, signer)
        if mode == "bad-sig":
            blob = blob[:-4] + (b"AAAA" if blob[-4:] != b"AAAA" else b"BBBB")
        self.last_response = blob
        return blob

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
