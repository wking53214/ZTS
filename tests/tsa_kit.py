"""TEST-ONLY RFC 3161 time-stamping authority, backed by OpenSSL's independent implementation.

The tokens are produced by `openssl ts -reply`, not by ZTS code, so the verifier is checked
against an implementation it shares no code with. This is NOT a public TSA: interop with a
real service is untested.

Skips when openssl or cryptography/asn1crypto is missing, unless ZTS_REQUIRE_TSA=1 (CI).
"""

from __future__ import annotations

import datetime as dt
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

REQUIRED = os.environ.get("ZTS_REQUIRE_TSA") == "1"


def _skip(reason):
    if REQUIRED:
        raise RuntimeError(f"ZTS_REQUIRE_TSA=1 but {reason}")
    pytest.skip(reason, allow_module_level=True)


try:
    import asn1crypto.tsp as tsp  # noqa: F401
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:
    _skip("cryptography and asn1crypto are required")
if not shutil.which("openssl"):
    _skip("openssl is not installed")
elif subprocess.run(["openssl", "ts", "-help"], capture_output=True).returncode not in (0, 1):
    _skip("this openssl has no `ts` command")


def make_tsa_cert(directory, name, *, kind="rsa", eku="critical", not_before=-1, not_after=2):
    """Write <name>.pem / <name>.key. eku: critical | noncritical | none | serverauth. Days relative to now."""
    key = rsa.generate_private_key(65537, 2048) if kind == "rsa" else ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now + dt.timedelta(days=not_before)).not_valid_after(now + dt.timedelta(days=not_after))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if eku in ("critical", "noncritical"):
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=(eku == "critical"))
    elif eku == "serverauth":
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
    cert = b.sign(key, hashes.SHA256())
    pem, keyf = directory / f"{name}.pem", directory / f"{name}.key"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return pem, keyf


def variant_cert(source_pem, key_pem, out_pem, **options):
    """A certificate with the SAME key, subject and serial as ``source_pem`` but different extensions or
    validity. Tokens signed with the key still match it by issuer and serial, so pinning this variant
    tests whether the verifier rejects an unfit certificate. (OpenSSL itself will not sign with one.)"""
    src = x509.load_pem_x509_certificate(source_pem.read_bytes())
    key = serialization.load_pem_private_key(key_pem.read_bytes(), None)
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(src.subject).issuer_name(src.issuer).public_key(key.public_key())
         .serial_number(src.serial_number)
         .not_valid_before(now + dt.timedelta(days=options.get("not_before", -1)))
         .not_valid_after(now + dt.timedelta(days=options.get("not_after", 2)))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    eku = options.get("eku", "critical")
    if eku in ("critical", "noncritical"):
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=(eku == "critical"))
    elif eku == "serverauth":
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
    out_pem.write_bytes(b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    return out_pem


def _config(directory, name, signer_digest):
    (directory / f"{name}.serial").write_text("01\n")
    path = directory / f"{name}.cnf"
    path.write_text(f"""[ tsa ]
default_tsa = c
[ c ]
dir = {directory}
serial = {directory}/{name}.serial
crypto_device = builtin
signer_cert = {directory}/{name}.pem
certs = {directory}/{name}.pem
signer_key = {directory}/{name}.key
signer_digest = {signer_digest}
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""")
    return path


class Tsa:
    """A local HTTP TSA. ``mode`` picks the behavior; ``name`` picks which key signs."""

    def __init__(self, directory, name="tsa", *, kind="rsa", signer_digest="sha256", **cert_options):
        self.dir, self.name, self.mode = directory, name, "normal"
        self.pem, self.key = make_tsa_cert(directory, name, kind=kind, **cert_options)
        self.cnf = _config(directory, name, signer_digest)
        self.requests = 0
        self.other: Tsa | None = None
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                query = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests += 1
                try:
                    code, body = outer.respond(query)
                except Exception:
                    code, body = 500, b"error"
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=lambda: self.httpd.serve_forever(poll_interval=0.02), daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/tsa"

    def _stamp(self, query: bytes, tsa: "Tsa | None" = None) -> bytes:
        tsa = tsa or self
        q = self.dir / f"{tsa.name}.q"
        q.write_bytes(query)
        out = self.dir / f"{tsa.name}.r"
        subprocess.run(["openssl", "ts", "-reply", "-config", str(tsa.cnf), "-queryfile", str(q), "-out", str(out)],
                       check=True, capture_output=True, timeout=30)
        return out.read_bytes()

    def respond(self, query: bytes):
        mode = self.mode
        if mode == "http500":
            return 500, b"nope"
        if mode == "garbage":
            return 200, b"this is not a timestamp response"
        if mode == "other-tsa":
            return 200, self._stamp(query, self.other)
        req = tsp.TimeStampReq.load(query)
        if mode == "wrong-digest":
            bad = tsp.TimeStampReq({"version": "v1", "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"}, "hashed_message": b"\x01" * 32},
                "nonce": req["nonce"].native, "cert_req": False})
            return 200, self._stamp(bad.dump())
        if mode == "wrong-nonce":
            bad = tsp.TimeStampReq({"version": "v1", "message_imprint": req["message_imprint"],
                                    "nonce": req["nonce"].native + 1, "cert_req": False})
            return 200, self._stamp(bad.dump())
        if mode == "no-nonce":
            bad = tsp.TimeStampReq({"version": "v1", "message_imprint": req["message_imprint"], "cert_req": False})
            return 200, self._stamp(bad.dump())
        if mode == "rejected":
            return 200, bytes.fromhex("3005300302" "0102")  # SEQUENCE { SEQUENCE { INTEGER 2 (rejection) } }
        response = self._stamp(query)
        if mode == "tamper-signature":
            raw = bytearray(response)
            raw[-8] ^= 0xFF  # inside the signature value
            return 200, bytes(raw)
        if mode == "truncated":
            return 200, response[: len(response) // 2]
        if mode == "huge":
            return 200, response + b"\x00" * 100_000
        return 200, response

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
