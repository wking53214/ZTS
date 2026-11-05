"""An external ledger anchor built on RFC 3161 trusted timestamps.

A timestamp authority (TSA) signs a hash together with the time it saw it. Anchoring the
ledger head with one gives evidence that the chain up to that head existed at that time,
signed by a party outside the ledger's writer. Anyone holding the token can later check it
against the TSA's certificate without trusting the machine that wrote the ledger.

What is verified. For every token this module checks, against a TSA signing certificate the
operator pinned: the token is a TimeStampToken whose content type is TSTInfo; the TSTInfo
imprint is the SHA-256 of ``(sequence, head)`` as defined by :func:`head_digest`; the nonce
matches (on publish); the signer is exactly a pinned certificate (the certificates inside
the token are ignored); the certificate allows time stamping (critical extended key usage)
and was valid at the stamped time; the signed attributes bind the content; and the signature
verifies with SHA-256, SHA-384 or SHA-512 over RSA PKCS#1 v1.5 or ECDSA. Anything else is
refused. There is no certificate chain building and no revocation check: pin the TSA's
signing certificate itself, and replace it when the TSA rotates.

What this does NOT give you, so nothing downstream claims more:

  * Rollback protection by itself. A TSA proves a head existed; it does not remember your
    ledger. The receipts file is local. An attacker who can rewrite both the ledger and the
    receipts can restore an older consistent pair. Copy receipts somewhere the writer cannot
    reach (an auditor, a WORM store). Whoever holds the latest token can prove how far the
    ledger had got.
  * Interoperability with any particular public TSA. It was tested against OpenSSL's
    independent RFC 3161 implementation, not against a public service.
  * Timeliness. To keep a release from waiting on the network for every ledger entry,
    publishing is lazy: a head is stamped when ``min_interval`` seconds have passed, or when
    ``flush()`` is called. Entries after the last stamped head are not covered yet, and
    ``verify_anchored`` cannot see them removed. So the uncovered tail is bounded: once more than
    ``max_unanchored_entries`` entries, or more than ``max_unanchored_age`` seconds, are waiting for
    a stamp, :meth:`behind` says so and the tower refuses new releases until the TSA catches up.
  * Custody. The receipts file sits beside the ledger. ``on_receipt`` hands every receipt to a
    function you supply the moment it is durable, so a copy can be kept somewhere the ledger's
    writer cannot rewrite. ZTS cannot tell whether that place is out of the writer's reach.

Needs ``pip install zts[tsa]``.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import secrets
import ssl
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .ledger_store import LedgerCorruptionError, LedgerStoreError, _Locked, _open, _read_from, _write_all

HEAD_DOMAIN = b"zts-ledger-head-v1\x00"
MAX_RESPONSE_BYTES = 65536
_HASHES = ("sha256", "sha384", "sha512")


class TimestampError(RuntimeError):
    """The TSA could not be asked, or its answer cannot be trusted."""


def head_digest(sequence: int, head: str) -> bytes:
    """SHA-256 of the domain-separated ``{"head", "sequence"}`` document: what the TSA stamps."""
    doc = json.dumps({"head": head, "sequence": sequence}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(HEAD_DOMAIN + doc.encode("utf-8")).digest()


def _libs() -> Any:
    try:
        from asn1crypto import cms, tsp
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    except ImportError as exc:
        raise TimestampError("asn1crypto and cryptography are required for the RFC 3161 anchor") from exc
    return type("L", (), dict(cms=cms, tsp=tsp, x509=x509, hashes=hashes, ec=ec, padding=padding, rsa=rsa))


_RESPONSE: Any = None


def _response_class() -> Any:
    """RFC 3161's TimeStampResp, with the token optional as the RFC says it is.

    asn1crypto's own class requires the token, so a plain rejection (status only) would fail to
    parse and be reported as "malformed" instead of "refused".
    """
    global _RESPONSE
    if _RESPONSE is None:
        from asn1crypto import cms, core, tsp

        class TimeStampResponse(core.Sequence):
            _fields = [("status", tsp.PKIStatusInfo), ("time_stamp_token", cms.ContentInfo, {"optional": True})]

        _RESPONSE = TimeStampResponse
    return _RESPONSE


def build_request(digest: bytes, nonce: int) -> bytes:
    lib = _libs()
    return lib.tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
        "nonce": nonce,
        "cert_req": False,
    }).dump()


def load_pinned(certificates: list[bytes | str]) -> list[Any]:
    """Parse the pinned TSA signing certificates (PEM or DER)."""
    lib = _libs()
    out = []
    for item in certificates:
        raw = item.encode() if isinstance(item, str) else item
        try:
            out.append(lib.x509.load_pem_x509_certificate(raw) if raw.lstrip().startswith(b"-----")
                       else lib.x509.load_der_x509_certificate(raw))
        except ValueError:
            raise TimestampError("a pinned TSA certificate cannot be parsed") from None
    if not out:
        raise TimestampError("at least one pinned TSA certificate is required")
    return out


def verify_token(token_der: bytes, digest: bytes, pinned: list[Any], *, nonce: int | None = None) -> datetime:
    """Verify a TimeStampToken for ``digest`` against pinned certificates. Returns the stamped time."""
    lib = _libs()
    try:
        token = lib.cms.ContentInfo.load(token_der)
        if token["content_type"].native != "signed_data":
            raise TimestampError("not a signed-data token")
        signed = token["content"]
        encap = signed["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            raise TimestampError("the token does not carry TSTInfo")
        content = encap["content"].contents  # the exact signed octets, for the digest check
        info = lib.tsp.TSTInfo.load(content)
        if info["version"].native != "v1":
            raise TimestampError("unsupported TSTInfo version")
        imprint = info["message_imprint"]
        if imprint["hash_algorithm"]["algorithm"].native != "sha256" or imprint["hashed_message"].native != digest:
            raise TimestampError("the stamped hash is not the hash of this ledger head")
        if nonce is not None and info["nonce"].native != nonce:
            raise TimestampError("the nonce does not match the request")
        stamped = info["gen_time"].native
        if stamped.tzinfo is None:
            raise TimestampError("the stamp time has no timezone")
        stamped = stamped.astimezone(timezone.utc)

        infos = signed["signer_infos"]
        if len(infos) != 1:
            raise TimestampError("exactly one signer is required")
        signer = infos[0]
        cert = _find_signer(signer["sid"], pinned, lib)
        _check_certificate(cert, stamped, lib)

        attrs = signer["signed_attrs"]
        if attrs.native is None:
            raise TimestampError("signed attributes are required")
        digest_name = signer["digest_algorithm"]["algorithm"].native
        if digest_name not in _HASHES:
            raise TimestampError("unsupported digest algorithm")
        values = {a["type"].native: a["values"][0].native for a in attrs}
        if values.get("content_type") != "tst_info":
            raise TimestampError("the signed content type is not TSTInfo")
        if values.get("message_digest") != hashlib.new(digest_name, content).digest():
            raise TimestampError("the signed message digest does not match the content")
        _verify_signature(cert, signer, attrs.untag().dump(), digest_name, lib)
        return stamped
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"the token is malformed: {type(exc).__name__}") from None


def _find_signer(sid: Any, pinned: list[Any], lib: Any) -> Any:
    """The pinned certificate the signer identifies, by issuer and serial or by key identifier."""
    from asn1crypto import x509 as a1
    from cryptography.hazmat.primitives.serialization import Encoding

    for cert in pinned:
        if sid.name == "issuer_and_serial_number":
            ours = a1.Certificate.load(cert.public_bytes(Encoding.DER))
            if (sid.chosen["serial_number"].native == cert.serial_number
                    and sid.chosen["issuer"].dump() == ours.issuer.dump()):
                return cert
        elif sid.name == "subject_key_identifier":
            try:
                ski = cert.extensions.get_extension_for_class(lib.x509.SubjectKeyIdentifier).value.digest
            except lib.x509.ExtensionNotFound:
                continue
            if ski == sid.native:
                return cert
    raise TimestampError("the token was not signed by a pinned TSA certificate")


def _check_certificate(cert: Any, stamped: datetime, lib: Any) -> None:
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if not (not_before <= stamped <= not_after):
        raise TimestampError("the TSA certificate was not valid at the stamped time")
    try:
        eku = cert.extensions.get_extension_for_class(lib.x509.ExtendedKeyUsage)
    except lib.x509.ExtensionNotFound:
        raise TimestampError("the TSA certificate has no extended key usage") from None
    if lib.x509.oid.ExtendedKeyUsageOID.TIME_STAMPING not in eku.value or not eku.critical:
        raise TimestampError("the TSA certificate is not critically restricted to time stamping")


def _verify_signature(cert: Any, signer: Any, data: bytes, digest_name: str, lib: Any) -> None:
    signature = signer["signature"].native
    algo = signer["signature_algorithm"].signature_algo
    hash_cls = {"sha256": lib.hashes.SHA256, "sha384": lib.hashes.SHA384, "sha512": lib.hashes.SHA512}[digest_name]()
    key = cert.public_key()
    try:
        if algo == "rsassa_pkcs1v15" and isinstance(key, lib.rsa.RSAPublicKey):
            key.verify(signature, data, lib.padding.PKCS1v15(), hash_cls)
        elif algo == "ecdsa" and isinstance(key, lib.ec.EllipticCurvePublicKey):
            key.verify(signature, data, lib.ec.ECDSA(hash_cls))
        else:
            raise TimestampError("unsupported signature algorithm")
    except TimestampError:
        raise
    except Exception:
        raise TimestampError("the TSA signature does not verify") from None


def http_post(url: str, body: bytes, timeout: float, context: ssl.SSLContext | None = None) -> bytes:
    """POST a TimeStampReq. No redirects, a size cap and a hard timeout. HTTP is fine: the token is signed."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise TimestampError("the TSA URL must be http or https")
    cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    kwargs: dict[str, Any] = {"timeout": timeout}
    if parts.scheme == "https":
        kwargs["context"] = context or ssl.create_default_context()
    conn = cls(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), **kwargs)
    try:
        conn.request("POST", parts.path or "/", body=body, headers={
            "Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"})
        response = conn.getresponse()
        if response.status != 200:
            raise TimestampError(f"the TSA answered {response.status}")
        data = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise TimestampError(f"the TSA could not be reached: {type(exc).__name__}") from None
    finally:
        conn.close()
    if len(data) > MAX_RESPONSE_BYTES:
        raise TimestampError("the TSA response is too large")
    return data


class Rfc3161Anchor:
    """A ``LedgerAnchor`` that stamps ledger heads with a TSA and keeps the tokens as receipts."""

    durable = True

    def __init__(
        self,
        tsa_url: str,
        tsa_certificates: list[bytes | str],
        receipts_path: str | Path,
        *,
        timeout: float = 10.0,
        min_interval: float = 30.0,
        ssl_context: ssl.SSLContext | None = None,
        transport: Callable[[str, bytes, float], bytes] | None = None,
        clock: Callable[[], datetime] | None = None,
        max_clock_skew: timedelta = timedelta(minutes=5),
        max_unanchored_entries: int | None = 500,
        max_unanchored_age: float | None = 300.0,
        on_receipt: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not isinstance(timeout, (int, float)) or timeout <= 0 or min_interval < 0:
            raise ValueError("timeout must be positive and min_interval cannot be negative")
        if max_unanchored_entries is not None and (
                not isinstance(max_unanchored_entries, int) or isinstance(max_unanchored_entries, bool)
                or max_unanchored_entries < 1):
            raise ValueError("max_unanchored_entries must be a positive integer, or None for no bound")
        if max_unanchored_age is not None and (
                not isinstance(max_unanchored_age, (int, float)) or isinstance(max_unanchored_age, bool)
                or max_unanchored_age <= 0):
            raise ValueError("max_unanchored_age must be a positive number of seconds, or None for no bound")
        if on_receipt is not None and not callable(on_receipt):
            raise TypeError("on_receipt must be callable")
        self._url = tsa_url
        self._pinned = load_pinned(tsa_certificates)
        self._path = Path(receipts_path)
        self._fd = _open(self._path)
        self._timeout, self._min_interval = float(timeout), float(min_interval)
        self._transport = transport or (lambda url, body, t: http_post(url, body, t, ssl_context))
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._skew = max_clock_skew
        self._lock = threading.Lock()
        self._pending: tuple[int, str] | None = None
        self._last_publish = float("-inf")  # never published: the first head is stamped at once
        #: The last error from a lazy publish or a flush, for health checks. None when the last one worked.
        self.last_error: str | None = None
        self.failures = 0
        #: Receipts written by this object. Zero means the TSA has never answered it.
        self.published = 0
        self._max_entries, self._max_age = max_unanchored_entries, max_unanchored_age
        self._on_receipt = on_receipt
        self.export_failures = 0
        self.last_export_error: str | None = None
        self._last_attempt = float("-inf")
        self._pending_since: float | None = None  # when the oldest unstamped entry was first seen
        try:
            latest = self.latest()
        except Exception:  # an unreadable receipts file is reported by verify_anchored, not here
            latest = None
        #: Sequence of the newest stamped entry, or -1.
        self._stamped_seq = latest[0] if latest else -1

    # ------------------------------------------------------------- the anchor seam

    def publish(self, sequence: int, head: str) -> None:
        """Record that ``head`` should be anchored. Stamps now only if ``min_interval`` has passed.

        A failed lazy stamp never blocks the ledger write that called it; it is counted in
        ``failures`` and reported by ``last_error``. Use :meth:`flush` where a failure must be seen.
        """
        with self._lock:
            self._pending = (sequence, head)
            if self._pending_since is None:
                self._pending_since = time.monotonic()
            if time.monotonic() - self._last_publish < self._min_interval:
                return
        try:
            self.flush()
        except TimestampError:
            # Recorded by flush(). Back off: while the TSA is down, every ledger write must not
            # pay its timeout again. An explicit flush() always tries.
            with self._lock:
                self._last_publish = time.monotonic()

    def flush(self) -> bool:
        """Stamp the newest pending head now. Raises TimestampError if it cannot be stamped.

        Returns False if nothing was pending.
        """
        with self._lock:
            if self._pending is None:
                return False
            sequence, head = self._pending
            self._last_attempt = time.monotonic()
        try:
            digest = head_digest(sequence, head)
            nonce = secrets.randbits(63) + 1
            raw = self._transport(self._url, build_request(digest, nonce), self._timeout)
            token_der, stamped = self._accept(raw, digest, nonce)
            receipt = self._append(sequence, head, stamped, token_der)
        except TimestampError as exc:
            with self._lock:
                self.failures += 1
                self.last_error = str(exc)
            raise
        except Exception as exc:
            with self._lock:
                self.failures += 1
                self.last_error = f"unexpected: {type(exc).__name__}"
            raise TimestampError("the head could not be stamped") from None
        with self._lock:
            self.published += 1
            self._stamped_seq = max(self._stamped_seq, sequence)
            if self._pending == (sequence, head):
                self._pending, self._pending_since = None, None
            else:
                self._pending_since = time.monotonic()  # a newer head arrived while this one was out
            self._last_publish = time.monotonic()
            self.last_error = None
        self._export(receipt)
        return True

    # ------------------------------------------------------------- backlog and custody

    def behind(self, head_sequence: int) -> str | None:
        """None if the stamped head is close enough to ``head_sequence`` (the ledger's newest entry).

        Otherwise ``"entries"`` or ``"age"``: too many entries, or entries that have waited too long,
        are not covered by any timestamp, so removing them would go unnoticed.
        """
        with self._lock:
            waiting = head_sequence - self._stamped_seq
            if waiting <= 0:
                self._pending_since = None
                return None
            if self._pending_since is None:  # found at startup or after a gap: count from now, never from never
                self._pending_since = time.monotonic()
            if self._max_entries is not None and waiting > self._max_entries:
                return "entries"
            if self._max_age is not None and time.monotonic() - self._pending_since > self._max_age:
                return "age"
            return None

    def catch_up(self, head_sequence: int, head: str) -> None:
        """Try to stamp ``head`` now, unless a try was made less than ``min_interval`` ago.

        Without this a tower that stopped releasing because the anchor fell behind would never write
        another entry, so nothing would ever ask the TSA again. Never raises.
        """
        with self._lock:
            if time.monotonic() - self._last_attempt < self._min_interval:
                return
            if self._pending is None or self._pending[0] < head_sequence:
                self._pending = (head_sequence, head)
        try:
            self.flush()
        except TimestampError:
            pass  # recorded by flush(); the caller asks behind() again

    def receipts(self) -> list[dict[str, Any]]:
        """Every stored receipt, as written. Not re-verified here: use :meth:`verify_all`. For re-export."""
        return self._read()

    def _export(self, receipt: dict[str, Any]) -> None:
        if self._on_receipt is None:
            return
        try:
            self._on_receipt(dict(receipt))
            with self._lock:
                self.last_export_error = None
        except Exception as exc:  # the receipt is already durable here; a failed copy is reported, never fatal
            with self._lock:
                self.export_failures += 1
                self.last_export_error = f"{type(exc).__name__}"

    def latest(self) -> tuple[int, str] | None:
        """The newest receipt, re-verified against the pinned certificates. None if there are none."""
        receipts = self._read()
        if not receipts:
            return None
        sequence, head, _ = self._verified(receipts[-1])
        return sequence, head

    def verify_all(self) -> list[tuple[int, str, datetime]]:
        """Re-verify every receipt. Raises LedgerCorruptionError on the first bad one."""
        return [self._verified(r) for r in self._read()]

    def describe(self) -> dict[str, Any]:
        return {"kind": "rfc3161", "url": self._url, "pinned_certificates": len(self._pinned),
                "min_interval": self._min_interval, "failures": self.failures,
                "max_unanchored_entries": self._max_entries, "max_unanchored_age": self._max_age,
                "exports_receipts": self._on_receipt is not None, "export_failures": self.export_failures}

    def close(self) -> None:
        if self._fd >= 0:
            import os

            os.close(self._fd)
            self._fd = -1

    # ----------------------------------------------------------------- internals

    def _accept(self, raw: bytes, digest: bytes, nonce: int) -> tuple[bytes, datetime]:
        try:
            resp = _response_class().load(raw)
            status = resp["status"]["status"].native
            if status not in ("granted", "granted_with_mods"):
                raise TimestampError(f"the TSA refused the request ({status})")
            token_der = resp["time_stamp_token"].dump()
        except TimestampError:
            raise
        except Exception:
            raise TimestampError("the TSA response is malformed") from None
        stamped = verify_token(token_der, digest, self._pinned, nonce=nonce)
        now = self._clock().astimezone(timezone.utc)
        if abs(now - stamped) > self._skew:
            raise TimestampError("the stamped time is too far from this machine's clock")
        return token_der, stamped

    def _append(self, sequence: int, head: str, stamped: datetime, token_der: bytes) -> dict[str, Any]:
        receipt = {"gen_time": stamped.isoformat(), "head": head, "sequence": sequence,
                   "token": base64.b64encode(token_der).decode("ascii")}
        line = (json.dumps(receipt, sort_keys=True) + "\n").encode()
        with _Locked(self._fd):
            try:
                import os

                _write_all(self._fd, line)
                os.fsync(self._fd)
            except OSError as exc:
                raise TimestampError("the receipt could not be written durably") from exc
        return receipt

    def _read(self) -> list[dict[str, Any]]:
        with _Locked(self._fd):
            data = _read_from(self._fd, 0)
        if data and not data.endswith(b"\n"):
            data = data[: data.rfind(b"\n") + 1]  # an unfinished final line was never acknowledged
        out = []
        for line in data.splitlines():
            try:
                rec = json.loads(line)
                if set(rec) != {"gen_time", "head", "sequence", "token"}:
                    raise ValueError
                out.append(rec)
            except ValueError:
                raise LedgerCorruptionError("the receipts file holds a line that does not parse") from None
        return out

    def _verified(self, rec: dict[str, Any]) -> tuple[int, str, datetime]:
        try:
            token = base64.b64decode(rec["token"], validate=True)
            stamped = verify_token(token, head_digest(rec["sequence"], rec["head"]), self._pinned)
        except (TimestampError, ValueError, TypeError, KeyError) as exc:
            raise LedgerCorruptionError(f"a receipt does not verify: {exc}") from None
        return rec["sequence"], rec["head"], stamped


__all__ = ["Rfc3161Anchor", "TimestampError", "build_request", "head_digest", "http_post",
           "load_pinned", "verify_token", "LedgerStoreError"]
