"""Reference receiver for ZTS timestamp receipts, writing to a locked (write-once) AWS S3 bucket.

This is an EXAMPLE you deploy in a separate AWS account from the releasing host. It is not part of the zts package, and the
S3 code in it has been tested only against a stand-in client, never against real S3 (see README.md).

What it guarantees, in order of importance:

1. The releasing host holds one bearer token for this endpoint and no AWS credentials. It can add receipts. It cannot read,
   change or delete anything in the bucket.
2. A receipt is stored once. The same receipt again is accepted (the exporter resends after an outage). A DIFFERENT receipt
   for a sequence already stored is refused with 409 and nothing is written: that is either a bug or an attack, and the
   operator should be told (log it, alarm on 409).
3. With a verifier configured, a receipt whose timestamp token does not verify against the pinned authority certificate is
   refused (422) and nothing is written, so a compromised host cannot fill the audit copy with junk.
4. The bucket's own Object Lock, not this code, is what makes stored receipts permanent.

Request: POST a JSON receipt (the dict ZTS's anchor writes: gen_time, head, sequence, token) with
``Authorization: Bearer <token>``. Answers: 200 stored or already stored; 400 malformed; 401 bad or missing token;
409 conflicting receipt; 413 too large; 422 token does not verify; 500 storage failed.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

MAX_BODY = 16384
MAX_HEAD = 256
MAX_TOKEN = 12000
FIELDS = frozenset({"gen_time", "head", "sequence", "token"})


class Store(Protocol):
    def put_if_absent(self, key: str, data: bytes) -> bool:
        """Write ``data`` at ``key`` only if nothing is there. True if written, False if the key already existed."""

    def get(self, key: str) -> bytes:
        """The bytes stored at ``key``."""


class LocalStore:
    """A folder store for tests and local trials. Not locked: a real deployment uses S3Store."""

    def __init__(self, directory: str) -> None:
        self._dir = directory
        os.makedirs(directory, exist_ok=True)

    def _path(self, key: str) -> str:
        return os.path.join(self._dir, key.replace("/", "__"))

    def put_if_absent(self, key: str, data: bytes) -> bool:
        try:
            fd = os.open(self._path(key), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        return True

    def get(self, key: str) -> bytes:
        with open(self._path(key), "rb") as f:
            return f.read()


class S3Store:
    """Write-once receipts in an S3 bucket that has Object Lock enabled.

    Each object is written with a conditional create (``If-None-Match: *``), so S3 itself refuses to overwrite, and with
    a COMPLIANCE-mode retention date, so nobody (the account root included) can delete or overwrite it until then.
    ``client`` is a boto3 S3 client; pass a stand-in in tests.
    """

    def __init__(self, client: Any, bucket: str, *, retain_days: int, prefix: str = "receipts/",
                 mode: str = "COMPLIANCE") -> None:
        if not isinstance(retain_days, int) or isinstance(retain_days, bool) or retain_days < 1:
            raise ValueError("retain_days must be a positive whole number")
        if mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise ValueError("mode must be COMPLIANCE or GOVERNANCE")
        # COMPLIANCE cannot be shortened or removed by anyone, ever. GOVERNANCE can be bypassed by a user with a special
        # permission: use it for a trial, and switch to COMPLIANCE once the retention period is decided.
        self._s3, self._bucket, self._days, self._prefix, self._mode = client, bucket, retain_days, prefix, mode

    def put_if_absent(self, key: str, data: bytes) -> bool:
        try:
            self._s3.put_object(
                Bucket=self._bucket, Key=self._prefix + key, Body=data, ContentType="application/json",
                IfNoneMatch="*", ObjectLockMode=self._mode,
                ObjectLockRetainUntilDate=datetime.now(timezone.utc) + timedelta(days=self._days))
        except Exception as exc:  # botocore ClientError: the code says whether the key already existed
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("PreconditionFailed", "ConditionalRequestConflict"):
                return False
            raise
        return True

    def get(self, key: str) -> bytes:
        return self._s3.get_object(Bucket=self._bucket, Key=self._prefix + key)["Body"].read()


def tsa_verifier(certificates: list[bytes | str]) -> Callable[[dict[str, Any]], None]:
    """A verifier that checks the receipt's timestamp token against the pinned authority certificate(s).

    Needs the zts package with the ``tsa`` extra. Raises (any exception) when the token does not verify.
    """
    from zts.anchor_tsa import head_digest, load_pinned, verify_token

    pinned = load_pinned(certificates)

    def verify(receipt: dict[str, Any]) -> None:
        token = base64.b64decode(receipt["token"], validate=True)
        verify_token(token, head_digest(receipt["sequence"], receipt["head"]), pinned)

    return verify


class Receiver:
    def __init__(self, store: Store, token: str, *, verifier: Callable[[dict[str, Any]], None] | None = None) -> None:
        if not isinstance(token, str) or len(token) < 32:
            raise ValueError("the bearer token must be a string of at least 32 characters")
        self._store, self._token, self._verifier = store, token.encode("utf-8"), verifier

    def handle(self, body: bytes, headers: dict[str, str]) -> tuple[int, str]:
        supplied = {k.lower(): v for k, v in headers.items()}.get("authorization", "")
        scheme, _, value = supplied.partition(" ")
        if scheme != "Bearer" or not hmac.compare_digest(value.encode("utf-8"), self._token):
            return 401, "unauthorized"
        if len(body) > MAX_BODY:
            return 413, "too large"
        receipt = _parse(body)
        if receipt is None:
            return 400, "malformed receipt"
        if self._verifier is not None:
            try:
                self._verifier(receipt)
            except Exception:
                return 422, "the timestamp token does not verify"
        key = f"{receipt['sequence']:012d}.json"
        data = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            if self._store.put_if_absent(key, data):
                return 200, "stored"
            if self._store.get(key) == data:
                return 200, "already stored"
        except Exception:
            return 500, "storage failed"
        return 409, "a different receipt is already stored for this sequence"


def _parse(body: bytes) -> dict[str, Any] | None:
    try:
        def no_repeats(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            found = dict(pairs)
            if len(found) != len(pairs):
                raise ValueError("repeated key")
            return found

        receipt = json.loads(body.decode("utf-8"), object_pairs_hook=no_repeats,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(receipt, dict) or set(receipt) != FIELDS:
        return None
    seq, head, when, token = receipt["sequence"], receipt["head"], receipt["gen_time"], receipt["token"]
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 <= seq < 10**12:
        return None
    if not all(isinstance(v, str) for v in (head, when, token)):
        return None
    if not 0 < len(head) <= MAX_HEAD or len(when) > 64 or not 0 < len(token) <= MAX_TOKEN:
        return None
    try:
        if datetime.fromisoformat(when).tzinfo is None:
            return None
        base64.b64decode(token, validate=True)
    except (ValueError, binascii.Error):
        return None
    return receipt


_RECEIVER: Receiver | None = None


def _receiver() -> Receiver:
    """Built once per warm Lambda container: a cold start pays for boto3 and the certificate load, later calls do not."""
    global _RECEIVER
    if _RECEIVER is None:
        import boto3  # imported here so the module loads, and its tests run, without boto3

        verifier = (tsa_verifier([os.environ["RECEIPT_TSA_CERT_PEM"]]) if os.environ.get("RECEIPT_TSA_CERT_PEM")
                    else None)
        _RECEIVER = Receiver(S3Store(boto3.client("s3"), os.environ["RECEIPT_BUCKET"],
                                     retain_days=int(os.environ["RECEIPT_RETAIN_DAYS"]),
                                     mode=os.environ.get("RECEIPT_LOCK_MODE", "COMPLIANCE")),
                             os.environ["RECEIPT_TOKEN"], verifier=verifier)
    return _RECEIVER


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """AWS Lambda entry point behind a function URL or API Gateway (payload format 2.0).

    Configuration, all from the environment: RECEIPT_BUCKET, RECEIPT_RETAIN_DAYS, RECEIPT_LOCK_MODE (default COMPLIANCE), RECEIPT_TOKEN (better: fetch it from
    Secrets Manager in your own wrapper) and, to verify tokens, RECEIPT_TSA_CERT_PEM.
    """
    raw = event.get("body") or ""
    body = base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode("utf-8")
    status, text = _receiver().handle(body, event.get("headers") or {})
    return {"statusCode": status, "headers": {"Content-Type": "text/plain"}, "body": text}
