"""Reference delivery and confirmation for the release service: an HTTPS receiver that takes the text and says whether it holds it.

Replace these if your receiver speaks differently; the service only needs two callables (see assemble_example.py):

    deliver(output: str, signature: dict) -> None          raise on any failure
    confirm(release_id: str, sha256: str) -> bool           True only if the RECEIVER says it holds exactly that artifact

The tower treats a delivery that raises as unfinished and a confirmation that is not exactly True as unconfirmed, so a receiver that
is down, slow or wrong never produces a quiet "delivered". The credential is read from a root-controlled file on every call, never kept
in memory longer than the call, and never put in a URL or an error message.

Receiver contract (what this reference expects; yours may differ):
    POST <url>            {"output": str, "signature": {...}}                 -> 200
    POST <url>/confirm    {"release_id": str, "sha256": str}                  -> 200 {"held": true}
both with ``Authorization: Bearer <credential>``.
"""

from __future__ import annotations

import json
import os
import ssl

from zts._http import HttpFailure, bounded_post

MAX_RESPONSE = 4096


class DeliveryError(RuntimeError):
    """The receiver did not accept the delivery. The text is safe to log."""


def read_credential(path: str) -> str:
    """The bearer credential, refused unless the file is owned by the current user and closed to everyone else."""
    info = os.stat(path)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise DeliveryError("the credential file must be owned by this account and mode 600")
    token = open(path, encoding="utf-8").read().strip()
    if len(token) < 16 or not token.isprintable() or " " in token:
        raise DeliveryError("the credential file does not hold a usable token")
    return token


class HttpsReceiver:
    def __init__(self, url: str, credential_path: str, *, timeout: float = 10.0, ssl_context: ssl.SSLContext | None = None) -> None:
        if not isinstance(url, str) or not url.startswith("https://") or url.endswith("/"):
            raise ValueError("url must be an https URL without a trailing slash")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        self._url, self._cred, self._timeout, self._ctx = url, credential_path, float(timeout), ssl_context

    def _post(self, url: str, payload: dict) -> bytes:
        headers = {"Content-Type": "application/json", "Authorization": "Bearer " + read_credential(self._cred)}
        try:
            return bounded_post(url, json.dumps(payload, separators=(",", ":")).encode("utf-8"), self._timeout, self._ctx,
                                schemes=("https",), headers=headers, service="receiver", response_noun="response",
                                max_bytes=MAX_RESPONSE)
        except HttpFailure as exc:
            raise DeliveryError(str(exc)) from None

    def deliver(self, output: str, signature: dict) -> None:
        self._post(self._url, {"output": output, "signature": signature})

    def confirm(self, release_id: str, sha256: str) -> bool:
        try:
            answer = json.loads(self._post(self._url + "/confirm", {"release_id": release_id, "sha256": sha256}))
        except (DeliveryError, ValueError):
            return False
        return isinstance(answer, dict) and answer == {"held": True}
