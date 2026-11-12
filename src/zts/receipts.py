"""Hand timestamp receipts to a destination outside the ledger writer's reach.

``Rfc3161Anchor(on_receipt=...)`` calls its hook once per receipt, synchronously, after the receipt is durable on
local disk. A hook that fails is counted and reported (``receipt_export_live`` in readiness) and never stops a
release, but the anchor does not call it again for that receipt. That is why this module has two parts:

* :class:`HttpsReceiptExporter` is the hook. One bounded HTTPS POST per receipt, with a hard deadline.
* :meth:`HttpsReceiptExporter.resend` pushes every receipt from the local file after an outage.

What this does NOT do, and you must provide: a destination that the host running ZTS cannot rewrite or delete from
(append-only storage, a separate account, a write-once bucket). That separation is the whole point of the off-box
copy; an exporter cannot create it. The destination must treat a repeated ``sequence`` as the same receipt
(``resend`` repeats receipts by design) and should refuse a different receipt for a sequence it already holds.

Credentials go in ``headers`` (for example ``{"Authorization": "Bearer ..."}``), loaded from your secret store. They
are never put in the URL, and the URL is never included in an error message.
"""

from __future__ import annotations

import json
import ssl
from typing import Any

from ._http import HttpFailure, bounded_post

DEFAULT_TIMEOUT = 3.0  # the hook runs on the path of a ledger write: keep it short
MAX_RESPONSE_BYTES = 4096


class ReceiptExportError(RuntimeError):
    """The destination did not accept the receipt. The text is safe to show an operator."""


class HttpsReceiptExporter:
    """A callable for ``on_receipt``: POST each receipt as JSON to an https URL and require a 200."""

    def __init__(self, url: str, *, timeout: float = DEFAULT_TIMEOUT, headers: dict[str, str] | None = None,
                 ssl_context: ssl.SSLContext | None = None) -> None:
        if not isinstance(url, str) or not url.startswith("https://"):
            raise ValueError("the receipt destination must be an https URL")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        extra = dict(headers or {})
        if any(k.lower() in ("content-type", "content-length", "host") for k in extra):
            raise ValueError("headers may not set Content-Type, Content-Length or Host")
        self._url, self._timeout, self._context = url, float(timeout), ssl_context
        self._headers = {"Content-Type": "application/json", **extra}
        self.sent = 0

    def __call__(self, receipt: dict[str, Any]) -> None:
        body = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            bounded_post(self._url, body, self._timeout, self._context, schemes=("https",), headers=self._headers,
                         service="receipt destination", response_noun="response", max_bytes=MAX_RESPONSE_BYTES)
        except HttpFailure as exc:
            raise ReceiptExportError(str(exc)) from None
        self.sent += 1

    def resend(self, anchor: Any, *, after_sequence: int = -1) -> int:
        """Send every stored receipt with a sequence above ``after_sequence``, oldest first. Returns how many.

        Stops at the first failure and raises, so the destination never holds a gap followed by newer receipts.
        Use it after an outage (``receipt_export_live`` failing), with the newest sequence the destination holds.
        """
        sent = 0
        for receipt in anchor.receipts():
            if receipt["sequence"] > after_sequence:
                self(receipt)
                sent += 1
        return sent


__all__ = ["DEFAULT_TIMEOUT", "HttpsReceiptExporter", "ReceiptExportError"]
