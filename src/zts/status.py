"""Online authorization-status revalidation against the grant issuer.

This is the status half of Enforcer's ``AuthorizationRevalidator`` seam. On every
release it asks the issuer, over HTTPS, whether this exact grant is still current, and
accepts only an answer signed by a ``status`` key in the trust root. There is no cache:
each release gets a live answer, so the freshness bound is Enforcer's (30 s by default)
and not a cache lifetime.

Protocol (``zts-status-1``). Request: ``POST <base_url>/v1/status``, JSON::

    {"challenge": "<b64u 16 random bytes>", "envelope_sha256": "...", "policy_version": "...",
     "issuer_id": "...", "nonce": "..."}

Response ``200``: ``zts-status-1 . b64u(header) . b64u(body) . b64u(signature)``, signed
like a grant (see :mod:`zts.trust`) by a key whose role is ``status`` and whose issuer is
the grant's issuer. The signed body::

    {"status": "CURRENT" | "REVOKED" | "UNKNOWN", "challenge": ..., "envelope_sha256": ...,
     "policy_version": ..., "issuer_id": ..., "nonce": ..., "checked_at": ..., "valid_until": ...}

The challenge, envelope digest, policy version, issuer and nonce must echo the request, so
a captured answer cannot be replayed for another grant or another moment.

Failure is denial. A network error, a timeout, a non-200 reply, a redirect, an oversized
or malformed body, a bad signature, an echo that does not match, an unknown status value:
each raises, and Enforcer then denies the release. The transport is HTTPS only and
verifies the server certificate with the default context unless the operator supplies one
(for example to add a client certificate for mutual TLS). TLS protects the channel; the
signature is what authenticates the answer.
"""

from __future__ import annotations

import http.client
import json
import secrets
import ssl
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from .trust import (
    ROLE_STATUS,
    FileTrustRoot,
    Rejected,
    TrustRoot,
    b64u_decode,
    b64u_encode,
    lookup_key,
    parse_time,
    read_header,
    split_signed,
    strict_json,
    verify_signature,
)

STATUS_TYPE = "zts-status-1"
MAX_RESPONSE_BYTES = 65536
_BODY_FIELDS = frozenset({"status", "challenge", "envelope_sha256", "policy_version", "issuer_id",
                          "nonce", "checked_at", "valid_until"})

Transport = Callable[[str, bytes, float], bytes]


class StatusUnavailable(RuntimeError):
    """The issuer could not be asked, or its answer cannot be trusted. Raised to Enforcer."""


def https_post(url: str, body: bytes, timeout: float, context: ssl.SSLContext | None = None) -> bytes:
    """POST over verified TLS. No redirects, no plain HTTP, a size cap and a hard timeout."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise StatusUnavailable("the status URL must be https")
    conn = http.client.HTTPSConnection(
        parts.hostname, parts.port or 443, timeout=timeout,
        context=context or ssl.create_default_context())
    try:
        conn.request("POST", parts.path or "/", body=body, headers={
            "Content-Type": "application/json", "Accept": "application/octet-stream"})
        response = conn.getresponse()
        if response.status != 200:  # includes every 3xx: a redirect is never followed
            raise StatusUnavailable(f"the status service answered {response.status}")
        data = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise StatusUnavailable(f"the status service could not be reached: {type(exc).__name__}") from None
    finally:
        conn.close()
    if len(data) > MAX_RESPONSE_BYTES:
        raise StatusUnavailable("the status response is too large")
    return data


class HttpStatusRevalidator:
    """Enforcer ``AuthorizationRevalidator`` backed by the issuer's signed status API.

    ``trust`` is the same trust root the grant verifier uses; the status keys live in it
    with role ``status``. Needs ``pip install zts[trust]``.
    """

    def __init__(
        self,
        base_url: str,
        trust: "TrustRoot | FileTrustRoot",
        *,
        timeout: float = 3.0,
        ssl_context: ssl.SSLContext | None = None,
        transport: Transport | None = None,
        clock: Callable[[], datetime] | None = None,
        on_reject: Callable[[str], None] | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("base_url must be an https URL")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be a positive number of seconds")
        self._url = base_url.rstrip("/") + "/v1/status"
        self._host = parts.hostname
        self._trust = trust
        self._timeout = float(timeout)
        self._transport = transport or (lambda url, body, t: https_post(url, body, t, ssl_context))
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._on_reject = on_reject

    @property
    def revalidator_id(self) -> str:
        return f"zts-http-status/{self._host}"

    def revalidate(self, envelope: Any, claims: Any) -> Any:
        import enforcer  # lazy: Enforcer is optional for importing zts

        challenge = b64u_encode(secrets.token_bytes(16))
        request = {
            "challenge": challenge, "envelope_sha256": envelope.envelope_sha256,
            "policy_version": envelope.policy_version, "issuer_id": claims.issuer_id,
            "nonce": claims.nonce,
        }
        try:
            raw = self._transport(self._url, json.dumps(request, sort_keys=True).encode(), self._timeout)
            return self._verify(raw, request, enforcer)
        except Rejected as exc:
            self._notify(exc.reason)
            raise StatusUnavailable("the status answer was not accepted") from None
        except StatusUnavailable:
            self._notify("unavailable")
            raise
        except Exception:
            self._notify("error")
            raise StatusUnavailable("the status answer could not be obtained") from None

    def _notify(self, reason: str) -> None:
        if self._on_reject is not None:
            try:
                self._on_reject(reason)
            except Exception:  # nosec B110
                pass  # an alerting hook must never change a refusal

    def _verify(self, raw: bytes, request: dict[str, str], enforcer: Any) -> Any:
        header_b64, body_b64, sig_b64 = split_signed(raw, STATUS_TYPE.encode(), MAX_RESPONSE_BYTES)
        kid = read_header(header_b64, STATUS_TYPE)
        root = self._trust.current() if isinstance(self._trust, FileTrustRoot) else self._trust
        now = self._clock().astimezone(timezone.utc)
        key = lookup_key(root, kid, ROLE_STATUS, now)
        signature = b64u_decode(sig_b64)
        if len(signature) != 64:
            raise Rejected("format")
        verify_signature(key.public_key, signature,
                         STATUS_TYPE.encode() + b"\x00" + header_b64 + b"." + body_b64)
        body = strict_json(b64u_decode(body_b64))
        if set(body) != _BODY_FIELDS:
            raise Rejected("body")
        for name in ("challenge", "envelope_sha256", "policy_version", "issuer_id", "nonce"):
            if body[name] != request[name]:
                raise Rejected(f"echo_{name}")
        if body["issuer_id"] != key.issuer_id:
            raise Rejected("issuer_mismatch")
        try:
            value = enforcer.AuthorizationStatusValue(body["status"])
        except ValueError:
            raise Rejected("status_value") from None
        return enforcer.AuthorizationStatus(
            status=value, envelope_sha256=body["envelope_sha256"], policy_version=body["policy_version"],
            checked_at=parse_time(body["checked_at"]), valid_until=parse_time(body["valid_until"]))


__all__ = ["HttpStatusRevalidator", "STATUS_TYPE", "StatusUnavailable", "https_post"]
