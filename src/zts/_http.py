"""One bounded HTTP POST, shared by the status client and the timestamp client.

Why this exists. A socket timeout limits one wait, not the whole exchange: a server that sends one
byte every few seconds never trips it, and ``http.client`` happily keeps reading for as long as bytes
keep arriving. Both callers are on the release path, so a slow or hostile endpoint could hold a
thread (and the release's gate timeout, which abandons the call but cannot stop its thread) for
hours. This helper puts one deadline on the whole exchange: a watchdog closes the socket when the
time is up, which wakes whatever is blocked on it, and the call then fails.

What the deadline covers: the TLS handshake, sending the request, waiting for and reading the
response. What it cannot cover: name resolution and the TCP connect, which block in the operating
system and cannot be interrupted from here; the connect is bounded per address by the same
timeout. Anything that must be bounded absolutely (the release itself) is bounded by the gate's
timeout, which does not depend on this.

No redirect is followed, no proxy is consulted, and the response size is capped.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
from urllib.parse import urlsplit


class HttpFailure(Exception):
    """The exchange did not produce a 200 with a body in time. The text is safe to show an operator."""


def bounded_post(
    url: str,
    body: bytes,
    timeout: float,
    context: ssl.SSLContext | None,
    *,
    schemes: tuple[str, ...],
    headers: dict[str, str],
    service: str,
    response_noun: str,
    max_bytes: int,
) -> bytes:
    parts = urlsplit(url)
    if parts.scheme not in schemes or not parts.hostname:
        raise HttpFailure(f"the {service} URL must be {' or '.join(schemes)}")
    secure = parts.scheme == "https"
    if secure:
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            parts.hostname, parts.port or 443, timeout=timeout, context=context or ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)

    expired, finished = threading.Event(), threading.Event()

    def abort() -> None:
        expired.set()
        if finished.is_set():
            return
        sock = conn.sock
        if sock is None:
            # Still connecting: there is nothing to close yet. Look again shortly, so a connect that
            # completes after the deadline is cut at once instead of being allowed to run on.
            again = threading.Timer(0.05, abort)
            again.daemon = True
            again.start()
            return
        for action in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
            try:
                action()
            except OSError:
                pass  # already closed: nothing to wake

    watchdog = threading.Timer(timeout, abort)
    watchdog.daemon = True
    watchdog.start()
    try:
        conn.request("POST", parts.path or "/", body=body, headers=headers)
        response = conn.getresponse()
        if response.status != 200:  # includes every 3xx: a redirect is never followed
            raise HttpFailure(f"the {service} answered {response.status}")
        data = response.read(max_bytes + 1)
        if expired.is_set():  # the watchdog closed the socket: what was read is a fragment, not an answer
            raise HttpFailure(f"the {service} did not answer within {timeout:g}s")
    except HttpFailure:
        raise
    except (OSError, http.client.HTTPException) as exc:
        if expired.is_set() or isinstance(exc, TimeoutError):  # a wait that ran out is the deadline too
            raise HttpFailure(f"the {service} did not answer within {timeout:g}s") from None
        raise HttpFailure(f"the {service} could not be reached: {type(exc).__name__}") from None
    finally:
        finished.set()
        watchdog.cancel()
        conn.close()
    if len(data) > max_bytes:
        raise HttpFailure(f"the {response_noun} is too large")
    return data
