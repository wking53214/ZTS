"""The application's side: ask the release service to release one text. Standard library only, so the application needs nothing from ZTS.

    from client import release
    answer = release("/run/zts/release.sock", release_id="rel-42", scope="tenant-1/ops-report", text=report,
                     grant=grant_bytes, identity=signed_identity_fields)
    if answer["released"]: ...

``identity`` is a dict with tenant_id, subject_id, roles (list), trust_level, authentication_method, verified and signature (the
identity provider's signed string, see ../identity_provider/). The answer is the four fields documented in service.py. A connection that
fails, or an answer that cannot be read, raises; treat both as "not released" and do NOT retry with the same grant without checking
the outcome first (the grant may be spent: look at the ledger, or ask for the release id's outcome).
"""

from __future__ import annotations

import base64
import json
import socket


def release(socket_path: str, *, release_id: str, scope: str, text: str, grant: bytes, identity: dict, timeout: float = 30.0) -> dict:
    request = {"release_id": release_id, "scope": scope, "text": text, "grant": base64.b64encode(grant).decode("ascii"),
               "identity": identity}
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(timeout)
        conn.connect(socket_path)
        conn.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    answer = json.loads(data)
    if not isinstance(answer, dict) or set(answer) != {"released", "outcome", "reason_code", "authorized"}:
        raise ValueError("the release service answered something unexpected")
    return answer
