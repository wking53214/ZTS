"""The release service: the one process that holds the tower, the keys, the ledger and the delivery credentials.

The application talks to it over a local Unix socket and never touches any of those. This is an EXAMPLE you deploy under its own
operating-system account (see ../isolation/); it is not part of the ``zts`` package. Linux only (it reads the caller's account from
the kernel with SO_PEERCRED).

Protocol. One request per connection: a single line of JSON, then the service answers with a single line of JSON and closes.

    request  {"release_id": str, "scope": str, "text": str, "grant": <base64 of the grant bytes>,
              "identity": {"tenant_id", "subject_id", "roles": [str], "trust_level", "authentication_method",
                           "verified": bool, "signature": str}}
    response {"released": bool, "outcome": str, "reason_code": str, "authorized": bool}

``outcome`` is the tower's release outcome (denied, not_attempted, failed_before_delivery, delivery_unknown, delivered_*), or
``refused`` when the service itself said no before the tower was asked (bad request, caller not allowed, too large, busy).
Nothing else ever comes back: no key, no credential, no ledger line, no exception text.

Who may ask. The kernel tells the service which account is on the other end of the socket. A caller account that is not in the
config is refused, and each account may present only the tenants and subjects the config lists for it. This is in addition to, not
instead of, the identity provider's signature and the grant: all three must say yes.

What the grant is. The application obtains it from your issuer and passes it in. It is bound to the exact text, single-use, and
checked by the tower; the service only carries it.
"""

from __future__ import annotations

import base64
import binascii
import importlib
import json
import logging
import os
import signal
import socket
import stat
import struct
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

LOG = logging.getLogger("zts.release_service")

MAX_REQUEST_BYTES = 256 * 1024
MAX_GRANT_BYTES = 8192
REQUEST_FIELDS = frozenset({"release_id", "scope", "text", "grant", "identity"})
IDENTITY_FIELDS = frozenset({"tenant_id", "subject_id", "roles", "trust_level", "authentication_method", "verified", "signature"})
CONFIG_KEYS = frozenset({"socket_path", "socket_mode", "socket_group", "callers", "tower_factory", "max_request_bytes",
                         "max_concurrent", "read_timeout"})


def refusal(reason: str) -> dict[str, Any]:
    return {"released": False, "outcome": "refused", "reason_code": reason, "authorized": False}


@dataclass(frozen=True)
class CallerPolicy:
    """Which account may present which tenants and subjects. Anything not listed is refused."""

    rules: dict[int, tuple[frozenset[str], frozenset[str]]]

    @classmethod
    def from_config(cls, callers: Any) -> "CallerPolicy":
        if not isinstance(callers, dict) or not callers:
            raise ValueError("callers must name at least one account")
        rules: dict[int, tuple[frozenset[str], frozenset[str]]] = {}
        for uid, rule in callers.items():
            if not isinstance(uid, str) or not uid.isdigit() or not isinstance(rule, dict) or set(rule) != {"tenants", "subjects"}:
                raise ValueError("each caller is a numeric account id with exactly 'tenants' and 'subjects'")
            lists = []
            for key in ("tenants", "subjects"):
                values = rule[key]
                if not isinstance(values, list) or not values or not all(isinstance(v, str) and v for v in values):
                    raise ValueError(f"{key} must be a non-empty list of names (use [\"*\"] to allow any, deliberately)")
                lists.append(frozenset(values))
            rules[int(uid)] = (lists[0], lists[1])
        return cls(rules)

    def allows(self, uid: int, tenant: str, subject: str) -> bool:
        rule = self.rules.get(uid)
        if rule is None:
            return False
        tenants, subjects = rule
        return ("*" in tenants or tenant in tenants) and ("*" in subjects or subject in subjects)


def read_peer_uid(conn: socket.socket) -> int:
    """The account on the other end of a Unix socket, from the kernel. Cannot be set by the caller."""
    _pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return uid


class ReleaseService:
    def __init__(
        self,
        tower: Any,
        policy: CallerPolicy,
        *,
        max_request_bytes: int = MAX_REQUEST_BYTES,
        max_concurrent: int = 8,
        read_timeout: float = 10.0,
        peer_uid: Callable[[socket.socket], int] = read_peer_uid,
        require_ready: bool = True,
    ) -> None:
        if not callable(getattr(tower, "enforce", None)):
            raise TypeError("tower must provide enforce()")
        if require_ready:
            self._require_ready(tower)
        self._tower, self._policy = tower, policy
        self._max, self._timeout, self._peer_uid = max_request_bytes, read_timeout, peer_uid
        self._slots = threading.BoundedSemaphore(max_concurrent)
        self._stop = threading.Event()
        self._server: socket.socket | None = None
        from zts.cns import CNSDock

        self._dock = CNSDock()
        self._dock.connect()

    @staticmethod
    def _require_ready(tower: Any) -> None:
        """Refuse to run a tower that is not a production tower, or whose readiness has a FAIL."""
        if getattr(tower, "release_gate", None) is None:
            raise RuntimeError("the tower has no Enforcer release gate: this service only runs the production path")
        report = tower.readiness()
        failed = [c.name for c in report.checks if c.status == "FAIL"]
        if failed:
            raise RuntimeError(f"the tower is not ready: {', '.join(failed)}")

    # ------------------------------------------------------------------ one request, no socket

    def process(self, uid: int, raw: bytes) -> dict[str, Any]:
        """Turn one request into one response. Never raises."""
        try:
            return self._process(uid, raw)
        except Exception:  # the caller learns only that it failed; the log has the type
            LOG.exception("release service error")
            return {"released": False, "outcome": "service_error", "reason_code": "SERVICE_ERROR", "authorized": False}

    def _process(self, uid: int, raw: bytes) -> dict[str, Any]:
        from zts.release import ReleaseRequest
        from zts.trust import Rejected, strict_json

        if len(raw) > self._max:
            return refusal("TOO_LARGE")
        try:
            body = strict_json(raw)
        except Rejected:
            return refusal("BAD_REQUEST")
        parsed = self._parse(body)
        if parsed is None:
            return refusal("BAD_REQUEST")
        release_id, scope, text, grant, identity_fields = parsed
        if not self._policy.allows(uid, identity_fields["tenant_id"], identity_fields["subject_id"]):
            LOG.warning("caller account %s may not present tenant %r subject %r", uid, identity_fields["tenant_id"],
                        identity_fields["subject_id"])
            return refusal("CALLER_NOT_ALLOWED")
        try:
            identity = self._identity(identity_fields)
            artifact = self._dock.to_zts_artifact(identity)
        except Exception:
            return refusal("IDENTITY_INVALID")
        result = self._tower.enforce(text, release=ReleaseRequest(
            identity=identity, artifact=artifact, release_id=release_id, scope=scope, proof=grant))
        return {"released": bool(result.released), "outcome": str(result.release_outcome),
                "reason_code": str(result.reason_code), "authorized": bool(result.authorization.get("authorized", False))}

    @staticmethod
    def _parse(body: dict[str, Any]) -> tuple[str, str, str, bytes, dict[str, Any]] | None:
        if set(body) != REQUEST_FIELDS:
            return None
        release_id, scope, text, grant_b64, ident = (body[k] for k in ("release_id", "scope", "text", "grant", "identity"))
        if not all(type(v) is str and v.strip() for v in (release_id, scope, text, grant_b64)):
            return None
        if not isinstance(ident, dict) or set(ident) != IDENTITY_FIELDS:
            return None
        roles = ident["roles"]
        if not isinstance(roles, list) or not all(type(r) is str and r for r in roles) or type(ident["verified"]) is not bool:
            return None
        if not all(type(ident[k]) is str and ident[k] for k in ("tenant_id", "subject_id", "trust_level", "authentication_method")):
            return None
        if type(ident["signature"]) is not str:
            return None
        try:
            grant = base64.b64decode(grant_b64, validate=True)
        except (binascii.Error, ValueError):
            return None
        if not 0 < len(grant) <= MAX_GRANT_BYTES:
            return None
        return release_id, scope, text, grant, ident

    @staticmethod
    def _identity(fields: dict[str, Any]) -> Any:
        from cns.governance import IdentityContext, TrustLevel

        return IdentityContext(
            tenant_id=fields["tenant_id"], subject_id=fields["subject_id"], roles=tuple(fields["roles"]),
            trust_level=TrustLevel(fields["trust_level"]), authentication_method=fields["authentication_method"],
            verified=fields["verified"], signature=fields["signature"])

    # --------------------------------------------------------------------------- the socket

    def _read_line(self, conn: socket.socket) -> bytes | None:
        conn.settimeout(self._timeout)
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > self._max + 1:
                return None
        return data.split(b"\n", 1)[0]

    def _serve_one(self, conn: socket.socket) -> None:
        try:
            with conn:
                try:
                    uid = self._peer_uid(conn)
                    line = self._read_line(conn)
                    response = refusal("TOO_LARGE") if line is None else self.process(uid, line)
                except (OSError, struct.error):
                    return
                try:
                    conn.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")
                except OSError:
                    pass  # the caller went away; the release, if any, is already recorded in the ledger
        finally:
            self._slots.release()

    def bind(self, path: str, *, mode: int = 0o660, group: str | None = None) -> None:
        """Create the listening socket, refusing an unsafe place for it."""
        target = Path(path)
        parent = target.parent
        info = parent.stat()
        if info.st_mode & 0o022:
            raise RuntimeError(f"{parent} is writable by group or others; the socket must live in a directory only the service controls")
        if target.exists() or target.is_symlink():
            if not stat.S_ISSOCK(target.lstat().st_mode):
                raise RuntimeError(f"{target} exists and is not a socket")
            probe = socket.socket(socket.AF_UNIX)
            try:
                probe.connect(str(target))
            except (ConnectionRefusedError, FileNotFoundError):
                target.unlink()  # a stale socket from a process that is gone
            else:
                raise RuntimeError(f"{target} is in use by another service")
            finally:
                probe.close()
        server = socket.socket(socket.AF_UNIX)
        try:
            old = os.umask(0o177)
            try:
                server.bind(str(target))
            finally:
                os.umask(old)
            if group is not None:
                import shutil
                shutil.chown(target, group=group)
            os.chmod(target, mode)
            server.listen(32)
            server.settimeout(0.5)
        except BaseException:
            server.close()  # a bind that fails part way must not leave its socket open
            raise
        self._server = server

    def serve_forever(self) -> None:
        assert self._server is not None, "bind() first"
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                with conn:
                    try:
                        conn.sendall(json.dumps(refusal("BUSY"), separators=(",", ":")).encode() + b"\n")
                    except OSError:
                        pass
                continue
            threading.Thread(target=self._serve_one, args=(conn,), daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self._server is not None:
            self._server.close()


# ------------------------------------------------------------------------------ configuration


def load_config(path: str) -> dict[str, Any]:
    from zts.trust import Rejected, strict_json

    info = os.stat(path)
    if info.st_mode & 0o022:
        raise ValueError(f"{path} is writable by group or others")
    try:
        config = strict_json(Path(path).read_bytes())
    except Rejected as exc:
        raise ValueError(f"{path} is not strict JSON ({exc.reason})") from None
    unknown = set(config) - CONFIG_KEYS
    missing = {"socket_path", "callers", "tower_factory"} - set(config)
    if unknown or missing:
        raise ValueError(f"config keys: unknown {sorted(unknown)}, missing {sorted(missing)}")
    if not isinstance(config["socket_path"], str) or not config["socket_path"].startswith("/"):
        raise ValueError("socket_path must be an absolute path")
    if not isinstance(config["tower_factory"], str) or config["tower_factory"].count(":") != 1:
        raise ValueError("tower_factory must be 'module:function'")
    return config


def build_service(config: dict[str, Any]) -> ReleaseService:
    module, _, name = config["tower_factory"].partition(":")
    tower = getattr(importlib.import_module(module), name)(config)
    return ReleaseService(
        tower, CallerPolicy.from_config(config["callers"]),
        max_request_bytes=int(config.get("max_request_bytes", MAX_REQUEST_BYTES)),
        max_concurrent=int(config.get("max_concurrent", 8)), read_timeout=float(config.get("read_timeout", 10.0)))


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("usage: python -m release_service CONFIG.json", file=sys.stderr)
        return 2
    config = load_config(args[0])
    service = build_service(config)
    service.bind(config["socket_path"], mode=int(config.get("socket_mode", "0660"), 8), group=config.get("socket_group"))
    signal.signal(signal.SIGTERM, lambda *_: service.stop())
    signal.signal(signal.SIGINT, lambda *_: service.stop())
    LOG.info("release service listening on %s", config["socket_path"])
    service.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
