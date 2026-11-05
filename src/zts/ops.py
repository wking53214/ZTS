"""Operations: security metrics, structured audit events, startup validation and health.

None of this changes a release decision. It records them, and it refuses to start a
tower that claims to be production while configured as something else.

The rule for every check: PASS only for what this process verified; FAIL for what it
verified is wrong; UNKNOWN for what only the operator can know. A check never says
PASS because an interface exists. In particular ZTS cannot see inside a custom proof
verifier, status source or replay store, so those report UNKNOWN however they are
named, and a deployment must establish them by review and by exercise, not by this
report.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

PASS = "PASS"  # nosec B105
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"

LOGGER = logging.getLogger("zts.release")

#: Denials that mean someone may be attacking the boundary, not that a dependency is down.
SECURITY_REASONS = frozenset({
    "GRANT_REPLAYED", "PROOF_INVALID", "SCOPE_MISMATCH", "GRANT_REVOKED", "GRANT_EXPIRED",
    "CNS_VERIFICATION_FAILED", "CNS_IDENTITY_UNTRUSTED", "ARTIFACT_CHANGED", "POLICY_CHANGED",
    "PRODUCTION_INVARIANT_VIOLATED", "AUTHORITY_CONTEXT_MISMATCH",
})
#: Failures of a dependency or of the audit trail: the system is degraded, not necessarily attacked.
AVAILABILITY_REASONS = frozenset({
    "LEDGER_UNAVAILABLE", "ENFORCER_TIMEOUT", "PROOF_PROVIDER_TIMEOUT", "PROOF_PROVIDER_ERROR",
    "CNS_UNAVAILABLE", "ENFORCER_UNAVAILABLE", "REPLAY_STORE_ERROR", "VERIFIER_ERROR",
    "AUTHORITY_REVALIDATION_ERROR", "DELIVERY_UNCONFIRMED", "RELEASE_ACTION_FAILED",
})


class ReleaseMetrics:
    """Thread-safe counters of release outcomes and the reasons behind them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._outcomes: Counter[str] = Counter()
        self._reasons: Counter[str] = Counter()
        self._total = 0
        self._observer_errors = 0
        self._anchor_failures = 0

    def observer_failed(self) -> None:
        with self._lock:
            self._observer_errors += 1

    def anchor_failed(self) -> None:
        with self._lock:
            self._anchor_failures += 1

    def record(self, outcome: str, reason: str) -> None:
        with self._lock:
            self._total += 1
            self._outcomes[outcome] += 1
            if reason:
                self._reasons[reason] += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            reasons = dict(self._reasons)
            return {
                "total": self._total,
                "outcomes": dict(self._outcomes),
                "reasons": reasons,
                # The numbers an alert rule would watch.
                "replays_detected": reasons.get("GRANT_REPLAYED", 0),
                "security_denials": sum(n for r, n in reasons.items() if r in SECURITY_REASONS),
                "availability_failures": sum(n for r, n in reasons.items() if r in AVAILABILITY_REASONS),
                "delivery_unknown": self._outcomes.get("delivery_unknown", 0),
                "audit_incomplete": self._outcomes.get("delivered_audit_incomplete", 0),
                "observer_errors": self._observer_errors,
                "anchor_failures": self._anchor_failures,
            }


def audit_event(result: Any, *, policy_version: str = "") -> dict[str, Any]:
    """A JSON-safe record of one release decision. Identifiers, digests, codes and times only.

    Never contains the artifact, the proof, or matched text.
    """
    auth = result.authorization or {}
    return {
        "event": "zts.release",
        "outcome": result.release_outcome,
        "reason_code": result.reason_code,
        "released": result.released,
        "release_id": result.release_id,
        "subject_digest": auth.get("subject_digest", ""),
        "operation": auth.get("operation", ""),
        "scope": auth.get("scope", ""),
        "policy_version": auth.get("policy_version", policy_version),
        "profile": auth.get("profile", result.sieve.profile),
        "authorized": auth.get("authorized", False),
        "grant_state": auth.get("grant_state", ""),
        "delivery_verified": result.delivery_verified,
        "audit_durable": result.audit_durable,
        "audit_anchored": result.audit_anchored,
        "attempts": result.attempts,
        "elapsed_ms": round(result.elapsed_ms, 3),
        "decided_at": auth.get("decided_at", ""),
    }


def log_event(event: dict[str, Any]) -> None:
    """Emit one structured line on the ``zts.release`` logger.

    INFO for a clean delivery, WARNING for a denial or anything not fully delivered and
    recorded, ERROR when an attack signature or an unknown delivery occurred. Nothing is
    printed unless the application attaches a handler to the logger.
    """
    reason = event["reason_code"]
    if event["outcome"] == "delivered":
        level = logging.INFO
    elif reason in SECURITY_REASONS or event["outcome"] == "delivery_unknown":
        level = logging.ERROR
    else:
        level = logging.WARNING
    LOGGER.log(level, json.dumps(event, sort_keys=True))


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class ReadinessReport:
    checks: list[Check] = field(default_factory=list)

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    @property
    def unknown(self) -> list[Check]:
        return [c for c in self.checks if c.status == UNKNOWN]

    @property
    def ready(self) -> bool:
        """No check failed. Says nothing about UNKNOWN checks, which only the operator can settle."""
        return not self.failed

    @property
    def fully_verified(self) -> bool:
        return not self.failed and not self.unknown

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "fully_verified": self.fully_verified,
            "checks": [{"name": c.name, "status": c.status, "detail": c.detail} for c in self.checks],
        }


class ProductionConfigError(ValueError):
    """The tower was asked to be a production tower and is not configured as one."""


def _verdict(ok: bool, name: str, good: str, bad: str) -> Check:
    return Check(name, PASS if ok else FAIL, good if ok else bad)


def check_configuration(tower: Any) -> list[Check]:
    """Static checks: how the tower is configured. Safe to run at startup."""
    gate = tower.release_gate
    checks = [
        _verdict(gate is not None, "enforcer_gate", "release goes through the Enforcer gate",
                 "no Enforcer gate: nothing can be released through the production path"),
        _verdict(tower.tap is None and bool(tower.require_enforcer), "no_legacy_release_path",
                 "no legacy capstone, and require_enforcer is on",
                 "a legacy capstone is present or require_enforcer is off"),
        _verdict(tower.ledger.durable, "durable_ledger", "the ledger is fsynced to a file store",
                 "the ledger is in memory: a release cannot be durably recorded"),
        _verdict(tower.ledger.anchored, "ledger_anchor", "a ledger anchor is configured",
                 "no ledger anchor: truncation of the ledger cannot be detected"),
        _verdict(tower.delivery_confirmer is not None, "delivery_confirmer",
                 "a delivery confirmer is configured",
                 "no delivery confirmer: success rests on the callback's own return"),
        _verdict(gate is not None and gate.timeout is not None, "enforcer_timeout",
                 "the Enforcer call and the grant provider are time-bounded",
                 "no timeout: a hung authority hangs the release path"),
        _verdict(bool(getattr(tower, "_key_supplied", False)), "release_signature_key",
                 "the release signature key was supplied, not generated per process",
                 "the release signature key is random per process: signatures cannot be verified after a restart"),
    ]
    if gate is not None:
        checks += _probe_enforcer(gate)
    checks += _probe_anchor(tower.ledger)
    checks.append(Check("trust_root_governance", UNKNOWN,
                        "who owns the trust root, how it is stored, rotated and distributed is an operator "
                        "decision that no code can verify"))
    return checks


def _probe_anchor(ledger: Any) -> list[Check]:
    anchor = getattr(ledger, "_anchor", None)
    if anchor is None:
        return []
    from .anchor_tsa import Rfc3161Anchor

    if isinstance(anchor, Rfc3161Anchor):
        info = anchor.describe()
        return [
            Check("anchor_kind", PASS, f"RFC 3161 time-stamp anchor with {info['pinned_certificates']} pinned "
                                       "TSA certificate(s); tokens are re-verified on every read"),
            Check("anchor_independence", UNKNOWN,
                  "the TSA proves a head existed. It does not remember your ledger: keep the receipts file "
                  "where the ledger's writer cannot rewrite it, or rollback goes unnoticed"),
        ]
    return [Check("anchor_independence", UNKNOWN,
                  f"{type(anchor).__name__}: whether this anchor is out of the ledger writer's reach is a "
                  "deployment fact")]


def _probe_enforcer(gate: Any) -> list[Check]:
    """Look at how Enforcer was configured. Enforcer exposes no accessor, so this reads private
    attributes; if they are not there the answer is UNKNOWN, never PASS.

    ZTS's own adapters (the Ed25519 verifier, the HTTPS status client, the PostgreSQL replay store)
    can be inspected, so they can PASS for what this process verifies about them. Anything custom
    stays UNKNOWN however it is named. Nothing here can say whether a trust root is *legitimate*.
    """
    enforcer = getattr(gate, "_enforcer", None)
    checks = [
        _probe_verifier(getattr(enforcer, "_verifier", None)),
        _probe_status(getattr(enforcer, "_revalidator", None), getattr(enforcer, "_verifier", None)),
    ]
    checks += _probe_replay_store(getattr(enforcer, "_replay_store", None))
    verifier_hook = getattr(gate, "identity_verifier", None)
    checks.append(Check(
        "identity_authentication", UNKNOWN,
        "an identity verifier is configured; ZTS cannot verify what it does" if verifier_hook is not None
        else "no identity verifier: the grant issuer is the only authentication of the subject"))
    return checks


def _generic_adapter(adapter: Any, id_attr: str, name: str) -> Check | None:
    ident = getattr(adapter, id_attr, None)
    if not isinstance(ident, str):
        return Check(name, UNKNOWN, "could not read the adapter's identifier")
    if ident.startswith("reject-all"):
        return Check(name, FAIL, f"{ident}: Enforcer's reject-everything default is still in place")
    if ident.startswith("tests/") or ident.startswith("test-"):
        return Check(name, FAIL, f"{ident}: this identifies itself as a test fixture")
    return None


def _usable_keys(trust: Any, role: str) -> int:
    from datetime import datetime, timezone

    root = trust.current() if hasattr(trust, "current") else trust
    now = datetime.now(timezone.utc)
    return sum(1 for k in root.keys.values() if k.role == role and k.usable_at(now))


def _probe_verifier(verifier: Any) -> Check:
    name = "proof_verifier"
    found = _generic_adapter(verifier, "verifier_id", name)
    if found is not None:
        return found
    from .trust import Ed25519GrantVerifier, TrustRootError

    if isinstance(verifier, Ed25519GrantVerifier):
        try:
            usable = _usable_keys(verifier._trust, "grant")
        except TrustRootError as exc:
            return Check(name, FAIL, f"the trust root cannot be loaded: {exc}")
        if usable == 0:
            return Check(name, FAIL, "the trust root has no usable grant key: every proof will be refused")
        return Check(name, PASS, f"ZTS Ed25519 verifier, one algorithm, {usable} usable grant key(s). "
                                 "Whether the trust root itself is legitimate is not something this can check")
    return Check(name, UNKNOWN, f"{getattr(verifier, 'verifier_id', '?')}: a custom verifier; ZTS cannot "
                                "verify what it does. Review and exercise it")


def _probe_status(revalidator: Any, verifier: Any) -> Check:
    name = "status_source"
    found = _generic_adapter(revalidator, "revalidator_id", name)
    if found is not None:
        return found
    from .status import HttpStatusRevalidator
    from .trust import TrustRootError

    if isinstance(revalidator, HttpStatusRevalidator):
        try:
            usable = _usable_keys(revalidator._trust, "status")
        except TrustRootError as exc:
            return Check(name, FAIL, f"the trust root cannot be loaded: {exc}")
        if usable == 0:
            return Check(name, FAIL, "the trust root has no usable status key: every status answer will be refused")
        return Check(name, PASS, f"HTTPS signed status API ({revalidator.revalidator_id}), live per release, no "
                                 f"cache, challenge-bound, {usable} usable status key(s). Reachability is not tested here")
    return Check(name, UNKNOWN, f"{getattr(revalidator, 'revalidator_id', '?')}: a custom status source; ZTS "
                                "cannot verify what it does. Review and exercise it")


def _probe_replay_store(store: Any) -> list[Check]:
    name = "replay_store"
    if store is None:
        return [Check(name, UNKNOWN, "could not read the replay store")]
    from .replay_postgres import PostgresReplayStore

    if isinstance(store, PostgresReplayStore):
        info = store.describe()
        healthy = store.health()
        checks = [Check(name, PASS if healthy else FAIL,
                        "shared PostgreSQL store: reachable, with the two uniqueness constraints in place. "
                        "Replication and failover durability are the operator's to confirm" if healthy
                        else "the PostgreSQL replay store is unreachable or lacks its uniqueness constraints")]
        mode = info.get("sslmode")
        host = str(info.get("host", ""))
        local = host.startswith("/") or host in ("localhost", "127.0.0.1", "::1")
        if mode in ("verify-full", "verify-ca"):
            checks.append(Check("replay_store_tls", PASS, f"sslmode={mode}"))
        elif local:
            checks.append(Check("replay_store_tls", UNKNOWN, f"sslmode={mode} on a local connection"))
        else:
            checks.append(Check("replay_store_tls", FAIL, f"sslmode={mode} to {host}: the replay database "
                                                         "connection is not verified TLS"))
        return checks
    connection = getattr(store, "_connection", None)
    if connection is not None:
        try:
            rows = connection.execute("PRAGMA database_list").fetchall()
            files = [row[2] for row in rows if row[1] == "main"]
        except Exception:
            return [Check(name, UNKNOWN, "could not inspect the SQLite replay store")]
        if files and files[0]:
            return [Check(name, UNKNOWN, "file-backed SQLite: survives a restart on this host, but is not shared "
                                         "across hosts. Whether that matches the deployment is the operator's to confirm")]
        return [Check(name, FAIL, "in-memory SQLite: every spent grant is forgotten at restart")]
    return [Check(name, UNKNOWN, f"{type(store).__name__}: durability and cross-host consistency "
                                 "are the operator's to verify")]


def check_runtime(tower: Any) -> list[Check]:
    """Live checks: is the thing working right now."""
    checks: list[Check] = []
    ok, reason = tower.ledger.verify()
    checks.append(_verdict(ok, "ledger_chain", "the hash chain verifies", f"the chain does not verify: {reason}"))
    if tower.ledger.anchored:
        ok, reason = tower.ledger.verify_anchored()
        checks.append(_verdict(ok, "ledger_anchor_match", "the chain matches the anchor", f"anchor check failed: {reason}"))
    gate = tower.release_gate
    if gate is not None:
        from .release import _load_enforcer  # lazy: Enforcer is optional

        try:
            _load_enforcer()
            checks.append(Check("enforcer_importable", PASS, "Enforcer imports and is a supported release"))
        except Exception as exc:
            checks.append(Check("enforcer_importable", FAIL, str(exc)))
        try:
            gate._dock.connect()
            checks.append(Check("cns_importable", PASS, "CNS imports and is a supported release"))
        except Exception as exc:
            checks.append(Check("cns_importable", FAIL, str(exc)))
    anchor = getattr(tower.ledger, "_anchor", None)
    last_error = getattr(anchor, "last_error", None)
    if anchor is not None and hasattr(anchor, "last_error"):
        checks.append(_verdict(last_error is None, "anchor_service", "the last anchor publish succeeded",
                               f"the last anchor publish failed: {last_error}"))
    checks.append(_verdict(not tower.closing, "accepting_work", "accepting releases", "the tower is closed or closing"))
    return checks


__all__ = [
    "AVAILABILITY_REASONS",
    "Check",
    "FAIL",
    "LOGGER",
    "PASS",
    "ProductionConfigError",
    "ReadinessReport",
    "ReleaseMetrics",
    "SECURITY_REASONS",
    "UNKNOWN",
    "audit_event",
    "check_configuration",
    "check_runtime",
    "log_event",
]
