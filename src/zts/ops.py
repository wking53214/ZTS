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

    def observer_failed(self) -> None:
        with self._lock:
            self._observer_errors += 1

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
    return checks


def _probe_enforcer(gate: Any) -> list[Check]:
    """Best-effort look at Enforcer's configuration. Enforcer exposes no accessor, so this reads
    private attributes; if they are not there the answer is UNKNOWN, never PASS."""
    checks: list[Check] = []
    enforcer = getattr(gate, "_enforcer", None)
    for attr, id_attr, name in (("_verifier", "verifier_id", "proof_verifier"),
                                ("_revalidator", "revalidator_id", "status_source")):
        ident = getattr(getattr(enforcer, attr, None), id_attr, None)
        if not isinstance(ident, str):
            checks.append(Check(name, UNKNOWN, "could not read the adapter's identifier"))
        elif ident.startswith("reject-all"):
            checks.append(Check(name, FAIL, f"{ident}: Enforcer's reject-everything default is still in place"))
        elif ident.startswith("tests/") or ident.startswith("test-"):
            checks.append(Check(name, FAIL, f"{ident}: this identifies itself as a test fixture"))
        else:
            checks.append(Check(
                name, UNKNOWN,
                f"{ident}: ZTS cannot verify what this adapter does. Review and exercise it; "
                "this report does not vouch for it"))
    checks.append(_probe_replay_store(getattr(enforcer, "_replay_store", None)))
    return checks


def _probe_replay_store(store: Any) -> Check:
    name = "replay_store"
    if store is None:
        return Check(name, UNKNOWN, "could not read the replay store")
    connection = getattr(store, "_connection", None)
    if connection is not None:
        try:
            rows = connection.execute("PRAGMA database_list").fetchall()
            files = [row[2] for row in rows if row[1] == "main"]
        except Exception:
            return Check(name, UNKNOWN, "could not inspect the SQLite replay store")
        if files and files[0]:
            return Check(name, UNKNOWN, "file-backed SQLite: survives a restart on this host, "
                                        "but is not shared across hosts. Whether that matches the "
                                        "deployment is the operator's to confirm")
        return Check(name, FAIL, "in-memory SQLite: every spent grant is forgotten at restart")
    return Check(name, UNKNOWN, f"{type(store).__name__}: durability and cross-host consistency "
                                "are the operator's to verify")


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
