"""Test kit for the release boundary: real Enforcer, real CNS, test-only trust adapters.

Nothing on the enforcement path is mocked. The tower, the ZTS adapter, the CNS
dock, CNS itself and Enforcer (gate, replay store, envelope handling) are the
real code. The two things Enforcer deliberately does not ship are stood in here
and are NOT production code:

  * `HmacVerifier`: authenticates a grant with an HMAC under a test key, so a
    forged or modified proof really fails authentication.
  * `StatusSource`: an authorization-status source whose answer a test controls.

The issuer side (`envelope_for`, `mint`) is written out independently of
zts.release on purpose: it follows the envelope mapping documented in
docs/RELEASE_BOUNDARY.md, so a drift in the adapter shows up as a failure.

Skips when CNS or Enforcer is missing, unless ZTS_REQUIRE_CNS=1 or
ZTS_REQUIRE_ENFORCER=1 (CI), where a missing package is a failure.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import pytest

if os.environ.get("ZTS_REQUIRE_ENFORCER") == "1":
    import enforcer
else:
    enforcer = pytest.importorskip("enforcer")
if os.environ.get("ZTS_REQUIRE_CNS") == "1":
    import cns
else:
    cns = pytest.importorskip("cns")
from cns.governance import IdentityContext, TrustLevel  # noqa: E402

from enforcer import (  # noqa: E402
    ActionEnvelope,
    AuthorizationStatus,
    AuthorizationStatusValue,
    Enforcer,
    GrantClaims,
    ProofVerificationError,
    SQLiteReplayStore,
)

from zts import DeterministicIntegrityTower, KineticGovernor  # noqa: E402
from zts.cns import CNSDock  # noqa: E402
from zts.ledger import ValLedger  # noqa: E402
from zts.ledger_store import FileLedgerStore  # noqa: E402
from zts.release import EnforcerReleaseGate, ReleaseRequest  # noqa: E402

TEXT = "Disk utilization reached 94% on node 3 at 02:17 UTC."
OTHER_TEXT = "Disk utilization reached 12% on node 9 at 04:41 UTC."
POLICY = "policy-v1"
SCOPE = "tenant-1/ops-report"
KEY = b"test-only-issuer-key-not-production"
PROFILE = "ops"


class Clock:
    """The clock Enforcer, the issuer and the status source all share."""

    def __init__(self) -> None:
        self.now = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


def make_identity(**overrides: Any) -> IdentityContext:
    fields = dict(
        tenant_id="tenant-1",
        subject_id="subject-1",
        roles=("reader", "auditor"),
        trust_level=TrustLevel.VERIFIED,
        authentication_method="mtls",
        verified=True,
        signature="sig-1",
    )
    fields.update(overrides)
    return IdentityContext(**fields)


# ----------------------------------------------------------------- issuer side


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def envelope_for(
    text: str,
    artifact: Any,
    *,
    release_id: str,
    scope: str = SCOPE,
    profile: str = PROFILE,
    policy: str = POLICY,
    operation: str = "zts.release",
) -> ActionEnvelope:
    """What an independent issuer computes for a release, from the documented mapping."""
    parameters = json.dumps(
        {
            "canonical_sha256": _sha(artifact.canonical_representation.encode("utf-8")),
            "parameters_version": "zts-release/1",
            "profile": profile,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return ActionEnvelope(
        subject_id=artifact.subject_digest,
        action=operation,
        target_type="zts.output",
        target_id=scope,
        request_id=release_id,
        parameters_sha256=_sha(parameters),
        policy_version=policy,
        evidence_sha256=_sha(text.encode("utf-8")),
        schema_version=1,
    )


_CLAIM_FIELDS = (
    "subject_id", "action", "target_type", "target_id", "evidence_sha256",
    "request_id", "parameters_sha256", "policy_version", "schema_version",
)


def mint(
    envelope: ActionEnvelope,
    clock: Clock,
    *,
    key: bytes = KEY,
    issuer: str = "tests/issuer",
    nonce: str | None = None,
    lifetime: float = 60,
    issued_offset: float = 0,
    **overrides: Any,
) -> bytes:
    """Issue a grant for `envelope`, optionally bound to something else (`overrides`)."""
    claims: dict[str, Any] = {name: getattr(envelope, name) for name in _CLAIM_FIELDS}
    claims.update(overrides)
    issued = clock() + timedelta(seconds=issued_offset)
    claims.update(
        issuer_id=issuer,
        nonce=nonce or secrets.token_hex(8),
        issued_at=issued.isoformat(),
        expires_at=(issued + timedelta(seconds=lifetime)).isoformat(),
    )
    body = json.dumps(claims, sort_keys=True).encode("utf-8")
    return body + b"." + hmac.new(key, body, hashlib.sha256).hexdigest().encode("ascii")


class HmacVerifier:
    """Test-only proof adapter: authenticates with an HMAC under a test key."""

    verifier_id = "tests/hmac-verifier"

    def __init__(self, key: bytes = KEY, mode: str = "normal") -> None:
        self._key = key
        self.mode = mode

    def verify_and_decode(self, proof: bytes) -> GrantClaims:
        if self.mode == "crash":
            raise RuntimeError("verifier crashed")
        if self.mode == "not-claims":
            return {"not": "claims"}  # type: ignore[return-value]
        try:
            body, _, mac = proof.rpartition(b".")
            expected = hmac.new(self._key, body, hashlib.sha256).hexdigest().encode("ascii")
            if not body or not hmac.compare_digest(mac, expected):
                raise ProofVerificationError("bad mac")
            raw = json.loads(body)
            raw["issued_at"] = datetime.fromisoformat(raw["issued_at"])
            raw["expires_at"] = datetime.fromisoformat(raw["expires_at"])
            return GrantClaims(**raw)
        except ProofVerificationError:
            raise
        except Exception as exc:
            raise ProofVerificationError("malformed proof") from exc


class StatusSource:
    """Test-only authorization-status source. A test chooses what it reports."""

    revalidator_id = "tests/status-source"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self.mode = "current"
        self.age = 0.0
        self.policy: str | None = None
        self.envelope_sha256: str | None = None
        self.on_call: Callable[[], None] | None = None
        self.calls = 0

    def revalidate(self, envelope: ActionEnvelope, claims: GrantClaims) -> Any:
        self.calls += 1
        if self.on_call is not None:
            self.on_call()
        if self.mode == "unavailable":
            raise OSError("status source unavailable")
        if self.mode == "not-status":
            return "CURRENT"
        value = {
            "current": AuthorizationStatusValue.CURRENT,
            "revoked": AuthorizationStatusValue.REVOKED,
            "unknown": AuthorizationStatusValue.UNKNOWN,
        }[self.mode]
        checked = self._clock() - timedelta(seconds=self.age)
        return AuthorizationStatus(
            status=value,
            envelope_sha256=self.envelope_sha256 or envelope.envelope_sha256,
            policy_version=self.policy or envelope.policy_version,
            checked_at=checked,
            valid_until=checked + timedelta(seconds=20 + self.age),
        )


class FailingStore:
    """A replay store that is down."""

    def consume(self, issuer_id: str, nonce: str, request_id: str) -> bool:
        raise OSError("replay store unavailable")


# ---------------------------------------------------------------- the ZTS side


@dataclass
class Sink:
    """The protected callback: the only way delivered output is observable."""

    calls: list[tuple[str, dict[str, str]]] = field(default_factory=list)

    def __call__(self, output: str, signature: dict[str, str]) -> None:
        self.calls.append((output, dict(signature)))


@dataclass
class Stack:
    tower: DeterministicIntegrityTower
    sink: Sink
    clock: Clock
    status: StatusSource
    verifier: HmacVerifier
    enforcer: Enforcer
    store: Any
    identity: Any
    artifact: Any
    captured: list[Any]
    candidates: list[Any] = field(default_factory=list)


def build(
    tmp_path: Any,
    *,
    store: Any = None,
    clock: Clock | None = None,
    policy: str = POLICY,
    ledger: ValLedger | None = None,
    identity: Any = None,
    sink: Callable[..., None] | None = None,
    verifier: HmacVerifier | None = None,
    confirmer: Any = "default",
    gate_timeout: float | None = None,
    identity_verifier: Callable[[Any], bool] | None = None,
    **tower_options: Any,
) -> Stack:
    clock = clock or Clock()
    status = StatusSource(clock)
    verifier = verifier or HmacVerifier()
    store = store if store is not None else SQLiteReplayStore(tmp_path / "replay.db")
    gate_enforcer = Enforcer(verifier=verifier, revalidator=status, replay_store=store, clock=clock)
    recorder = Sink()
    receiving = sink if hasattr(sink, "calls") else recorder
    if ledger is None:
        ledger = ValLedger(key=b"l" * 32, store=FileLedgerStore(tmp_path / "ledger.jsonl"))

    def default_confirmer(release_id: str, digest: str) -> bool:
        """Asks the receiving side what it holds. It does not look at the sink's return value."""
        return digest in {_sha(out.encode("utf-8")) for out, _ in receiving.calls}

    tower = DeterministicIntegrityTower(
        PROFILE,
        governor=KineticGovernor(ceiling_seconds=0.001),
        hmac_key=b"k" * 32,
        persist_ledger_key=False,
        release_gate=EnforcerReleaseGate(gate_enforcer, policy_version=policy, timeout=gate_timeout,
                                      identity_verifier=identity_verifier),
        require_enforcer=True,
        release_sink=sink or recorder,
        delivery_confirmer=default_confirmer if confirmer == "default" else confirmer,
        ledger=ledger,
        **tower_options,
    )
    # Keep a handle on each SieveResult the tower is about to decide on, so a test
    # can mutate it between authorization and release.
    captured: list[Any] = []
    original = tower.zts.run

    def spy(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        captured.append(result)
        return result

    tower.zts.run = spy  # type: ignore[method-assign]
    identity = identity or make_identity()
    return Stack(
        tower=tower, sink=recorder, clock=clock, status=status, verifier=verifier,
        enforcer=gate_enforcer, store=store, identity=identity,
        artifact=CNSDock().to_zts_artifact(identity), captured=captured,
    )


def request(
    stack: Stack,
    release_id: str = "rel-1",
    *,
    text: str = TEXT,
    proof: bytes | None = None,
    provider: Callable[[Any], bytes | None] | None | str = "default",
    scope: str = SCOPE,
    operation: str = "zts.release",
    artifact: Any = None,
    identity: Any = None,
    **overrides: Any,
) -> ReleaseRequest:
    """A release request. By default the grant is issued, for the exact artifact, on demand."""
    artifact = artifact if artifact is not None else stack.artifact
    if proof is None and provider == "default":
        def provider(candidate: Any) -> bytes:  # noqa: F811
            stack.candidates.append(candidate)
            envelope = ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes)
            return mint(envelope, stack.clock, **overrides)
    elif provider == "default":
        provider = None
    return ReleaseRequest(
        identity=identity if identity is not None else stack.identity,
        artifact=artifact,
        release_id=release_id,
        scope=scope,
        proof=proof,
        proof_provider=provider,  # type: ignore[arg-type]
        operation=operation,
    )


def static_grant(stack: Stack, release_id: str = "rel-1", *, text: str = TEXT, **kwargs: Any) -> bytes:
    """A grant issued ahead of time for a known artifact."""
    envelope = envelope_for(text, stack.artifact, release_id=release_id)
    return mint(envelope, stack.clock, **kwargs)


def run(stack: Stack, mode: str, req: ReleaseRequest | None, text: str = TEXT) -> Any:
    """Drive the same release through the synchronous or the asynchronous path."""
    if mode == "sync":
        return stack.tower.enforce(text, release=req)

    async def generator(prompt: str) -> str:
        return text

    return asyncio.run(stack.tower.run("prompt", generator, release=req))


def tap_entries(stack: Stack) -> list[Any]:
    return [e for e in stack.tower.ledger.entries if e.layer == "TAP"]


def assert_not_released(
    stack: Stack,
    result: Any,
    reason: str,
    *,
    outcome: str | None = None,
    deliveries: int = 0,
    ledger_deliveries: int | None = None,
) -> None:
    """Everything a denied release must be: no output, no callback, recorded, unambiguous.

    `deliveries` is how many earlier, legitimate releases the sink may have seen.
    `ledger_deliveries` is how many RELEASED entries the ledger may hold; it differs from
    `deliveries` only after a restart, where a durable ledger still holds the earlier run.
    """
    assert result.released is False
    assert result.output == ""
    assert result.signature == {} and result.checksum == ""
    assert len(stack.sink.calls) == deliveries, "the protected callback ran on a denied release"
    assert result.release_outcome != "released"
    assert result.reason_code == reason, result.reason_code
    if outcome is not None:
        assert result.release_outcome == outcome, result.release_outcome
    assert result.reason_code != "VERIFIED_ACTION_BOUND_GRANT"
    assert result.authorization.get("released", False) is False
    # recorded where the ledger is available
    final = tap_entries(stack)[-1]
    assert final.status in ("HELD", "UNCONFIRMED"), final.status
    assert final.extra.get("reason_code", final.detail) == reason or final.detail == reason
    assert stack.tower.ledger.verify()[0]
    expected = deliveries if ledger_deliveries is None else ledger_deliveries
    assert sum(e.status == "RELEASED" for e in tap_entries(stack)) == expected
