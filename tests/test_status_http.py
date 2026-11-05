"""The online status revalidator against a real HTTPS service and the real Enforcer.

The service is a fixture (issuer_kit.StatusService) with a throwaway CA and keys. These
tests prove the client's mechanism: TLS verification, signature and echo checks, bounded
time, and that every failure ends in a denial that never reaches the delivery callback.
"""

from __future__ import annotations

import time

import pytest

from issuer_kit import IssuerKey, StatusService, trust_doc
from release_kit import Clock, assert_not_released, build, enforcer, request, run
from test_trust_ed25519 import issuer_provider
from zts.status import HttpStatusRevalidator, StatusUnavailable
from zts.trust import Ed25519GrantVerifier, TrustRoot


@pytest.fixture(params=["sync", "async"])
def mode(request):
    return request.param


@pytest.fixture
def world(tmp_path):
    clock = Clock()
    grant_key, status_key = IssuerKey("issuer-a", "grant"), IssuerKey("issuer-a", "status")
    cross_key = IssuerKey("issuer-b", "status")  # pinned, active, correct role, but another issuer's key
    root = TrustRoot.from_dict(trust_doc(grant_key.entry(clock), status_key.entry(clock), cross_key.entry(clock)))
    svc = StatusService(tmp_path, status_key, clock)
    svc.cross_key = cross_key
    svc.other_key = IssuerKey("issuer-a", "status")  # a status key the trust root does not know
    svc.role_key = grant_key                          # a key that IS pinned, but with the wrong role
    rejects = []
    revalidator = HttpStatusRevalidator(svc.url, root, timeout=0.6, ssl_context=svc.client_context(),
                                        clock=clock, on_reject=rejects.append)
    s = build(tmp_path, clock=clock, verifier=Ed25519GrantVerifier(root, clock=clock))
    s.enforcer._revalidator = revalidator  # Enforcer reads this when it authorizes
    w = type("W", (), dict(s=s, svc=svc, root=root, grant=grant_key, status=status_key, rejects=rejects,
                           revalidator=revalidator, clock=clock, tmp=tmp_path))
    yield w
    svc.close()


def release(w, mode, rid="rel-1"):
    return run(w.s, mode, request(w.s, rid, provider=issuer_provider(w.s, w.grant, nonce=f"n-{rid}")))


# ------------------------------------------------------------------ the good path


def test_a_current_answer_from_the_issuer_releases_through_the_whole_real_stack(world, mode):
    r = release(world, mode)
    assert r.release_outcome == "delivered" and len(world.s.sink.calls) == 1
    assert r.authorization["decision"]["revalidator_id"] == "zts-http-status/localhost"
    (req,) = world.svc.requests
    assert set(req) == {"challenge", "envelope_sha256", "policy_version", "issuer_id", "nonce"}
    assert "Disk utilization" not in str(req), "the status service must never see the artifact"


def test_every_release_asks_again_there_is_no_cache(world, mode):
    release(world, mode, "rel-1")
    release(world, mode, "rel-2")
    assert len(world.svc.requests) == 2 and len({r["challenge"] for r in world.svc.requests}) == 2


# ---------------------------------------------------- the issuer says no, or says nothing


@pytest.mark.parametrize("answer,reason", [("revoked", "GRANT_REVOKED"), ("unknown", "AUTHORITY_STATUS_UNKNOWN"),
                                           ("stale", "AUTHORITY_STATUS_STALE")])
def test_a_signed_answer_that_is_not_current_or_not_fresh_is_a_denial(world, mode, answer, reason):
    world.svc.mode = answer
    assert_not_released(world.s, release(world, mode), reason, outcome="denied")


def test_revocation_reaches_the_next_release_immediately(world, mode):
    assert release(world, mode, "rel-1").released
    world.svc.mode = "revoked"
    r = release(world, mode, "rel-2")
    assert_not_released(world.s, r, "GRANT_REVOKED", outcome="denied", deliveries=1)


#: answer mode -> the specific reason the client must give. A denial for any other reason fails.
BAD_ANSWERS = {
    "http500": "unavailable", "redirect": "unavailable", "slow": "unavailable", "huge": "unavailable",
    "garbage": "format", "unsigned": "bad_signature", "bad-sig": "bad_signature", "wrong-alg": "unsupported_alg",
    "unknown-key": "unknown_kid", "wrong-role": "wrong_role", "wrong-issuer": "echo_issuer_id",
    "bad-challenge": "echo_challenge", "bad-envelope": "echo_envelope_sha256", "bad-policy": "echo_policy_version",
    "bad-nonce": "echo_nonce", "cross-issuer": "issuer_mismatch", "naive-time": "claims", "extra-field": "body", "unknown-status": "status_value",
}


@pytest.mark.parametrize("answer", list(BAD_ANSWERS))
def test_every_way_the_answer_can_be_wrong_ends_in_a_denial_that_never_delivers(world, mode, answer):
    world.svc.mode = answer
    started = time.perf_counter()
    r = release(world, mode)
    assert time.perf_counter() - started < 1.2, "bounded by the timeout"
    assert_not_released(world.s, r, "AUTHORITY_REVALIDATION_ERROR", outcome="denied")
    assert world.rejects[-1] == BAD_ANSWERS[answer], world.rejects


def test_an_old_signed_answer_replayed_for_a_new_request_is_refused_by_the_challenge(world, mode):
    assert release(world, mode, "rel-1").released   # the service remembers this valid CURRENT answer
    world.svc.mode = "replay"
    r = release(world, mode, "rel-2")
    assert_not_released(world.s, r, "AUTHORITY_REVALIDATION_ERROR", outcome="denied", deliveries=1)
    assert world.rejects[-1] == "echo_challenge"


# ------------------------------------------------------------------------------ TLS


def test_a_service_with_an_untrusted_certificate_is_refused(world, mode):
    strict = HttpStatusRevalidator(world.svc.url, world.root, timeout=1.0, clock=world.clock)  # default trust store
    world.s.enforcer._revalidator = strict
    assert_not_released(world.s, release(world, mode), "AUTHORITY_REVALIDATION_ERROR", outcome="denied")


def test_a_certificate_for_the_wrong_hostname_is_refused(tmp_path, world, mode):
    wrong = StatusService(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, world.status,
                          world.clock, hosts=("other.example",))
    try:
        client = HttpStatusRevalidator(wrong.url, world.root, timeout=1.0, ssl_context=wrong.client_context(),
                                       clock=world.clock)
        world.s.enforcer._revalidator = client
        assert_not_released(world.s, release(world, mode), "AUTHORITY_REVALIDATION_ERROR", outcome="denied")
        assert wrong.requests == [], "no request may be sent once the identity check fails"
    finally:
        wrong.close()


def test_plain_http_is_not_accepted_at_all(world):
    with pytest.raises(ValueError):
        HttpStatusRevalidator("http://localhost:1", world.root)
    for bad in (0, -1, "3"):
        with pytest.raises(ValueError):
            HttpStatusRevalidator(world.svc.url, world.root, timeout=bad)


def test_an_unreachable_service_is_a_denial(world, mode):
    dead = HttpStatusRevalidator("https://localhost:1", world.root, timeout=0.5, clock=world.clock)
    world.s.enforcer._revalidator = dead
    assert_not_released(world.s, release(world, mode), "AUTHORITY_REVALIDATION_ERROR", outcome="denied")


# -------------------------------------------------------- the client on its own


def test_the_client_raises_a_generic_error_and_never_returns_a_partial_answer(world):
    world.svc.mode = "bad-sig"
    env = enforcer.ActionEnvelope.from_canonical_bytes(
        __import__("release_kit").envelope_for("x", world.s.artifact, release_id="r").canonical_bytes())
    claims = enforcer.GrantClaims(
        issuer_id="issuer-a", subject_id=env.subject_id, action=env.action, target_type=env.target_type,
        target_id=env.target_id, evidence_sha256=env.evidence_sha256, request_id=env.request_id,
        parameters_sha256=env.parameters_sha256, policy_version=env.policy_version, schema_version=1,
        issued_at=world.clock(), expires_at=world.clock() + __import__("datetime").timedelta(seconds=60), nonce="n")
    with pytest.raises(StatusUnavailable) as info:
        world.revalidator.revalidate(env, claims)
    assert str(info.value) == "the status answer was not accepted"
    assert world.rejects[-1] == "bad_signature"
