"""The Ed25519 grant verifier and its trust root, against an independent test issuer.

The issuer (issuer_kit.py) is a fixture with throwaway keys. These tests prove the
verifier's mechanism. They say nothing about who should own a real trust root.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pytest

from issuer_kit import IssuerKey, b64, grant_claims, sign_blob, sign_grant, trust_doc
from release_kit import Clock, enforcer, envelope_for, make_identity
from zts.cns import CNSDock
from zts.trust import (
    Ed25519GrantVerifier, FileTrustRoot, TrustRoot, TrustRootError,
)

ProofError = enforcer.ProofVerificationError


@pytest.fixture
def world(tmp_path):
    clock = Clock()
    key = IssuerKey("issuer-a")
    rejections = []
    root = TrustRoot.from_dict(trust_doc(key.entry(clock)))
    verifier = Ed25519GrantVerifier(root, clock=clock, on_reject=rejections.append)
    artifact = CNSDock().to_zts_artifact(make_identity())
    envelope = envelope_for("hello", artifact, release_id="rel-1")
    return type("W", (), dict(clock=clock, key=key, root=root, verifier=verifier, envelope=envelope,
                              rejections=rejections, tmp=tmp_path))


def refused(world, proof, reason):
    with pytest.raises(ProofError):
        world.verifier.verify_and_decode(proof)
    assert world.rejections[-1] == reason, world.rejections


# ------------------------------------------------------------------ acceptance


def test_a_grant_from_a_pinned_key_verifies_and_decodes(world):
    claims = world.verifier.verify_and_decode(sign_grant(world.envelope, world.clock, world.key))
    assert claims.issuer_id == "issuer-a" and claims.request_id == "rel-1"
    assert claims.subject_id == world.envelope.subject_id and claims.nonce == "n-1"


def test_the_verifier_id_names_the_trust_root_that_decided(world):
    assert world.verifier.verifier_id == f"zts-ed25519/{world.root.digest[:12]}"
    other = Ed25519GrantVerifier(TrustRoot.from_dict(trust_doc()), clock=world.clock)
    assert other.verifier_id != world.verifier.verifier_id


# ------------------------------------------------------- forged, altered, wrong keys


def test_a_signature_from_a_key_that_is_not_pinned_is_refused(world):
    refused(world, sign_grant(world.envelope, world.clock, IssuerKey("issuer-a")), "unknown_kid")


def test_a_forged_signature_under_a_pinned_key_id_is_refused(world):
    forger = IssuerKey("issuer-a")
    forger.kid = world.key.kid  # claims the pinned id but signs with its own key
    refused(world, sign_grant(world.envelope, world.clock, forger), "bad_signature")


@pytest.mark.parametrize("what", ["claims", "header", "signature"])
def test_any_altered_byte_of_a_signed_grant_is_refused(world, what):
    proof = sign_grant(world.envelope, world.clock, world.key)
    head, header, claims, sig = proof.split(b".")
    pick = {"claims": claims, "header": header, "signature": sig}[what]
    flipped = bytes([pick[3] ^ 1]) if False else (b"A" if pick[3:4] != b"A" else b"B")
    mutated = pick[:3] + flipped + pick[4:]
    parts = {"claims": claims, "header": header, "signature": sig}
    parts[what] = mutated
    reason = {"claims": "bad_signature", "header": None, "signature": None}[what]
    with pytest.raises(ProofError):
        world.verifier.verify_and_decode(b".".join([head, parts["header"], parts["claims"], parts["signature"]]))
    if reason:
        assert world.rejections[-1] == reason


def test_a_scope_escalation_edit_after_signing_is_refused(world):
    proof = sign_grant(world.envelope, world.clock, world.key)
    head, header, claims, sig = proof.split(b".")
    doc = json.loads(base64.urlsafe_b64decode(claims + b"=" * (-len(claims) % 4)))
    doc["target_id"] = "somewhere-else"
    edited = b64(json.dumps(doc, sort_keys=True).encode()).encode()
    refused(world, b".".join([head, header, edited, sig]), "bad_signature")


# --------------------------------------------------- algorithm downgrade and confusion


@pytest.mark.parametrize("alg", ["HS256", "none", "ed25519", "Ed448", "RS256", "", None, 25519])
def test_only_the_exact_algorithm_name_is_accepted(world, alg):
    proof = sign_grant(world.envelope, world.clock, world.key, header={"alg": alg})
    refused(world, proof, "unsupported_alg")


def test_hmac_keyed_with_the_public_key_is_refused_the_classic_confusion_attack(world):
    header = {"alg": "HS256", "kid": world.key.kid, "typ": "zts-grant-1"}
    body = grant_claims(world.envelope, world.clock, world.key)
    h, b = b64(json.dumps(header, sort_keys=True).encode()), b64(json.dumps(body, sort_keys=True).encode())
    mac = hmac.new(world.key.raw, f"zts-grant-1\x00{h}.{b}".encode(), hashlib.sha256).digest()
    refused(world, f"zts-grant-1.{h}.{b}.{b64(mac)}".encode(), "unsupported_alg")


def test_the_algorithm_must_be_in_the_signed_header_not_chosen_by_the_caller(world):
    proof = sign_grant(world.envelope, world.clock, world.key)
    head, header, claims, sig = proof.split(b".")
    swapped = b64(json.dumps({"alg": "none", "kid": world.key.kid, "typ": "zts-grant-1"}, sort_keys=True).encode())
    with pytest.raises(ProofError):
        world.verifier.verify_and_decode(b".".join([head, swapped.encode(), claims, sig]))


# ----------------------------------------------------- unknown, expired, revoked, role


def test_an_unknown_issuer_has_no_keys_so_nothing_verifies(world):
    stranger = IssuerKey("issuer-z")
    refused(world, sign_grant(world.envelope, world.clock, stranger), "unknown_kid")


def test_a_key_may_only_sign_for_its_own_issuer(world):
    refused(world, sign_grant(world.envelope, world.clock, world.key, issuer_id="issuer-b"), "issuer_mismatch")


@pytest.mark.parametrize(
    "before,after,reason",
    [(-7200, -3600, "key_window"), (3600, 7200, "key_window")],
    ids=["expired key", "not yet valid key"],
)
def test_a_key_outside_its_validity_window_is_refused(world, before, after, reason):
    key = IssuerKey("issuer-a")
    verifier = Ed25519GrantVerifier(
        TrustRoot.from_dict(trust_doc(key.entry(world.clock, before=before, after=after))),
        clock=world.clock, on_reject=world.rejections.append)
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, world.clock, key))
    assert world.rejections[-1] == reason


def test_a_grant_that_outlives_its_signing_key_is_refused(world):
    key = IssuerKey("issuer-a")
    root = TrustRoot.from_dict(trust_doc(key.entry(world.clock, after=30)))
    verifier = Ed25519GrantVerifier(root, clock=world.clock, on_reject=world.rejections.append)
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, world.clock, key, lifetime=60))
    assert world.rejections[-1] == "key_window"


def test_a_revoked_key_is_refused_even_for_a_grant_that_is_otherwise_valid(world):
    key = IssuerKey("issuer-a")
    root = TrustRoot.from_dict(trust_doc(key.entry(world.clock, status="revoked")))
    verifier = Ed25519GrantVerifier(root, clock=world.clock, on_reject=world.rejections.append)
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, world.clock, key))
    assert world.rejections[-1] == "revoked_key"


def test_a_status_key_cannot_sign_grants(world):
    key = IssuerKey("issuer-a", role="status")
    root = TrustRoot.from_dict(trust_doc(key.entry(world.clock)))
    verifier = Ed25519GrantVerifier(root, clock=world.clock, on_reject=world.rejections.append)
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, world.clock, key))
    assert world.rejections[-1] == "wrong_role"


def test_the_key_expiring_between_issue_and_use_refuses_the_grant(world):
    proof = sign_grant(world.envelope, world.clock, world.key)
    world.clock.advance(days=2)
    refused(world, proof, "key_window")


# ------------------------------------------------------------------------ malformed


@pytest.mark.parametrize("junk", [
    b"", b"x", None, "a string", 12, b"zts-grant-1", b"zts-grant-1.a.b", b"zts-grant-1.a.b.c.d",
    b"other-prefix.a.b.c", b"A" * 10_000, bytearray(b"zts-grant-1.a.b.c"),
])
def test_malformed_proofs_are_refused(world, junk):
    with pytest.raises(ProofError):
        world.verifier.verify_and_decode(junk)
    assert world.rejections[-1] in ("format", "error")


def test_padding_and_other_non_canonical_base64_are_refused(world):
    head, header, claims, sig = sign_grant(world.envelope, world.clock, world.key).split(b".")
    with pytest.raises(ProofError):
        world.verifier.verify_and_decode(b".".join([head, header + b"=", claims, sig]))
    with pytest.raises(ProofError):
        world.verifier.verify_and_decode(b".".join([head, header, claims.replace(b"-", b"+") + b"+", sig]))


def test_duplicate_keys_extra_fields_missing_fields_and_naive_times_are_refused(world):
    def signed(raw_body):
        hdr = {"alg": "Ed25519", "kid": world.key.kid, "typ": "zts-grant-1"}
        return sign_blob("zts-grant-1", hdr, {}, world.key, raw_body=raw_body)

    good = grant_claims(world.envelope, world.clock, world.key)
    dup = json.dumps(good).encode()[:-1] + b', "nonce": "again"}'
    assert world.verifier.verify_and_decode(signed(json.dumps(good).encode()))
    for bad in (dup, json.dumps({**good, "extra": 1}).encode(),
                json.dumps({k: v for k, v in good.items() if k != "nonce"}).encode(),
                json.dumps({**good, "issued_at": "2026-11-04T12:00:00"}).encode(),
                json.dumps({**good, "expires_at": 12}).encode(),
                json.dumps({**good, "schema_version": "1"}).encode(),
                json.dumps({**good, "expires_at": good["issued_at"]}).encode(),
                b'{"nonce": NaN}', b"[]", b"\xff\xfe"):
        with pytest.raises(ProofError):
            world.verifier.verify_and_decode(signed(bad))


def test_a_refusal_never_leaks_detail_to_the_caller(world):
    with pytest.raises(ProofError) as info:
        world.verifier.verify_and_decode(sign_grant(world.envelope, world.clock, IssuerKey("issuer-a")))
    assert str(info.value) == "the proof was not accepted"


def test_a_failing_alert_hook_cannot_turn_a_refusal_into_an_accept(world):
    def boom(reason):
        raise RuntimeError("alerting down")

    verifier = Ed25519GrantVerifier(world.root, clock=world.clock, on_reject=boom)
    with pytest.raises(ProofError):
        verifier.verify_and_decode(b"junk")


# -------------------------------------------------------------------- trust root file


def write_root(path, doc, mode=0o644):
    path.write_text(json.dumps(doc))
    os.chmod(path, mode)


def test_the_trust_root_file_is_loaded_and_refuses_unsafe_or_malformed_content(world):
    p = world.tmp / "trust.json"
    write_root(p, trust_doc(world.key.entry(world.clock)))
    assert world.key.kid in FileTrustRoot(p).current().keys
    os.chmod(p, 0o666)
    with pytest.raises(TrustRootError, match="writable"):
        FileTrustRoot(p)
    for bad in ({"version": 2, "keys": []}, {"version": 1}, {"version": 1, "keys": [], "x": 1},
                trust_doc({**world.key.entry(world.clock), "kid": "ed25519-" + "0" * 16}),
                trust_doc({**world.key.entry(world.clock), "role": "root"}),
                trust_doc({**world.key.entry(world.clock), "status": "maybe"}),
                trust_doc({**world.key.entry(world.clock), "extra": 1}),
                trust_doc(world.key.entry(world.clock), world.key.entry(world.clock)),
                trust_doc({**world.key.entry(world.clock), "not_after": world.key.entry(world.clock, after=-9999)["not_after"]})):
        write_root(p, bad)
        with pytest.raises(TrustRootError):
            FileTrustRoot(p)


def test_rotation_and_revocation_take_effect_without_a_restart(world):
    p = world.tmp / "trust.json"
    old, new = IssuerKey("issuer-a"), IssuerKey("issuer-a")
    write_root(p, trust_doc(old.entry(world.clock)))
    verifier = Ed25519GrantVerifier(FileTrustRoot(p), clock=world.clock, on_reject=world.rejections.append)
    assert verifier.verify_and_decode(sign_grant(world.envelope, world.clock, old))
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, world.clock, new))
    write_root(p, trust_doc(old.entry(world.clock), new.entry(world.clock)))      # add the new key
    assert verifier.verify_and_decode(sign_grant(world.envelope, world.clock, new))
    write_root(p, trust_doc(old.entry(world.clock, status="revoked"), new.entry(world.clock)))  # revoke old
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, world.clock, old))
    assert world.rejections[-1] == "revoked_key"
    assert verifier.verify_and_decode(sign_grant(world.envelope, world.clock, new))


@pytest.mark.parametrize("breakage", ["garbage", "delete", "unsafe-mode"])
def test_a_broken_trust_root_refuses_everything_with_no_fallback_to_the_old_contents(world, breakage):
    p = world.tmp / "trust.json"
    write_root(p, trust_doc(world.key.entry(world.clock)))
    verifier = Ed25519GrantVerifier(FileTrustRoot(p), clock=world.clock, on_reject=world.rejections.append)
    proof = sign_grant(world.envelope, world.clock, world.key)
    assert verifier.verify_and_decode(proof)
    if breakage == "garbage":
        p.write_text("{not json")
    elif breakage == "delete":
        p.unlink()
    else:
        os.chmod(p, 0o666)
    with pytest.raises(ProofError):
        verifier.verify_and_decode(proof)
    assert world.rejections[-1] == "trust_root"
    assert verifier.verifier_id == "zts-ed25519/unavailable"


def test_a_trust_root_that_does_not_match_its_pinned_digest_is_refused(world):
    p = world.tmp / "trust.json"
    write_root(p, trust_doc(world.key.entry(world.clock)))
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    FileTrustRoot(p, expected_sha256=digest)
    with pytest.raises(TrustRootError, match="pinned digest"):
        FileTrustRoot(p, expected_sha256="0" * 64)
    verifier = Ed25519GrantVerifier(FileTrustRoot(p, expected_sha256=digest), clock=world.clock)
    write_root(p, trust_doc(world.key.entry(world.clock), IssuerKey("issuer-a").entry(world.clock)))  # edited
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, world.clock, world.key))


def test_an_empty_trust_root_is_valid_and_trusts_nothing(world):
    verifier = Ed25519GrantVerifier(TrustRoot.from_dict(trust_doc()), clock=world.clock)
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, world.clock, world.key))


def test_clock_skew_in_the_future_cannot_resurrect_an_expired_key(world):
    key = IssuerKey("issuer-a")
    root = TrustRoot.from_dict(trust_doc(key.entry(world.clock, after=10)))
    world.clock.advance(seconds=11)
    verifier = Ed25519GrantVerifier(root, clock=world.clock, on_reject=world.rejections.append)
    with pytest.raises(ProofError):
        verifier.verify_and_decode(sign_grant(world.envelope, Clock(), key))
    assert world.rejections[-1] == "key_window"


def test_a_non_canonical_spelling_of_a_valid_signature_is_refused_no_malleability(world):
    """The last base64 character of a 64-byte signature has two spare bits. A variant that
    decodes to the same bytes must not be accepted as a second spelling of the same proof."""
    proof = sign_grant(world.envelope, world.clock, world.key)
    head, header, claims, sig = proof.split(b".")
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(sig[-1:])
    twin = alphabet[(last & ~0b11) | ((last + 1) & 0b11):][:1]
    assert twin != sig[-1:] and base64.urlsafe_b64decode(sig[:-1] + twin + b"==") == base64.urlsafe_b64decode(sig + b"==")
    refused(world, b".".join([head, header, claims, sig[:-1] + twin]), "format")


# --------------------------------------------- end to end through the real tower


def stack_with_ed25519(tmp_path, key, *, root_entries=None):
    from release_kit import build
    clock = Clock()
    root = TrustRoot.from_dict(trust_doc(*(root_entries or [key.entry(clock)])))
    s = build(tmp_path, clock=clock, verifier=Ed25519GrantVerifier(root, clock=clock))
    return s, root


def issuer_provider(s, key, **kw):
    def provide(candidate):
        s.candidates.append(candidate)
        options = {"nonce": f"n-{len(s.candidates)}", **kw}
        return sign_grant(enforcer.ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes),
                          s.clock, key, **options)
    return provide


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_a_grant_signed_by_a_pinned_key_releases_through_the_real_tower(tmp_path, mode):
    from release_kit import request, run
    key = IssuerKey("issuer-a")
    s, _ = stack_with_ed25519(tmp_path, key)
    r = run(s, mode, request(s, provider=issuer_provider(s, key)))
    assert r.release_outcome == "delivered" and len(s.sink.calls) == 1
    assert r.authorization["decision"]["verifier_id"].startswith("zts-ed25519/")


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("attack", ["unknown-key", "revoked-key", "wrong-algorithm", "forged"])
def test_bad_proofs_never_reach_the_delivery_callback(tmp_path, mode, attack):
    from release_kit import assert_not_released, request, run
    key = IssuerKey("issuer-a")
    clock = Clock()
    entry = key.entry(clock, status="revoked" if attack == "revoked-key" else "active")
    s, _ = stack_with_ed25519(tmp_path, key, root_entries=[entry])
    signer = IssuerKey("issuer-a") if attack == "unknown-key" else key
    kw = {"header": {"alg": "HS256"}} if attack == "wrong-algorithm" else {}
    if attack == "forged":
        signer = IssuerKey("issuer-a")
        signer.kid = key.kid
    r = run(s, mode, request(s, provider=issuer_provider(s, signer, **kw)))
    assert_not_released(s, r, "PROOF_INVALID", outcome="denied")


def test_a_replayed_ed25519_grant_is_denied_by_enforcer(tmp_path):
    from release_kit import request, run
    key = IssuerKey("issuer-a")
    s, _ = stack_with_ed25519(tmp_path, key)
    envelope_grant = {}

    def once(candidate):
        envelope_grant.setdefault("proof", sign_grant(
            enforcer.ActionEnvelope.from_canonical_bytes(candidate.envelope_bytes), s.clock, key))
        return envelope_grant["proof"]

    assert run(s, "sync", request(s, provider=once)).released
    again = run(s, "sync", request(s, provider=once))
    assert again.released is False and again.reason_code == "GRANT_REPLAYED" and len(s.sink.calls) == 1
