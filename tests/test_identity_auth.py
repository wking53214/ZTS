"""Identity authentication: Ed25519IdentityVerifier, the identity trust-root role, the reference signer and readiness.

The signer in examples/identity_provider is deliberately independent of ZTS (it only needs `cryptography`), so these tests are
also the check that the format can be implemented from its description.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from issuer_kit import IssuerKey, b64, trust_doc
from release_kit import Clock, build, request, run, static_grant
from zts.identity import Ed25519IdentityVerifier, identity_binding_bytes
from zts.trust import FileTrustRoot, TrustRoot, TrustRootError

SIGNER = Path(__file__).resolve().parents[1] / "examples" / "identity_provider" / "sign_identity.py"
spec = importlib.util.spec_from_file_location("sign_identity", SIGNER)
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)

AUD = "zts-release/test"
CLOCK = Clock()
NOW = int(CLOCK().timestamp())


@dataclass(frozen=True)
class Identity:
    tenant_id: str = "tenant-1"
    subject_id: str = "alice"
    roles: tuple = ("reader", "auditor")
    trust_level: str = "verified"
    authentication_method: str = "oidc"
    verified: bool = True
    signature: str = ""


@pytest.fixture
def idp():
    return IssuerKey("idp", "identity")


def root_for(*keys, status="active"):
    return TrustRoot.from_dict(trust_doc(*[k.entry(CLOCK, status=status) for k in keys]))


def verifier(idp, **kw):
    kw.setdefault("clock", CLOCK)
    return Ed25519IdentityVerifier(root_for(idp), audience=AUD, **kw)


def signed(idp, identity=None, **kw):
    identity = identity or Identity()
    args = dict(tenant_id=identity.tenant_id, subject_id=identity.subject_id, roles=identity.roles,
                trust_level=identity.trust_level, authentication_method=identity.authentication_method,
                audience=AUD, issued_at=NOW - 10, lifetime_seconds=120)
    args.update(kw)
    return replace(identity, signature=signer.sign_identity(idp.private, **args))


# ------------------------------------------------------------------------ the format


def test_the_binding_bytes_are_frozen():
    """If this changes, every identity provider's signer breaks. It is the format, written out."""
    assert identity_binding_bytes(Identity()) == (
        b'{"authentication_method":"oidc","roles":["reader","auditor"],"subject_id":"alice",'
        b'"tenant_id":"tenant-1","trust_level":"verified","verified":true}')


def test_an_independently_written_signer_is_accepted(idp):
    assert verifier(idp)(signed(idp)) is True


def test_unicode_in_an_identity_is_signed_and_verified_as_utf8(idp):
    who = Identity(subject_id="zoë-日本", tenant_id="тенант")
    assert verifier(idp)(signed(idp, who)) is True


# ------------------------------------------------------------- every change after signing is caught


@pytest.mark.parametrize("field,value", [
    ("tenant_id", "tenant-2"), ("subject_id", "mallory"), ("roles", ("reader", "auditor", "admin")),
    ("roles", ("reader",)), ("roles", ("auditor", "reader")), ("trust_level", "high"), ("authentication_method", "password"),
])
def test_changing_any_signed_field_after_signing_is_refused(idp, field, value):
    good = signed(idp)
    reasons = []
    assert verifier(idp, on_reject=reasons.append)(replace(good, **{field: value})) is False
    assert reasons == ["bad_signature"]


def test_an_identity_not_marked_verified_is_refused_even_if_someone_signed_it(idp):
    reasons = []
    assert verifier(idp, on_reject=reasons.append)(replace(signed(idp), verified=False)) is False
    assert reasons == ["not_verified"]


@pytest.mark.parametrize("damage", [
    lambda s: s[:-3] + ("AAA" if not s.endswith("AAA") else "BBB"),   # the signature bytes
    lambda s: s.replace("zts-identity-1.", "zts-identity-2.", 1),
    lambda s: s + ".extra",
    lambda s: s.rsplit(".", 1)[0],
    lambda s: "",
    lambda s: "not a signature",
    lambda s: s.replace(".", "..", 1),
    lambda s: "é" + s,
    lambda s: s + "=",
])
def test_a_damaged_signature_string_is_refused(idp, damage):
    good = signed(idp)
    assert verifier(idp)(replace(good, signature=damage(good.signature))) is False


@pytest.mark.parametrize("value", [None, b"zts-identity-1.a.b.c", 5, ["x"], "x" * 5000])
def test_a_signature_that_is_not_a_reasonable_string_is_refused(idp, value):
    assert verifier(idp)(Identity(signature=value)) is False


# ---------------------------------------------------------------------- audience, time, keys


def test_an_identity_signed_for_another_audience_is_refused(idp):
    reasons = []
    other = signed(idp, audience="some-other-service")
    assert verifier(idp, on_reject=reasons.append)(other) is False and reasons == ["audience"]


def test_an_expired_identity_is_refused(idp):
    reasons = []
    old = signed(idp, issued_at=NOW - 500, lifetime_seconds=120)
    assert verifier(idp, on_reject=reasons.append)(old) is False and reasons == ["expired"]


def test_an_identity_dated_in_the_future_is_refused_beyond_the_skew_only(idp):
    reasons = []
    assert verifier(idp, on_reject=reasons.append)(signed(idp, issued_at=NOW + 60)) is False and reasons == ["not_yet_valid"]
    assert verifier(idp)(signed(idp, issued_at=NOW + 3)) is True


@pytest.mark.parametrize("lifetime,ok", [(300, True), (301, False), (1, True)])
def test_a_longer_life_than_allowed_is_refused(idp, lifetime, ok):
    assert verifier(idp)(signed(idp, lifetime_seconds=lifetime, issued_at=NOW - 0)) is ok


def test_a_lifetime_that_does_not_end_after_it_starts_is_refused(idp):
    assert verifier(idp)(signed(idp, lifetime_seconds=0)) is False
    assert verifier(idp)(signed(idp, lifetime_seconds=-5)) is False


def test_the_allowed_life_and_skew_are_configurable_and_validated(idp):
    assert verifier(idp, max_lifetime=600)(signed(idp, lifetime_seconds=500)) is True
    for bad in (0, -1, True, "5", None):
        with pytest.raises(ValueError):
            verifier(idp, max_lifetime=bad)
        with pytest.raises(ValueError):
            verifier(idp, max_skew=bad)
    for bad in ("", "  ", None, 5):
        with pytest.raises(ValueError, match="audience"):
            Ed25519IdentityVerifier(root_for(idp), audience=bad)


def test_an_unknown_key_is_refused(idp):
    other = IssuerKey("idp", "identity")
    reasons = []
    assert verifier(idp, on_reject=reasons.append)(signed(other)) is False and reasons == ["unknown_kid"]


def test_a_revoked_key_is_refused(idp):
    reasons = []
    v = Ed25519IdentityVerifier(root_for(idp, status="revoked"), audience=AUD, clock=CLOCK, on_reject=reasons.append)
    assert v(signed(idp)) is False and reasons == ["revoked_key"]


def test_a_key_whose_window_has_not_begun_or_has_ended_is_refused(idp):
    reasons = []
    early = TrustRoot.from_dict(trust_doc(idp.entry(CLOCK, before=3600, after=7200)))
    late = TrustRoot.from_dict(trust_doc(idp.entry(CLOCK, before=-7200, after=-3600)))
    for root in (early, late):
        v = Ed25519IdentityVerifier(root, audience=AUD, clock=CLOCK, on_reject=reasons.append)
        assert v(signed(idp)) is False
    assert reasons == ["key_window", "key_window"]


def test_a_signed_identity_must_fit_inside_the_keys_validity_window(idp):
    short = TrustRoot.from_dict(trust_doc(idp.entry(CLOCK, before=-5, after=30)))
    reasons = []
    v = Ed25519IdentityVerifier(short, audience=AUD, clock=CLOCK, on_reject=reasons.append)
    assert v(signed(idp, issued_at=NOW - 20, lifetime_seconds=120)) is False and reasons[-1] == "key_window"


@pytest.mark.parametrize("role", ["grant", "status"])
def test_a_key_of_another_role_cannot_vouch_for_an_identity(role):
    wrong = IssuerKey("idp", role)
    reasons = []
    v = Ed25519IdentityVerifier(root_for(wrong), audience=AUD, clock=CLOCK, on_reject=reasons.append)
    assert v(signed(wrong)) is False and reasons == ["wrong_role"]


def test_an_identity_key_cannot_sign_grants_either(idp):
    """The roles do not leak in the other direction: the grant verifier refuses an identity-role key."""
    pytest.importorskip("enforcer")
    from zts.trust import Ed25519GrantVerifier
    from release_kit import enforcer
    reasons = []
    verifier_ = Ed25519GrantVerifier(root_for(idp), clock=CLOCK, on_reject=reasons.append)
    from issuer_kit import sign_blob
    proof = sign_blob("zts-grant-1", {"alg": "Ed25519", "kid": idp.kid, "typ": "zts-grant-1"}, {"x": 1}, idp)
    with pytest.raises(enforcer.ProofVerificationError):
        verifier_.verify_and_decode(proof)
    assert reasons == ["wrong_role"]


def test_the_trust_root_still_refuses_a_role_it_does_not_know():
    entry = dict(IssuerKey("idp", "identity").entry(CLOCK), role="admin")
    with pytest.raises(TrustRootError):
        TrustRoot.from_dict(trust_doc(entry))


# --------------------------------------------------------------- a valid signature, a bad payload


def raw_signed(idp, identity, payload_bytes):
    """A genuinely signed identity whose payload is whatever the test wants: only strict parsing can refuse it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: F401
    h = signer._b64u(json.dumps({"alg": "Ed25519", "kid": idp.kid, "typ": "zts-identity-1"}, sort_keys=True,
                                separators=(",", ":")).encode()).encode()
    p = signer._b64u(payload_bytes).encode()
    sig = idp.private.sign(b"zts-identity-1\x00" + h + b"." + p + b"\x00" + identity_binding_bytes(identity))
    return replace(identity, signature=f"zts-identity-1.{h.decode()}.{p.decode()}.{signer._b64u(sig)}")


@pytest.mark.parametrize("payload", [
    b'{"aud":"zts-release/test","exp":%d,"iat":%d,"iat":%d}' % (NOW + 60, NOW, NOW),            # repeated key
    b'{"aud":"zts-release/test","exp":%d,"iat":%d,"extra":1}' % (NOW + 60, NOW),                 # extra field
    b'{"aud":"zts-release/test","exp":%d}' % (NOW + 60),                                         # missing field
    b'{"aud":"zts-release/test","exp":%d.5,"iat":%d}' % (NOW + 60, NOW),                         # float
    b'{"aud":"zts-release/test","exp":true,"iat":%d}' % NOW,                                     # bool
    b'{"aud":"zts-release/test","exp":NaN,"iat":%d}' % NOW,                                      # NaN
    b'{"aud":"zts-release/test","exp":"%d","iat":%d}' % (NOW + 60, NOW),                         # string
    b'[1,2,3]', b'null', b'{ nope', b'\xff\xfe',
])
def test_a_correctly_signed_but_malformed_payload_is_refused(idp, payload):
    assert verifier(idp)(raw_signed(idp, Identity(), payload)) is False


def test_the_same_well_formed_payload_is_accepted(idp):
    ok = b'{"aud":"zts-release/test","exp":%d,"iat":%d}' % (NOW + 60, NOW - 5)
    assert verifier(idp)(raw_signed(idp, Identity(), ok)) is True


# --------------------------------------------------------------------- never raises


class Weird:
    pass


@pytest.mark.parametrize("thing", [None, 5, "text", Weird(), object(), Identity(roles="reader"), Identity(roles=(1, 2)),
                                   Identity(tenant_id=""), Identity(subject_id="  "), Identity(trust_level=None)])
def test_anything_that_is_not_a_proper_identity_is_a_false_never_an_exception(idp, thing):
    assert verifier(idp)(thing) is False


def test_an_enum_trust_level_is_read_by_value_like_cns_does(idp):
    import enum

    class Level(str, enum.Enum):
        verified = "verified"

    who = Identity(trust_level=Level.verified)
    assert verifier(idp)(replace(who, signature=signed(idp, Identity()).signature)) is True


def test_a_broken_alerting_hook_cannot_turn_a_refusal_into_an_acceptance(idp):
    def boom(reason):
        raise RuntimeError("alerting is down")

    assert verifier(idp, on_reject=boom)(replace(signed(idp), subject_id="mallory")) is False


def test_the_reason_never_contains_the_identity_or_the_signature(idp):
    seen = []
    bad = replace(signed(idp), subject_id="mallory-the-subject")
    verifier(idp, on_reject=seen.append)(bad)
    assert seen and all(len(r) < 20 and "mallory" not in r and "zts-identity" not in r for r in seen)


# ---------------------------------------------------------- rotation and revocation, no restart


def test_revoking_the_key_in_the_file_stops_acceptance_on_the_next_use(tmp_path, idp):
    import os
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(trust_doc(idp.entry(CLOCK))))
    os.chmod(path, 0o644)
    v = Ed25519IdentityVerifier(FileTrustRoot(path), audience=AUD, clock=CLOCK)
    token = signed(idp)
    assert v(token) is True
    path.write_text(json.dumps(trust_doc(idp.entry(CLOCK, status="revoked"))))
    os.chmod(path, 0o644)
    os.utime(path, (time.time() + 5, time.time() + 5))
    assert v(token) is False


def test_a_broken_trust_root_refuses_everything(tmp_path, idp):
    import os
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(trust_doc(idp.entry(CLOCK))))
    os.chmod(path, 0o644)
    reasons = []
    v = Ed25519IdentityVerifier(FileTrustRoot(path), audience=AUD, clock=CLOCK, on_reject=reasons.append)
    token = signed(idp)
    path.write_text("{ broken")
    os.chmod(path, 0o644)
    os.utime(path, (time.time() + 5, time.time() + 5))
    assert v(token) is False and reasons == ["trust_root"]


def test_known_limit_a_stolen_signed_identity_works_until_it_expires(idp):
    """The signed identity is a bearer credential. Asserted so a change to it is noticed, not as a claim it is fine."""
    token, v = signed(idp), verifier(idp)
    assert v(token) is True and v(token) is True


# ------------------------------------------------------------ through the real release gate


class Ticking(Clock):
    """A clock that jumps forward after the first reading, so the check just before delivery sees a later time."""

    def __init__(self):
        super().__init__()
        self.reads = 0

    def __call__(self):
        self.reads += 1
        return super().__call__() + (timedelta(seconds=1000) if self.reads > 1 else timedelta(0))


def real_identity(idp, **kw):
    pytest.importorskip("cns")
    from release_kit import make_identity
    plain = make_identity()
    token = signer.sign_identity(idp.private, tenant_id=plain.tenant_id, subject_id=plain.subject_id, roles=plain.roles,
                                 trust_level=getattr(plain.trust_level, "value", plain.trust_level),
                                 authentication_method=plain.authentication_method, audience=AUD,
                                 issued_at=NOW - 10, lifetime_seconds=120, **kw)
    return replace(plain, signature=token)


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_a_signed_identity_releases_and_an_unsigned_one_is_denied(tmp_path, idp, mode):
    from release_kit import assert_not_released, make_identity
    good = real_identity(idp)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    s = build(tmp_path / "a", identity=good, identity_verifier=verifier(idp))
    assert run(s, mode, request(s, proof=static_grant(s), provider=None)).released

    bad = make_identity()  # signature "sig-1": nobody vouched for this identity
    s2 = build(tmp_path / "b", identity=bad, identity_verifier=verifier(idp))
    assert_not_released(s2, run(s2, mode, request(s2, proof=static_grant(s2), provider=None)),
                        "IDENTITY_NOT_AUTHENTICATED", outcome="denied")


def test_the_identity_is_checked_again_just_before_delivery_not_only_at_the_start(tmp_path, idp):
    """The first check passes; by the second the signed identity has expired, so nothing is delivered and the grant is spent."""
    from release_kit import assert_not_released
    ticking = Ticking()
    v = Ed25519IdentityVerifier(root_for(idp), audience=AUD, clock=ticking)
    s = build(tmp_path, identity=real_identity(idp), identity_verifier=v)
    result = run(s, "sync", request(s, proof=static_grant(s), provider=None))
    assert_not_released(s, result, "IDENTITY_NOT_AUTHENTICATED", outcome="failed_before_delivery")
    assert ticking.reads >= 2


def test_the_grant_is_bound_to_the_exact_signed_identity(idp):
    """The signature is part of the subject digest the grant binds, so a grant issued for one token does not fit another."""
    pytest.importorskip("cns")
    from release_kit import make_identity
    from zts.cns import CNSDock
    dock = CNSDock()
    dock.connect()
    plain = make_identity()
    common = dict(tenant_id=plain.tenant_id, subject_id=plain.subject_id, roles=plain.roles,
                  trust_level=getattr(plain.trust_level, "value", plain.trust_level),
                  authentication_method=plain.authentication_method, audience=AUD, lifetime_seconds=120)
    first = replace(plain, signature=signer.sign_identity(idp.private, issued_at=NOW - 10, **common))
    second = replace(plain, signature=signer.sign_identity(idp.private, issued_at=NOW - 9, **common))
    assert dock.subject_digest(first) != dock.subject_digest(second)


# ----------------------------------------------------------------------------- readiness


def real_now():
    """Readiness compares key windows with the real clock, so its tests date their keys in real time."""
    return datetime.now(timezone.utc)


def live_verifier(idp, **kw):
    return Ed25519IdentityVerifier(TrustRoot.from_dict(trust_doc(idp.entry(real_now), **kw)), audience=AUD)


def test_readiness_passes_for_zts_own_verifier_with_a_usable_key_and_says_what_it_cannot_know(idp):
    from zts.ops import _probe_identity
    check = _probe_identity(live_verifier(idp))
    assert check.status == "PASS" and AUD in check.detail and "not something this can check" in check.detail


def test_readiness_fails_when_there_is_no_usable_identity_key(idp):
    from zts.ops import _probe_identity
    gone = Ed25519IdentityVerifier(root_for(idp, status="revoked"), audience=AUD, clock=CLOCK)
    assert _probe_identity(gone).status == "FAIL"
    only_grant = Ed25519IdentityVerifier(root_for(IssuerKey("a", "grant")), audience=AUD, clock=CLOCK)
    assert _probe_identity(only_grant).status == "FAIL"


def test_readiness_stays_unknown_for_a_custom_hook_however_it_is_named_and_when_there_is_none():
    from zts.ops import _probe_identity

    class Lookalike:
        audience = "zts-release/test"
        trust = None

        def __call__(self, identity):
            return True

    assert _probe_identity(Lookalike()).status == "UNKNOWN"
    assert _probe_identity(lambda identity: True).status == "UNKNOWN"
    assert _probe_identity(None).status == "UNKNOWN"


def test_the_live_check_counts_usable_identity_keys_and_degrades_when_the_file_is_emptied(tmp_path, idp):
    import os
    from zts.ops import _runtime_adapters
    path = tmp_path / "trust.json"

    def write(doc):
        path.write_text(json.dumps(doc))
        os.chmod(path, 0o644)
        os.utime(path, (time.time() + 5, time.time() + 5))

    write(trust_doc(idp.entry(real_now)))
    v = Ed25519IdentityVerifier(FileTrustRoot(path), audience=AUD)
    gate = type("G", (), {"identity_verifier": v, "enforcer": None})()
    assert {c.name: c.status for c in _runtime_adapters(gate)} == {"trust_root_identity_keys": "PASS"}
    write(trust_doc())
    assert {c.name: c.status for c in _runtime_adapters(gate)} == {"trust_root_identity_keys": "FAIL"}


def test_an_unexpected_failure_inside_the_check_is_a_refusal_not_an_exception(idp):
    """A clock that fails, or any other surprise, must not escape as an exception that a caller might treat as 'no answer'."""
    def broken_clock():
        raise RuntimeError("clock source is down")

    reasons = []
    v = Ed25519IdentityVerifier(root_for(idp), audience=AUD, clock=broken_clock, on_reject=reasons.append)
    assert v(signed(idp)) is False and reasons == ["error"]
