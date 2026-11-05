"""Golden wire-format vectors for zts-grant-1, zts-status-1 and the trust root.

Fixed seeds, fixed times: Ed25519 signatures are deterministic, so these bytes never change unless
the format does. They exist so someone writing an issuer or a status service in another language can
check their encoder against ZTS byte for byte. The seeds are PUBLIC TEST VALUES. Never use them.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from release_kit import enforcer  # noqa: E402
from zts.status import HttpStatusRevalidator  # noqa: E402
from zts.trust import Ed25519GrantVerifier, TrustRoot  # noqa: E402

GRANT_SEED, STATUS_SEED = bytes(range(0, 32)), bytes(range(32, 64))
TRUST_ROOT = json.loads(r'''{"keys": [{"issuer_id": "issuer-a", "kid": "ed25519-56475aa75463474c", "not_after": "2026-12-01T00:00:00+00:00", "not_before": "2026-11-01T00:00:00+00:00", "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg", "role": "grant", "status": "active"}, {"issuer_id": "issuer-a", "kid": "ed25519-24f6ed6acbfe1009", "not_after": "2026-12-01T00:00:00+00:00", "not_before": "2026-11-01T00:00:00+00:00", "public_key": "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc", "role": "status", "status": "active"}], "version": 1}''')
GRANT = b"zts-grant-1.eyJhbGciOiAiRWQyNTUxOSIsICJraWQiOiAiZWQyNTUxOS01NjQ3NWFhNzU0NjM0NzRjIiwgInR5cCI6ICJ6dHMtZ3JhbnQtMSJ9.eyJhY3Rpb24iOiAienRzLnJlbGVhc2UiLCAiZXZpZGVuY2Vfc2hhMjU2IjogImFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEiLCAiZXhwaXJlc19hdCI6ICIyMDI2LTExLTA0VDEyOjAxOjAwKzAwOjAwIiwgImlzc3VlZF9hdCI6ICIyMDI2LTExLTA0VDEyOjAwOjAwKzAwOjAwIiwgImlzc3Vlcl9pZCI6ICJpc3N1ZXItYSIsICJub25jZSI6ICJub25jZS1nb2xkZW4tMSIsICJwYXJhbWV0ZXJzX3NoYTI1NiI6ICJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwgInBvbGljeV92ZXJzaW9uIjogInBvbGljeS12MSIsICJyZXF1ZXN0X2lkIjogInJlbC1nb2xkZW4tMSIsICJzY2hlbWFfdmVyc2lvbiI6IDEsICJzdWJqZWN0X2lkIjogIjdkYmUyNWUxYzUxYWVkYzkwNDYxOTA5MDQxY2E3ODU4OGRhZDEwYzJhNGVlNDI5N2QwN2E3ZWRiZWVkNDc5M2EiLCAidGFyZ2V0X2lkIjogInRlbmFudC0xL29wcy1yZXBvcnQiLCAidGFyZ2V0X3R5cGUiOiAienRzLm91dHB1dCJ9.PxCUDn43IKYMBGeVnkOAxTc_sdmHOs_2AUyk12o_pWKoTg4xZCK7M9b8RzCrLoLQRrHOWe4teuKlV26IPPhjDA"
STATUS = b"zts-status-1.eyJhbGciOiAiRWQyNTUxOSIsICJraWQiOiAiZWQyNTUxOS0yNGY2ZWQ2YWNiZmUxMDA5IiwgInR5cCI6ICJ6dHMtc3RhdHVzLTEifQ.eyJjaGFsbGVuZ2UiOiAiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsICJjaGVja2VkX2F0IjogIjIwMjYtMTEtMDRUMTI6MDA6MTArMDA6MDAiLCAiZW52ZWxvcGVfc2hhMjU2IjogImNjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCAiaXNzdWVyX2lkIjogImlzc3Vlci1hIiwgIm5vbmNlIjogIm5vbmNlLWdvbGRlbi0xIiwgInBvbGljeV92ZXJzaW9uIjogInBvbGljeS12MSIsICJzdGF0dXMiOiAiQ1VSUkVOVCIsICJ2YWxpZF91bnRpbCI6ICIyMDI2LTExLTA0VDEyOjAwOjMwKzAwOjAwIn0.lOuY66dpaZCW8_XDfkxUyZnlthXCkD2AgNl0mQlXz7qt2qx3VWBU1-czGlGIhvJIeswIha6ujic7VGdscnCKCg"
CLAIMS = json.loads(r'''{"action": "zts.release", "evidence_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "expires_at": "2026-11-04T12:01:00+00:00", "issued_at": "2026-11-04T12:00:00+00:00", "issuer_id": "issuer-a", "nonce": "nonce-golden-1", "parameters_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "policy_version": "policy-v1", "request_id": "rel-golden-1", "schema_version": 1, "subject_id": "7dbe25e1c51aedc90461909041ca78588dad10c2a4ee4297d07a7edbeed4793a", "target_id": "tenant-1/ops-report", "target_type": "zts.output"}''')
STATUS_BODY = json.loads(r'''{"challenge": "AAAAAAAAAAAAAAAAAAAAAA", "checked_at": "2026-11-04T12:00:10+00:00", "envelope_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "issuer_id": "issuer-a", "nonce": "nonce-golden-1", "policy_version": "policy-v1", "status": "CURRENT", "valid_until": "2026-11-04T12:00:30+00:00"}''')
NOW = datetime(2026, 11, 4, 12, 0, 20, tzinfo=timezone.utc)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def signed(seed, prefix, body):
    key = Ed25519PrivateKey.from_private_bytes(seed)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = "ed25519-" + hashlib.sha256(raw).hexdigest()[:16]
    h = b64(json.dumps({"alg": "Ed25519", "kid": kid, "typ": prefix}, sort_keys=True).encode())
    c = b64(json.dumps(body, sort_keys=True).encode())
    return (f"{prefix}.{h}.{c}." + b64(key.sign(prefix.encode() + b"\x00" + h.encode() + b"." + c.encode()))).encode()


def test_the_vectors_are_what_an_independent_encoder_produces_from_the_fixed_seeds():
    assert signed(GRANT_SEED, "zts-grant-1", CLAIMS) == GRANT
    assert signed(STATUS_SEED, "zts-status-1", STATUS_BODY) == STATUS


def test_the_trust_root_vector_loads_and_names_the_keys_derived_from_the_seeds():
    root = TrustRoot.from_dict(TRUST_ROOT)
    assert {k.role for k in root.keys.values()} == {"grant", "status"}
    for entry in TRUST_ROOT["keys"]:
        raw = base64.urlsafe_b64decode(entry["public_key"] + "==")
        assert entry["kid"] == "ed25519-" + hashlib.sha256(raw).hexdigest()[:16]


def test_zts_accepts_the_grant_vector_and_decodes_every_claim():
    verifier = Ed25519GrantVerifier(TrustRoot.from_dict(TRUST_ROOT), clock=lambda: NOW)
    claims = verifier.verify_and_decode(GRANT)
    assert claims.request_id == "rel-golden-1" and claims.nonce == "nonce-golden-1"
    assert claims.target_id == "tenant-1/ops-report" and claims.schema_version == 1
    assert claims.issued_at == datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


def test_zts_accepts_the_status_vector_when_the_request_echoes_match():
    root = TrustRoot.from_dict(TRUST_ROOT)
    client = HttpStatusRevalidator("https://status.invalid", root, clock=lambda: NOW,
                                   transport=lambda url, body, timeout: STATUS)
    request = {k: STATUS_BODY[k] for k in ("challenge", "envelope_sha256", "policy_version", "issuer_id", "nonce")}
    status = client._verify(STATUS, request, enforcer)
    assert status.status.value == "CURRENT" and status.envelope_sha256 == "c" * 64
    assert status.valid_until == datetime(2026, 11, 4, 12, 0, 30, tzinfo=timezone.utc)
    stale_echo = dict(request, challenge="BBBBBBBBBBBBBBBBBBBBBB")
    from zts.trust import Rejected
    with pytest.raises(Rejected):
        client._verify(STATUS, stale_echo, enforcer)
