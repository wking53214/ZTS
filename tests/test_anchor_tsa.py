"""The RFC 3161 anchor against tokens issued by OpenSSL's independent implementation.

NOT tested: interop with any public TSA (none is reachable from the build environment).
The rollback test below asserts a documented limit, not a protection.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import time

import pytest

from tsa_kit import Tsa
from zts.anchor_tsa import Rfc3161Anchor, TimestampError, build_request, head_digest, load_pinned, verify_token
from zts.ledger import ValLedger
from zts.ledger_store import FileLedgerStore, LedgerCorruptionError

KEY = b"k" * 32
HEAD = "ab" * 32


@pytest.fixture
def tsa(tmp_path):
    t = Tsa(tmp_path)
    yield t
    t.close()


def anchor_for(tsa, tmp_path, **kw):
    kw.setdefault("min_interval", 0)
    kw.setdefault("timeout", 5.0)
    return Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "receipts.jsonl", **kw)


# -------------------------------------------------------------- genuine tokens


@pytest.mark.parametrize("kind,digest", [("rsa", "sha256"), ("rsa", "sha512"), ("ec", "sha256"), ("ec", "sha384")])
def test_tokens_from_an_independent_tsa_verify_for_both_key_types_and_several_hashes(tmp_path, kind, digest):
    t = Tsa(tmp_path, kind=kind, signer_digest=digest)
    try:
        a = anchor_for(t, tmp_path)
        a.publish(3, HEAD)
        assert a.latest() == (3, HEAD)
        (seq, head, stamped), = a.verify_all()
        assert (seq, head) == (3, HEAD) and abs(dt.datetime.now(dt.timezone.utc) - stamped) < dt.timedelta(minutes=2)
    finally:
        t.close()


def test_openssls_own_verifier_agrees_the_token_is_valid(tsa, tmp_path):
    from asn1crypto import tsp
    digest = head_digest(5, HEAD)
    q = tmp_path / "q.tsq"
    q.write_bytes(build_request(digest, 12345))
    r = tmp_path / "r.tsr"
    r.write_bytes(tsa._stamp(q.read_bytes()))
    ok = subprocess.run(["openssl", "ts", "-verify", "-in", str(r), "-queryfile", str(q), "-CAfile", str(tsa.pem),
                         "-untrusted", str(tsa.pem)], capture_output=True, text=True)
    assert "Verification: OK" in ok.stdout + ok.stderr
    token = tsp.TimeStampResp.load(r.read_bytes())["time_stamp_token"].dump()
    assert verify_token(token, digest, load_pinned([tsa.pem.read_bytes()]), nonce=12345)


# -------------------------------------------------------- what the TSA can get wrong


BAD_TSA = {
    "http500": "answered 500", "garbage": "malformed", "rejected": "refused the request",
    "wrong-digest": "not the hash of this ledger head", "wrong-nonce": "nonce", "no-nonce": "nonce",
    "tamper-signature": "", "truncated": "", "huge": "too large",
}


@pytest.mark.parametrize("mode", list(BAD_TSA))
def test_every_bad_answer_is_refused_and_leaves_no_receipt(tsa, tmp_path, mode):
    tsa.mode = mode
    a = anchor_for(tsa, tmp_path)
    a.publish(1, HEAD)            # lazy publish swallows the error: the ledger write must not wait on the TSA
    with pytest.raises(TimestampError) as info:
        a.flush()
    assert BAD_TSA[mode] in str(info.value)
    assert a.latest() is None and a.failures >= 1 and a.last_error


def test_a_token_from_a_tsa_that_is_not_pinned_is_refused(tsa, tmp_path):
    tsa.other = Tsa(tmp_path, "impostor")
    try:
        tsa.mode = "other-tsa"
        a = anchor_for(tsa, tmp_path)
        a.publish(1, HEAD)
        with pytest.raises(TimestampError, match="pinned"):
            a.flush()
    finally:
        tsa.other.close()


@pytest.mark.parametrize("options,why", [
    (dict(eku="none"), "extended key usage"),
    (dict(eku="noncritical"), "critically restricted"),
    (dict(eku="serverauth"), "critically restricted"),
    (dict(not_before=-10, not_after=-5), "not valid at the stamped time"),
    (dict(not_before=5, not_after=10), "not valid at the stamped time"),
])
def test_a_pinned_certificate_that_is_unfit_for_time_stamping_is_refused(tmp_path, options, why):
    from tsa_kit import variant_cert
    t = Tsa(tmp_path)  # a good TSA signs; the operator pinned a certificate that is unfit
    try:
        unfit = variant_cert(t.pem, t.key, tmp_path / "unfit.pem", **options)
        a = Rfc3161Anchor(t.url, [unfit.read_bytes()], tmp_path / "receipts.jsonl", min_interval=0, timeout=5.0)
        a.publish(1, HEAD)
        with pytest.raises(TimestampError, match=why):
            a.flush()
    finally:
        t.close()


def test_a_signature_digest_that_is_too_weak_is_refused(tmp_path):
    t = Tsa(tmp_path, signer_digest="sha1")
    try:
        a = anchor_for(t, tmp_path)
        a.publish(1, HEAD)
        with pytest.raises(TimestampError, match="unsupported digest"):
            a.flush()
    finally:
        t.close()


def test_a_stamp_far_from_this_machines_clock_is_refused(tsa, tmp_path):
    future = lambda: dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)  # noqa: E731
    a = anchor_for(tsa, tmp_path, clock=future)
    a.publish(1, HEAD)
    with pytest.raises(TimestampError, match="clock"):
        a.flush()


def test_an_unreachable_tsa_is_bounded_by_the_timeout(tmp_path, tsa):
    a = Rfc3161Anchor("http://127.0.0.1:1/x", [tsa.pem.read_bytes()], tmp_path / "r.jsonl", timeout=0.5, min_interval=0)
    started = time.perf_counter()
    a.publish(1, HEAD)
    with pytest.raises(TimestampError, match="could not be reached"):
        a.flush()
    assert time.perf_counter() - started < 3


def test_constructor_rejects_unusable_settings(tsa, tmp_path):
    with pytest.raises(TimestampError):
        Rfc3161Anchor(tsa.url, [], tmp_path / "r.jsonl")
    with pytest.raises(TimestampError):
        Rfc3161Anchor(tsa.url, [b"not a certificate"], tmp_path / "r2.jsonl")
    with pytest.raises(ValueError):
        Rfc3161Anchor(tsa.url, [tsa.pem.read_bytes()], tmp_path / "r3.jsonl", timeout=0)


# ------------------------------------------------------------- lazy publishing


def test_publishing_is_lazy_and_never_blocks_a_ledger_write_on_the_network(tsa, tmp_path):
    a = anchor_for(tsa, tmp_path, min_interval=3600)
    ledger = ValLedger(key=KEY, store=FileLedgerStore(tmp_path / "l.jsonl"), anchor=a)
    for i in range(5):
        ledger.log("T", "OK", str(i))
    assert tsa.requests == 1, "only the first head was stamped; the rest are pending"
    assert a.latest()[0] == 0
    assert ledger.verify_anchored()[0] is True, "an anchor that lags the chain is still consistent with it"
    assert a.flush() is True and tsa.requests == 2 and a.latest()[0] == 4
    assert a.flush() is False, "nothing pending"


def test_a_failed_lazy_stamp_does_not_stop_the_ledger_and_is_visible(tsa, tmp_path):
    tsa.mode = "http500"
    a = anchor_for(tsa, tmp_path)
    ledger = ValLedger(key=KEY, store=FileLedgerStore(tmp_path / "l.jsonl"), anchor=a)
    ledger.log("T", "OK", "x")
    assert len(ledger) == 1 and a.failures == 1 and "500" in (a.last_error or "")
    tsa.mode = "normal"
    assert a.flush() is True and a.last_error is None


def test_a_tsa_that_is_down_is_tried_once_per_interval_not_on_every_ledger_write(tsa, tmp_path):
    tsa.mode = "http500"
    a = anchor_for(tsa, tmp_path, min_interval=3600)
    ledger = ValLedger(key=KEY, store=FileLedgerStore(tmp_path / "l.jsonl"), anchor=a)
    for i in range(8):
        ledger.log("T", "OK", str(i))
    assert tsa.requests == 1, "backed off after the first failure"
    with pytest.raises(TimestampError):
        a.flush()
    assert tsa.requests == 2, "an explicit flush always tries"


# -------------------------------------------- the ledger against the external anchor


def anchored_ledger(tsa, tmp_path, n=6):
    a = anchor_for(tsa, tmp_path)
    ledger = ValLedger(key=KEY, store=FileLedgerStore(tmp_path / "l.jsonl"), anchor=a)
    for i in range(n):
        ledger.log("T", "OK", str(i))
    return ledger, a


def reopen(tsa, tmp_path):
    return ValLedger(key=KEY, store=FileLedgerStore(tmp_path / "l.jsonl"), anchor=anchor_for(tsa, tmp_path))


def test_an_untouched_ledger_verifies_against_the_timestamps_after_a_restart(tsa, tmp_path):
    ledger, a = anchored_ledger(tsa, tmp_path)
    assert ledger.verify_anchored()[0] is True
    assert reopen(tsa, tmp_path).verify_anchored()[0] is True


@pytest.mark.parametrize("drop", [1, 2, 4])
def test_truncating_the_ledger_is_caught_by_the_timestamped_head(tsa, tmp_path, drop):
    anchored_ledger(tsa, tmp_path)
    p = tmp_path / "l.jsonl"
    rows = p.read_bytes().splitlines(keepends=True)
    p.write_bytes(b"".join(rows[:-drop]))
    ok, reason = reopen(tsa, tmp_path).verify_anchored()
    assert ok is False and "truncated" in reason


def test_rewriting_the_tail_is_caught(tsa, tmp_path):
    anchored_ledger(tsa, tmp_path, 5)
    p = tmp_path / "l.jsonl"
    # Build a genuinely valid alternative fifth entry on the real first four, and swap it in.
    (tmp_path / "alt").mkdir()
    rows = p.read_bytes().splitlines(keepends=True)[:4]
    (tmp_path / "alt" / "l.jsonl").write_bytes(b"".join(rows))
    alt = ValLedger(key=KEY, store=FileLedgerStore(tmp_path / "alt" / "l.jsonl"))
    alt.log("T", "OK", "a different fifth entry")
    p.write_bytes((tmp_path / "alt" / "l.jsonl").read_bytes())
    victim = reopen(tsa, tmp_path)
    assert victim.verify()[0] is True, "a walk alone finds a perfectly valid chain"
    ok, reason = victim.verify_anchored()
    assert ok is False and "replaced" in reason


def test_a_forged_or_edited_receipt_does_not_verify(tsa, tmp_path):
    ledger, a = anchored_ledger(tsa, tmp_path, 3)
    p = tmp_path / "receipts.jsonl"
    rec = json.loads(p.read_bytes().splitlines()[-1])
    rec["head"] = "cd" * 32  # claim a different head under the same token
    p.write_bytes(json.dumps(rec, sort_keys=True).encode() + b"\n")
    with pytest.raises(LedgerCorruptionError):
        anchor_for(tsa, tmp_path).latest()
    assert ledger.verify_anchored() == (False, "anchor unavailable")


def test_receipts_deleted_for_a_non_empty_ledger_fail_verification(tsa, tmp_path):
    ledger, a = anchored_ledger(tsa, tmp_path, 3)
    (tmp_path / "receipts.jsonl").write_bytes(b"")
    assert ledger.verify_anchored() == (False, "anchor holds no head")


def test_a_torn_final_receipt_line_was_never_acknowledged_and_is_ignored(tsa, tmp_path):
    ledger, a = anchored_ledger(tsa, tmp_path, 3)
    with open(tmp_path / "receipts.jsonl", "ab") as f:
        f.write(b'{"gen_time": "2026')
    assert ledger.verify_anchored()[0] is True


def test_receipts_replaced_with_ones_from_another_tsa_are_refused(tsa, tmp_path):
    ledger, _ = anchored_ledger(tsa, tmp_path, 3)
    other = Tsa(tmp_path, "other")
    try:
        (tmp_path / "other-dir").mkdir()
        a2 = Rfc3161Anchor(other.url, [other.pem.read_bytes()], tmp_path / "other-dir" / "r.jsonl", min_interval=0)
        a2.publish(2, ledger.head)
        (tmp_path / "receipts.jsonl").write_bytes((tmp_path / "other-dir" / "r.jsonl").read_bytes())
        assert ledger.verify_anchored() == (False, "anchor unavailable")
    finally:
        other.close()


# ------------------------------------------------------------------ known limit


def test_known_limit_rolling_back_the_ledger_and_the_receipts_together_is_not_detected(tsa, tmp_path):
    """A TSA proves a head existed; it does not remember your ledger. An attacker who can restore an
    older, mutually consistent ledger and receipts file leaves nothing inconsistent to find. The defense
    is keeping receipts where the writer cannot reach them (documented in the module and the operations guide)."""
    ledger, a = anchored_ledger(tsa, tmp_path, 3)
    ledger_copy = (tmp_path / "l.jsonl").read_bytes()
    receipts_copy = (tmp_path / "receipts.jsonl").read_bytes()
    for i in range(4):
        ledger.log("T", "OK", f"later {i}")
    (tmp_path / "l.jsonl").write_bytes(ledger_copy)
    (tmp_path / "receipts.jsonl").write_bytes(receipts_copy)
    assert reopen(tsa, tmp_path).verify_anchored()[0] is True, "if this ever fails, the documented limit changed"
    # but the receipts someone kept elsewhere expose it:
    kept_elsewhere = [json.loads(line) for line in receipts_copy.splitlines()]
    assert max(r["sequence"] for r in kept_elsewhere) < 6


# ------------------------------------------------- content binding and the stamped format


def test_editing_the_stamped_content_inside_a_genuine_token_is_caught_by_the_signed_message_digest(tsa, tmp_path):
    """The CMS signature covers the signed attributes, not the content. Only the message-digest
    attribute ties the two together. Patch the stamped hash inside a real token to a different
    value: the imprint check then passes, the signature over the attributes is untouched, and
    ONLY the message-digest comparison can notice."""
    from asn1crypto import tsp
    digest = head_digest(5, HEAD)
    other = head_digest(6, HEAD)
    raw = tsa._stamp(build_request(digest, 777))
    token = tsp.TimeStampResp.load(raw)["time_stamp_token"].dump()
    assert digest in token
    patched = token.replace(digest, other)
    pinned = load_pinned([tsa.pem.read_bytes()])
    assert verify_token(token, digest, pinned, nonce=777)
    with pytest.raises(TimestampError, match="signed message digest"):
        verify_token(patched, other, pinned, nonce=777)


def test_editing_the_stamped_time_inside_a_genuine_token_is_refused(tsa):
    from asn1crypto import tsp
    digest = head_digest(5, HEAD)
    token = tsp.TimeStampResp.load(tsa._stamp(build_request(digest, 778)))["time_stamp_token"].dump()
    info = tsp.TSTInfo.load(__import__("asn1crypto.cms", fromlist=["x"]).ContentInfo.load(token)["content"]
                            ["encap_content_info"]["content"].contents)
    stamp = info["gen_time"].contents
    assert stamp in token
    forged = token.replace(stamp, stamp[:4] + b"0" + stamp[5:] if stamp[4:5] != b"0" else stamp[:4] + b"1" + stamp[5:])
    assert forged != token
    with pytest.raises(TimestampError):
        verify_token(forged, digest, load_pinned([tsa.pem.read_bytes()]), nonce=778)


def test_the_stamped_value_is_domain_separated_and_its_format_is_pinned():
    import hashlib
    expected = hashlib.sha256(b"zts-ledger-head-v1\x00" + b'{"head":"' + HEAD.encode() + b'","sequence":7}').digest()
    assert head_digest(7, HEAD) == expected
    assert head_digest(7, HEAD).hex() == expected.hex()
    assert head_digest(7, HEAD) != hashlib.sha256(b'{"head":"' + HEAD.encode() + b'","sequence":7}').digest()
    assert head_digest(7, HEAD) != head_digest(8, HEAD) != head_digest(8, "cd" * 32)
