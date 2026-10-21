"""The CNS dock against the real CNS: it connects, and a CNS verdict binds what it docks.

These skip where ``cns`` is not installed. CI installs the extra and sets
ZTS_REQUIRE_CNS=1, so there they cannot skip. The dock translates and binds
only: nothing here authorizes anything.
"""
import dataclasses
import hashlib
import os

import pytest

if os.environ.get("ZTS_REQUIRE_CNS") == "1":  # CI: a missing cns is a failure, not a skip
    import cns.gate as gate
else:
    gate = pytest.importorskip("cns.gate")

import cns  # noqa: E402
from cns.governance import IdentityContext, TrustLevel  # noqa: E402

from zts.cns import (  # noqa: E402
    CNSContractError, CNSDock, CNSVerificationError, EpistemicStatus,
)
from zts.cns.adapter import cns_version_supported  # noqa: E402

SUBJECT = "zts.cns.identity"


def make_identity(**overrides) -> IdentityContext:
    fields = dict(tenant_id="tenant-1", subject_id="subject-1", roles=("reader", "auditor"),
                  trust_level=TrustLevel.VERIFIED, authentication_method="mtls", verified=True,
                  signature="sig-1")
    fields.update(overrides)
    return IdentityContext(**fields)


def issued_by_cns(identity: IdentityContext, outcome=None) -> "gate.GateResult":
    """A verdict another repository would issue: CNS's digest over the identity's own fields."""
    content = {f.name: getattr(identity, f.name) for f in dataclasses.fields(identity)}
    content["roles"] = list(content["roles"])
    content["trust_level"] = content["trust_level"].value
    return gate.GateResult(gate="other.repo.gate", position=gate.GatePosition.ALPHA,
                           outcome=outcome or gate.GateOutcome.PASS, reason="r",
                           subject=SUBJECT, subject_digest=gate.subject_digest(content))


# ------------------------------------------------------------ connecting

def test_the_installed_cns_is_a_supported_release_and_the_dock_connects_to_it():
    assert cns_version_supported(cns.__version__), cns.__version__
    dock = CNSDock()
    dock.connect()
    assert dock.validate_contract()


def test_the_artifact_records_the_cns_release_it_was_docked_against():
    artifact = CNSDock().to_zts_artifact(make_identity())
    assert artifact.cns_contract_version == cns.__version__
    assert artifact.integrity_status is EpistemicStatus.KNOWN


def test_the_dock_still_refuses_something_that_is_not_a_cns_identity():
    with pytest.raises(CNSContractError):
        CNSDock().to_zts_artifact(object())


# ------------------------------------------------------------ the digest is CNS's

def test_the_docked_digest_is_cns_subject_digest_of_the_identity_content():
    dock = CNSDock()
    identity = make_identity()
    digest = dock.to_zts_artifact(identity).subject_digest
    assert digest == gate.subject_digest(dock.identity_content(identity))
    assert len(digest) == 64 and int(digest, 16) >= 0


def test_the_docked_digest_is_no_longer_sha256_of_repr():
    dock = CNSDock()
    identity = make_identity()
    old = hashlib.sha256(dock.canonicalize(identity).encode("utf-8")).hexdigest()
    assert dock.to_zts_artifact(identity).subject_digest != old
    assert not issued_by_cns(identity).binds(SUBJECT, old)


def test_the_identity_content_is_plain_data_cns_accepts():
    content = CNSDock().identity_content(make_identity())
    assert set(content) == {f.name for f in dataclasses.fields(IdentityContext)}
    assert type(content["trust_level"]) is str and type(content["roles"]) is list


# ------------------------------------------------------------ a CNS verdict binds it

def test_a_cns_verdict_binds_the_docked_artifact():
    identity = make_identity()
    artifact = CNSDock().to_zts_artifact(identity)
    verdict = issued_by_cns(identity)
    assert verdict.bound()
    assert verdict.binds(SUBJECT, artifact.subject_digest)


def test_a_cns_verdict_binds_the_same_identity_docked_again():
    verdict = issued_by_cns(make_identity())
    assert verdict.binds(SUBJECT, CNSDock().to_zts_artifact(make_identity()).subject_digest)


CHANGES = {
    "tenant_id": dict(tenant_id="tenant-2"),
    "subject_id": dict(subject_id="subject-2"),
    "roles": dict(roles=("reader",)),
    "roles order": dict(roles=("auditor", "reader")),
    "trust_level": dict(trust_level=TrustLevel.PRIVILEGED),
    "authentication_method": dict(authentication_method="password"),
    "verified": dict(verified=False),
    "signature": dict(signature="sig-2"),
}


@pytest.mark.parametrize("name", list(CHANGES))
def test_a_cns_verdict_does_not_bind_a_different_identity(name):
    verdict = issued_by_cns(make_identity())
    other = CNSDock().to_zts_artifact(make_identity(**CHANGES[name]))
    assert not verdict.binds(SUBJECT, other.subject_digest)


def test_every_identity_field_is_covered_by_a_change_above():
    base = make_identity()
    covered = {f.name for f in dataclasses.fields(IdentityContext)
               if any(getattr(make_identity(**c), f.name) != getattr(base, f.name) for c in CHANGES.values())}
    assert covered == {f.name for f in dataclasses.fields(IdentityContext)}


@pytest.mark.parametrize("outcome", list(gate.GateOutcome))
def test_binding_does_not_depend_on_the_verdict(outcome):
    identity = make_identity()
    assert issued_by_cns(identity, outcome).binds(SUBJECT, CNSDock().to_zts_artifact(identity).subject_digest)


# ------------------------------------------------------------ verification

def test_verify_accepts_the_artifact_it_docked_and_rejects_a_transplanted_one():
    dock = CNSDock()
    identity = make_identity()
    artifact = dock.to_zts_artifact(identity)
    assert dock.verify_docked_artifact(identity, artifact)
    with pytest.raises(CNSVerificationError, match="subject digest"):
        dock.verify_docked_artifact(make_identity(signature="sig-2"), artifact)
    with pytest.raises(CNSVerificationError, match="subject digest"):
        dock.verify_docked_artifact(identity, dataclasses.replace(artifact, subject_digest="0" * 64))
    with pytest.raises(CNSVerificationError, match="canonical representation"):
        dock.verify_docked_artifact(identity, dataclasses.replace(artifact, canonical_representation="x"))
