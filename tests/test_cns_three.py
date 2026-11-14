"""CNS 3.x and later: the breaking change in 3.0.0 (subject_digest refuses str, int, float, dict, list and tuple SUBCLASSES) and the dock.

The dock accepts CNS major 3 after reading the release note. Plain values digest as before; a subclass is
refused, so an identity that carries one (a `str` Enum role, a str subclass for the tenant) cannot be docked or
released. These tests hold both halves. They need CNS 3.x or later and skip on 2.x, unless ZTS_REQUIRE_CNS_3=1.
"""

from __future__ import annotations

import enum
import os

import pytest

from release_kit import build, make_identity, request, run, static_grant, assert_not_released

cns = pytest.importorskip("cns")
MAJOR3 = int(cns.__version__.split(".")[0]) >= 3
if not MAJOR3 and os.environ.get("ZTS_REQUIRE_CNS_3") == "1":
    raise RuntimeError(f"ZTS_REQUIRE_CNS_3=1 but the installed CNS is {cns.__version__}")
pytestmark = pytest.mark.skipif(not MAJOR3, reason="needs CNS 3.x or later")

from zts.cns import CNSDock  # noqa: E402


class Role(str, enum.Enum):
    reader = "reader"
    auditor = "auditor"


class Text(str):
    pass


def docked():
    dock = CNSDock()
    dock.connect()
    return dock


def test_a_plain_identity_is_docked_and_digested_as_before():
    identity = make_identity()
    dock = docked()
    assert dock.validate_contract()
    artifact = dock.to_zts_artifact(identity)
    assert artifact.cns_contract_version == cns.__version__
    assert artifact.subject_digest == dock.subject_digest(identity)


@pytest.mark.parametrize("override", [
    {"roles": (Role.reader,)},
    {"tenant_id": Text("tenant-1")},
    {"subject_id": Text("subject-1")},
    {"authentication_method": Role.reader},
])
def test_an_identity_carrying_a_str_subclass_cannot_be_digested_or_docked(override):
    identity = make_identity(**override)
    dock = docked()
    with pytest.raises(TypeError, match="subclass"):
        dock.subject_digest(identity)
    with pytest.raises(TypeError, match="subclass"):
        dock.to_zts_artifact(identity)


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_a_release_whose_identity_turns_into_a_subclass_is_denied_and_delivers_nothing(tmp_path, mode):
    """Same values as the identity the artifact was docked from, only the TYPE differs (a str Enum equal to the
    plain text), so the denial can only come from CNS refusing the subclass, not from a changed identity."""
    s = build(tmp_path)
    assert make_identity(roles=(Role.reader, Role.auditor)) == make_identity()
    req = request(s, proof=static_grant(s), provider=None)
    object.__setattr__(req, "identity", make_identity(roles=(Role.reader, Role.auditor)))
    result = run(s, mode, req)
    assert_not_released(s, result, "CNS_IDENTITY_UNTRUSTED", outcome="denied")


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_the_control_with_plain_values_is_released(tmp_path, mode):
    s = build(tmp_path)
    assert run(s, mode, request(s, proof=static_grant(s), provider=None)).released


@pytest.mark.skipif(int(cns.__version__.split(".")[0]) < 4, reason="CNS 4.0.0 is where non-list sequences stopped digesting")
def test_cns_4_refuses_a_non_list_sequence_but_the_dock_never_hands_it_one():
    """4.0.0's breaking change: subject_digest refuses a deque or range. The dock converts the roles to a plain list first, so an
    identity that holds them in another container is still docked and digests exactly like the tuple form."""
    from collections import deque

    from cns.gate import subject_digest

    dock = docked()
    with pytest.raises(TypeError):
        subject_digest({"roles": deque(["reader"])})
    assert dock.subject_digest(make_identity(roles=deque(["reader", "auditor"]))) == dock.subject_digest(make_identity())
