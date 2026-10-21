"""The CNS version rule: a floor within one major version, never one exact release.

The dock once demanded exactly CNS 1.4.0 and raised on every later release,
1.7.0 and the current 1.9.0 included. These tests pin the rule so that cannot
come back. They do not need CNS: the dock is pointed at stand-in ``cns``
modules declaring whatever version a test asks for, so they never skip.
"""
import sys
import types
from dataclasses import dataclass

import pytest

from zts.cns import CNS_CONTRACT_VERSION, CNSContractError, CNSDock
from zts.cns.adapter import cns_version_supported


@dataclass(frozen=True)
class IdentityContext:
    tenant_id: str
    subject_id: str
    roles: tuple
    trust_level: str
    authentication_method: str
    verified: bool
    signature: str


def stand_in_cns(monkeypatch, version):
    cns = types.ModuleType("cns")
    gate = types.ModuleType("cns.gate")
    governance = types.ModuleType("cns.governance")
    if version is not None:
        cns.__version__ = version
    gate.subject_digest = lambda content: "stand-in digest"
    governance.IdentityContext = IdentityContext
    cns.gate, cns.governance = gate, governance
    monkeypatch.setitem(sys.modules, "cns", cns)
    monkeypatch.setitem(sys.modules, "cns.gate", gate)
    monkeypatch.setitem(sys.modules, "cns.governance", governance)


def test_the_floor_is_the_release_the_seam_was_frozen_against():
    assert CNS_CONTRACT_VERSION == "1.4.0"


@pytest.mark.parametrize("version", ["1.4.0", "1.4.1", "1.5.0", "1.7.0", "1.8.0", "1.9.0", "1.10.0", "1.40.2"])
def test_every_release_of_the_same_major_at_or_above_the_floor_is_accepted(version):
    assert cns_version_supported(version)


@pytest.mark.parametrize("version", ["1.3.9", "1.0.0", "0.9.0", "0.2.0", "2.0.0", "3.1.0"])
def test_a_release_below_the_floor_or_of_another_major_is_refused(version):
    assert not cns_version_supported(version)


@pytest.mark.parametrize("version", [None, "", "1.9", "1.9.0.1", "v1.9.0", "1.9.0rc1", " 1.9.0", 1.9, (1, 9, 0)])
def test_a_version_that_is_not_plain_x_y_z_is_refused(version):
    assert not cns_version_supported(version)


@pytest.mark.parametrize("version", ["1.4.0", "1.7.0", "1.9.0", "1.10.0"])
def test_connect_accepts_a_later_release_and_records_it(monkeypatch, version):
    stand_in_cns(monkeypatch, version)
    dock = CNSDock()
    dock.connect()
    assert dock.validate_contract()
    identity = IdentityContext("t", "s", ("r",), "verified", "mtls", True, "sig")
    assert dock.to_zts_artifact(identity).cns_contract_version == version


@pytest.mark.parametrize("version", ["1.3.0", "2.0.0", None, "1.9.0rc1"])
def test_connect_refuses_an_unsupported_release(monkeypatch, version):
    stand_in_cns(monkeypatch, version)
    with pytest.raises(CNSContractError, match="incompatible CNS version"):
        CNSDock().connect()
