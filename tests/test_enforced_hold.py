from zts import DeterministicIntegrityTower, Verdict, ZeroTrustSieve

TEXT = "The operator believes throughput is degraded."


def test_enforced_detect_only_finding_holds_payload_at_any_score():
    result = ZeroTrustSieve("ops").run(TEXT)
    assert "believes" in result.payload_out
    assert result.verdict is Verdict.BREACH


def test_tower_withholds_unrepaired_enforced_finding():
    tower = DeterministicIntegrityTower("ops", persist_ledger_key=False)
    assert not tower.enforce(TEXT).released
