"""scripts/tsa_interop.py works end to end against the independent OpenSSL TSA, and refuses what it should."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from tsa_kit import Tsa

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "tsa_interop.py"
spec = importlib.util.spec_from_file_location("tsa_interop", SCRIPT)
tsa_interop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tsa_interop)


def test_a_real_round_trip_passes(tmp_path, capsys):
    t = Tsa(tmp_path)
    try:
        assert tsa_interop.main([t.url, "--cert", str(t.pem)]) == 0
    finally:
        t.close()
    assert "PASS" in capsys.readouterr().out


def test_an_authority_whose_certificate_was_not_pinned_fails(tmp_path, capsys):
    real, impostor = Tsa(tmp_path, "real"), Tsa(tmp_path, "impostor")
    try:
        assert tsa_interop.main([real.url, "--cert", str(impostor.pem)]) == 1
    finally:
        real.close()
        impostor.close()
    assert "FAIL" in capsys.readouterr().out


def test_an_unreachable_authority_fails(tmp_path, capsys):
    t = Tsa(tmp_path)
    url = t.url
    t.close()
    assert tsa_interop.main([url, "--cert", str(t.pem), "--timeout", "1"]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_a_stamped_time_far_from_this_hosts_clock_fails(tmp_path, capsys):
    t = Tsa(tmp_path)
    try:
        assert tsa_interop.main([t.url, "--cert", str(t.pem), "--max-skew", "-1"]) == 1
    finally:
        t.close()
    assert "FAIL" in capsys.readouterr().out
