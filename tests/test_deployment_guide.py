"""docs/DEPLOYMENT.md must not drift from the code it describes.

The guide's SQL is run against a real PostgreSQL, its Python is checked against the real signatures, every
readiness check of a fully assembled production tower is named in it, and the numbers it quotes are the code's.
What it says about YOUR deployment is not tested here, and cannot be.
"""

from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

from pg_kit import cluster  # noqa: F401  (session fixture)
from test_production_assembly import world  # noqa: F401  (fixture: a fully assembled production tower)
from zts.anchor_tsa import Rfc3161Anchor
from zts.ops import RECOMMENDED_LIMITS
from zts.replay_postgres import MIN_GRACE, PostgresReplayStore, PostgresSerialStore, ReplayStoreError
from zts.trust import FileTrustRoot, TrustRootError

GUIDE = Path(__file__).resolve().parents[1] / "docs" / "DEPLOYMENT.md"
TEXT = GUIDE.read_text(encoding="utf-8")


def blocks(language: str, marker: str) -> list[str]:
    pattern = rf"```{language}\n{re.escape(marker)}\n(.*?)```"
    return re.findall(pattern, TEXT, flags=re.S)


def test_the_guide_has_the_blocks_this_test_checks():
    assert len(blocks("python", "# verified-snippet")) == 2 and len(blocks("sql", "-- verified-sql")) == 1
    assert len(blocks("python", "# verified-function")) == 1


def test_the_python_blocks_import_real_names_and_call_real_signatures_with_real_keywords():
    for code in blocks("python", "# verified-snippet"):
        tree = ast.parse(code)
        scope: dict = {}
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                exec(compile(ast.Module([node], []), "<guide>", "exec"), scope)  # noqa: S102  (imports only)
        checked = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            try:
                target = eval(compile(ast.Expression(node.func), "<guide>", "eval"), scope)  # noqa: S307
            except Exception:
                continue  # a name the guide leaves to you (export_receipt, deliver, ...) or a method call
            if not (inspect.isclass(target) or inspect.isfunction(target)):
                continue
            keywords = {k.arg: None for k in node.keywords if k.arg is not None}
            try:
                inspect.signature(target).bind_partial(*[None] * len(node.args), **keywords)
            except TypeError as exc:
                pytest.fail(f"{ast.unparse(node.func)}: {exc}")
            checked += 1
        assert checked >= 2, "the block should exercise real constructors"


def test_the_sql_runs_and_the_roles_get_exactly_the_access_the_guide_claims(cluster):
    import datetime as dt

    import psycopg

    admin = cluster.dsn
    PostgresReplayStore(admin).close()
    PostgresSerialStore(admin).close()
    sql = blocks("sql", "-- verified-sql")[0]
    statements = [s.strip() for s in re.sub(r"--.*", "", sql).split(";") if s.strip()]
    with psycopg.connect(admin, autocommit=True) as conn:
        for statement in statements:
            conn.execute(statement)

    def as_role(name):
        return admin.replace("user=zts", f"user={name}")

    expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    gone = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)

    release = PostgresReplayStore(as_role("zts_release"), create=False)
    assert release.consume("i", "n1", "r1", expires_at=expires) is True
    assert release.consume("i", "n1", "r1", expires_at=expires) is False
    assert release.health() is True
    with pytest.raises(ReplayStoreError):
        release.prune()  # a release host cannot delete rows
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        release._conn().execute("ALTER TABLE zts_consumed_grants DROP CONSTRAINT zts_consumed_grants_request_id_key")
    with pytest.raises(ReplayStoreError, match="cannot create"):
        PostgresReplayStore(as_role("zts_release"), table="not_there_yet")  # and cannot create tables

    PostgresReplayStore(admin, create=False).consume("i", "old", "r-old", expires_at=gone)
    pruner = PostgresReplayStore(as_role("zts_pruner"), create=False)
    assert pruner.prune() == 1
    with pytest.raises(ReplayStoreError):
        pruner.consume("i", "n2", "r2", expires_at=expires)  # the pruner cannot consume a grant

    serial = PostgresSerialStore(as_role("zts_release"), create=False)
    serial.record(5, "d5")
    serial.record(6, "d6")
    with pytest.raises(TrustRootError):
        serial.record(5, "d5")  # a rollback is refused even for the role that may write
    with pytest.raises(TrustRootError):
        PostgresSerialStore(as_role("zts_pruner"), create=False).record(7, "d7")
    release.close(), pruner.close(), serial.close()


def test_every_readiness_check_of_a_production_tower_is_explained_in_the_guide(world):
    names = {c.name for c in world.make().tower.readiness().checks}
    assert len(names) >= 25
    missing = sorted(n for n in names if f"`{n}`" not in TEXT)
    assert missing == [], f"add these checks to section 7: {missing}"


def test_the_numbers_the_guide_quotes_are_the_codes():
    params = inspect.signature(Rfc3161Anchor).parameters
    assert params["max_unanchored_entries"].default == 500 and "(500)" in TEXT
    assert params["max_unanchored_age"].default == 300.0 and "(300 s)" in TEXT
    assert MIN_GRACE.total_seconds() == 30 and "30 seconds" in TEXT
    limits = RECOMMENDED_LIMITS
    assert limits["max_grant_lifetime_seconds"] == 300 and "5 min lifetime" in TEXT
    assert limits["allowed_clock_skew_seconds"] == 5 and "5 s skew" in TEXT
    assert limits["max_revalidation_age_seconds"] == 30 and "30 s status age" in TEXT


def test_the_guide_describes_the_trust_root_file_rules_the_code_enforces():
    from zts.trust import MAX_TRUST_BYTES

    assert MAX_TRUST_BYTES == 1 << 20 and "1 MiB" in TEXT
    assert "serial_store" in TEXT and FileTrustRoot.__init__.__kwdefaults__ is not None


def test_the_guide_uses_no_em_dashes():
    assert chr(0x2014) not in TEXT


def test_the_unfinished_release_helper_in_the_guide_finds_exactly_the_releases_with_no_ending():
    from zts.ledger import ValLedger

    scope: dict = {}
    exec(compile(blocks("python", "# verified-function")[0], "<guide>", "exec"), scope)  # noqa: S102
    find = scope["unfinished_releases"]
    ledger = ValLedger(key=b"l" * 32)
    assert find(ledger) == []
    for rid, steps in (("a", ["ATTEMPT", "RELEASING"]),                  # killed mid-delivery
                       ("b", ["ATTEMPT", "RELEASING", "RELEASED"]),      # delivered
                       ("c", ["ATTEMPT", "RELEASING", "UNCONFIRMED"]),   # delivery unknown, recorded
                       ("d", ["ATTEMPT", "HELD"]),                       # denied before delivery
                       ("e", ["ATTEMPT", "RELEASING"]),                  # killed mid-delivery
                       ("f", ["ATTEMPT", "RELEASING", "ATTEMPT", "HELD"]),   # killed, then retried and denied
                       ("g", ["ATTEMPT", "HELD", "ATTEMPT", "RELEASING", "RELEASED"]),  # denied, then delivered
                       ("h", ["ATTEMPT", "RELEASING", "HELD"])):         # the sink stopped before any effect
        for status in steps:
            ledger.log("TAP", status, "x", "payload", release_id=rid)
    ledger.log("G1", "RELEASING", "not a release entry", "payload", release_id="z")  # other layers are ignored
    assert find(ledger) == ["a", "e", "f"]



def test_every_test_file_the_guide_names_exists():
    """The traceability table in section 9 must not point at a file that was renamed or never written."""
    named = set(re.findall(r"`(test_[a-z0-9_]+\.py)`", TEXT))
    assert named, "the guide names no test file"
    missing = sorted(n for n in named if not (Path(__file__).parent / n).exists())
    assert missing == [], missing


def test_every_script_the_guide_names_exists():
    named = set(re.findall(r"scripts/([a-z0-9_]+\.py)", TEXT))
    assert {"tsa_interop.py", "trust_root_review.py"} <= named
    root = Path(__file__).resolve().parents[1] / "scripts"
    assert [n for n in sorted(named) if not (root / n).exists()] == []
