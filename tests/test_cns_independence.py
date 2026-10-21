"""ZTS is independent of CNS, and these tests hold whether or not CNS is installed.

Each runs in a fresh interpreter. Where ``cns`` is blocked outright
(``sys.modules['cns'] = None`` makes any import of it fail), the result does not
depend on what the test environment happens to contain. They never skip.
"""
import ast
import os
import subprocess
import sys
import textwrap
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PACKAGE = SRC / "zts"
BLOCK = "import sys; sys.modules['cns'] = None; sys.modules['cns.gate'] = None; sys.modules['cns.governance'] = None\n"
ENV = {"PYTHONPATH": str(SRC), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1"}


def run(code: str, *, block: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", (BLOCK if block else "") + textwrap.dedent(code)],
                          capture_output=True, text=True, env=ENV, timeout=120)


def ok(done: subprocess.CompletedProcess) -> None:
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip().endswith("ok"), done.stdout


def test_the_package_and_its_dock_import_with_cns_blocked():
    ok(run("import zts, zts.cns, zts.cli; print('ok')"))


def test_the_sieve_still_does_its_job_with_cns_blocked():
    ok(run("""
        from zts import ZeroTrustSieve, scrub
        assert ZeroTrustSieve("legal").run("As an AI, I may be wrong.").verdict.value == "breach"
        assert "leverage" not in scrub("I think we could probably leverage this methodology.")
        print('ok')
    """))


def test_the_dock_fails_closed_when_cns_is_blocked():
    ok(run("""
        from zts.cns import CNSDock, CNSUnavailableError, EpistemicStatus
        dock = CNSDock()
        try:
            dock.connect()
        except CNSUnavailableError:
            pass
        else:
            raise SystemExit("connected without cns")
        artifact = dock.unavailable()
        assert artifact.compatibility_status == "unavailable"
        assert artifact.overall_status is EpistemicStatus.UNKNOWN
        print('ok')
    """))


def test_importing_the_package_does_not_load_cns_even_when_it_is_installed():
    ok(run("""
        import sys
        import zts, zts.cns, zts.cli
        assert not [m for m in sys.modules if m == "cns" or m.startswith("cns.")], "cns was loaded"
        print('ok')
    """, block=False))


def cns_imports(tree):
    for node in ast.walk(tree):
        names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
            [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else []
        for name in names:
            if name == "cns" or name.startswith("cns."):
                yield node, name


def test_only_the_dock_imports_cns_and_only_inside_a_function():
    at_module_level, elsewhere = {}, {}
    for path in PACKAGE.rglob("*.py"):
        rel = str(path.relative_to(PACKAGE))
        tree = ast.parse(path.read_text(encoding="utf-8"))
        top = set(map(id, tree.body))
        for node, name in cns_imports(tree):
            if id(node) in top:
                at_module_level.setdefault(rel, []).append(name)
            if rel != os.path.join("cns", "adapter.py"):
                elsewhere.setdefault(rel, []).append(name)
    assert at_module_level == {}
    assert elsewhere == {}


def test_the_package_declares_no_runtime_dependency_and_pins_the_cns_extra():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert meta["dependencies"] == []
    assert meta["optional-dependencies"]["cns"] == ["cns @ git+https://github.com/wking53214/CNS.git@v1.9.0"]
