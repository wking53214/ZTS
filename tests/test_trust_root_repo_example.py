"""examples/trust_root_repo: the review workflow's own script, run against real git histories, and the file's safety properties.

The workflow has never run on GitHub. What is tested here is the shell script in its review step (extracted from the
workflow file and executed with the environment GitHub would give it) and properties of the file that a careless edit
could quietly remove.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from issuer_kit import IssuerKey, trust_doc
from release_kit import Clock

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "trust_root_repo"
WORKFLOW = (EXAMPLE / ".github" / "workflows" / "trust-root-review.yml").read_text(encoding="utf-8")
CLOCK = Clock()


def review_script() -> str:
    """The `run:` block of the step named 'Review the change ...', exactly as written in the workflow."""
    lines = WORKFLOW.splitlines()
    start = next(i for i, line in enumerate(lines) if "name: Review the change" in line)
    run = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |")
    indent = len(lines[run + 1]) - len(lines[run + 1].lstrip())
    body = []
    for line in lines[run + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        body.append(line[indent:])
    return "\n".join(body) + "\n"


# ------------------------------------------------------------- properties of the file


def active_lines():
    """The workflow without comments, whole-line or trailing (a trailing '# v4.2.2' is not part of the action name)."""
    return [re.sub(r"\s+#.*$", "", line) for line in WORKFLOW.splitlines() if not line.lstrip().startswith("#")]


def test_it_runs_on_pull_request_never_pull_request_target():
    text = "\n".join(active_lines())
    assert re.search(r"^on:\n  pull_request:", text, re.M)
    assert "pull_request_target" not in text


def test_it_has_read_only_permissions_and_a_timeout():
    text = "\n".join(active_lines())
    assert re.search(r"^permissions:\n  contents: read$", text, re.M)
    assert "write" not in text.replace("persist-credentials", "")
    assert re.search(r"timeout-minutes: \d+", text)


def test_every_action_is_pinned_to_a_full_commit_and_zts_to_a_variable_not_a_branch():
    uses = re.findall(r"uses: (\S+)", "\n".join(active_lines()))
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", u) for u in uses), uses
    assert "ref: ${{ vars.ZTS_COMMIT }}" in WORKFLOW


def test_no_value_from_the_event_is_spliced_into_a_shell_command():
    script = review_script()
    assert "${{" not in script, "values reach the script through env, never by substitution"


def test_the_check_covers_the_workflow_and_the_reviewer_list_too():
    assert ".github/**" in WORKFLOW and "CODEOWNERS" in WORKFLOW
    owners = (EXAMPLE / "CODEOWNERS").read_text(encoding="utf-8")
    for path in ("/trust-root.json", "/.github/", "/CODEOWNERS"):
        assert re.search(rf"^{re.escape(path)}\s+@", owners, re.M), path


def test_the_procedure_and_the_readme_point_at_each_other():
    procedure = (ROOT / "docs" / "TRUST_ROOT_PROCEDURE.md").read_text(encoding="utf-8")
    readme = (EXAMPLE / "README.md").read_text(encoding="utf-8")
    assert "examples/trust_root_repo" in procedure and "TRUST_ROOT_PROCEDURE.md" in readme
    assert "trust_root_review.py" in procedure


# ------------------------------------------------------------- the script, on real histories


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@x"})


def doc(path, entries, serial):
    d = trust_doc(*entries)
    d["serial"] = serial
    path.write_text(json.dumps(d), encoding="utf-8")


@pytest.fixture
def repo(tmp_path):
    work = tmp_path / "repo"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    shim = tmp_path / "bin"
    shim.mkdir()
    (shim / "python").symlink_to(sys.executable)
    return work, shim, tmp_path


def run_review(repo, base_sha):
    work, shim, tmp = repo
    summary = tmp / "summary.md"
    temp = tmp / "runner"
    temp.mkdir(exist_ok=True)
    env = {**os.environ, "PATH": f"{shim}:{os.environ['PATH']}", "BASE_SHA": base_sha, "ZTS_DIR": str(ROOT),
           "RUNNER_TEMP": str(temp), "GITHUB_STEP_SUMMARY": str(summary)}
    done = subprocess.run(["bash", "-c", review_script()], cwd=work, env=env, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr, summary.read_text() if summary.exists() else ""


def commit(work, message):
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", message)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=work, capture_output=True, text=True).stdout.strip()


def test_a_good_edit_passes_and_its_review_is_written_to_the_summary(repo):
    work = repo[0]
    g, s, extra = IssuerKey("a", "grant"), IssuerKey("a", "status"), IssuerKey("a", "grant")
    doc(work / "trust-root.json", [g.entry(CLOCK), s.entry(CLOCK)], 1)
    base = commit(work, "base")
    doc(work / "trust-root.json", [g.entry(CLOCK), s.entry(CLOCK), extra.entry(CLOCK)], 2)
    commit(work, "add a key")
    code, out, summary = run_review(repo, base)
    assert code == 0, out
    assert "### Trust-root review" in summary and extra.kid in summary and f"+ " in summary


def test_bringing_back_a_revoked_key_fails_the_job_not_just_the_message(repo):
    work = repo[0]
    g, s = IssuerKey("a", "grant"), IssuerKey("a", "status")
    doc(work / "trust-root.json", [g.entry(CLOCK, status="revoked"), s.entry(CLOCK)], 1)
    base = commit(work, "base")
    doc(work / "trust-root.json", [g.entry(CLOCK), s.entry(CLOCK)], 2)
    commit(work, "un-revoke")
    code, out, summary = run_review(repo, base)
    assert code == 1, out
    assert "REVOKED and is ACTIVE again" in summary


def test_an_edit_that_does_not_raise_the_serial_fails(repo):
    work = repo[0]
    g, s = IssuerKey("a", "grant"), IssuerKey("a", "status")
    doc(work / "trust-root.json", [g.entry(CLOCK), s.entry(CLOCK)], 5)
    base = commit(work, "base")
    doc(work / "trust-root.json", [g.entry(CLOCK, status="revoked"), s.entry(CLOCK)], 5)
    commit(work, "edit without a new serial")
    code, out, _ = run_review(repo, base)
    assert code == 1 and "serial must rise" in out


def test_a_file_that_is_not_valid_fails(repo):
    work = repo[0]
    g, s = IssuerKey("a", "grant"), IssuerKey("a", "status")
    doc(work / "trust-root.json", [g.entry(CLOCK), s.entry(CLOCK)], 1)
    base = commit(work, "base")
    (work / "trust-root.json").write_text('{"version": 1, "keys": [], "keys": []}')
    commit(work, "broken")
    code, out, _ = run_review(repo, base)
    assert code == 1 and "REFUSED" in out


def test_the_first_version_of_the_file_has_nothing_to_compare_and_is_only_validated(repo):
    work = repo[0]
    (work / "README.md").write_text("x")
    base = commit(work, "base without a trust root")
    g, s = IssuerKey("a", "grant"), IssuerKey("a", "status")
    doc(work / "trust-root.json", [g.entry(CLOCK), s.entry(CLOCK)], 1)
    commit(work, "first trust root")
    code, out, _ = run_review(repo, base)
    assert code == 0 and "first version" in out


def test_a_pull_request_that_only_changes_the_workflow_does_not_fail_for_an_unchanged_serial(repo):
    work = repo[0]
    g, s = IssuerKey("a", "grant"), IssuerKey("a", "status")
    doc(work / "trust-root.json", [g.entry(CLOCK), s.entry(CLOCK)], 3)
    base = commit(work, "base")
    (work / "CODEOWNERS").write_text("# changed")
    commit(work, "only the reviewer list")
    code, out, _ = run_review(repo, base)
    assert code == 0 and "unchanged" in out
