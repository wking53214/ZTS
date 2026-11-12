# A repository for the ZTS trust root, with a two-person review

Copy this folder's contents into a **separate private repository** whose only job is to hold `trust-root.json`. The
procedure it supports is [TRUST_ROOT_PROCEDURE.md](../../docs/TRUST_ROOT_PROCEDURE.md); read that first.

**Status: the check's logic is tested here (`tests/test_trust_root_repo_example.py` runs the workflow's own script against
real git histories). The workflow itself has never run on GitHub, and branch protection is something only you can switch on.**

## Files

| File | Purpose |
|---|---|
| `trust-root.json` | the trust root itself (you create it; format in DEPLOYMENT.md section 2) |
| `CODEOWNERS` | names the reviewers GitHub will require. Replace `@YOUR-ORG/trust-root-reviewers` |
| `.github/workflows/trust-root-review.yml` | runs ZTS's review tool on every pull request and posts its output |

## One-time setup

1. Create the private repository and add the three files above. Commit the first `trust-root.json` through a pull request too.
2. Create a team of reviewers (two or more people who each understand the output of the review tool) and put it in `CODEOWNERS`.
3. Settings, Secrets: add `ZTS_READ_TOKEN`, a token with **read-only** access to the ZTS repository (skip if ZTS is public).
4. Settings, Variables: add `ZTS_COMMIT`, the full 40-character ZTS commit whose review tool you have read and trust. Move it
   deliberately, as a reviewed change, never to a branch name.
5. Settings, Branches, protect `main`:
   - require a pull request before merging, with **at least 1 approval from a code owner**;
   - **dismiss stale approvals** when new commits are pushed;
   - require the status check `trust-root-review` to pass;
   - require approval of the **most recent push** by someone other than the person who pushed it;
   - **include administrators** (no bypass), and restrict who can push to `main` to nobody;
   - require signed commits if your team signs them.
6. Open a test pull request that raises the serial and adds a key, and one that un-revokes a key. The first should pass, the
   second should fail the check. Do not rely on the set-up until you have seen both.

## What the check does and does not do

It fails a pull request whose `trust-root.json` is invalid under ZTS's parser, does not raise the serial, brings back a
revoked key, or changes the role or issuer of an existing key id. It puts the full key table and the diff on the pull request.
It does **not** know whether a new key belongs to your issuer. The second person must confirm that out of band (ask the
issuer's key custodian for the key id and fingerprint through a channel you already trust).

A pull request can also edit the workflow to weaken the check. That is why `.github/` and `CODEOWNERS` are code-owned: the
same reviewers must approve a change to the check as to the keys.
