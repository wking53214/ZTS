# Trust-root procedure

The trust root is the file that lists which issuer keys ZTS believes. Whoever can change it can authorise releases, or bring
back a key that was revoked after a theft. ZTS cannot tell a legitimate edit from an attack on the file, so the control is
people and process. This is the process; adopt it, change it where it does not fit, and write down what you changed.

Decision taken: **two-person review in version control.** The set-up (repository, reviewers, check, branch protection) is in
[examples/trust_root_repo/](../examples/trust_root_repo/README.md). Tooling: `scripts/trust_root_review.py`.

## Roles

| Role | Does | Must not |
|---|---|---|
| **Key custodian** | holds the issuer's signing keys; produces and vouches for public keys | approve a change that adds their own key without a second custodian or an owner |
| **Author** | prepares the change as a pull request | approve their own change |
| **Reviewer** | runs or reads the review output, checks the key out of band, approves | approve something they did not check |
| **Operator** | deploys the approved file to the hosts and confirms it took | edit the file on a host |

Name a person for each role, and a deputy. Write the names where the team will find them.

## An ordinary change (add a key, rotate, extend a window)

1. **Author:** edit `trust-root.json` in a branch. Raise `serial`. Open a pull request.
2. **Check:** the `trust-root-review` job runs. It must pass. Read its output on the pull request: every key, and what changed.
3. **Reviewer:** for each key that is new or changed, confirm with the key custodian, through a channel you already trust
   (not the pull request, not email from an unknown address), the **key id and the first and last 8 characters of the public
   key**. Check the issuer name, the role (`grant` or `status`, never both), and the window (starts before first use, ends
   when you want it to).
4. **Reviewer:** approve only if every line of the diff is one you expected.
5. **Merge.** The merge commit is the record of who changed what, when, and who approved it.
6. **Operator:** deploy (below). Do not edit the file on a host to speed things up.

**Rotation order** (so no release is refused): add the new key with a start time before first use, raise `serial`, deploy,
switch the issuer to the new key, wait for old grants to expire (the grant lifetime, 5 minutes by default), then mark the old
key `revoked` in a second change.

## Emergency: a key is compromised

Speed matters more than ceremony, and revoking is the safe direction.

1. Anyone in the reviewer or operator roles may open a pull request that sets the key's `status` to `revoked` and raises `serial`.
2. One approval is enough. The check still runs. Merge and deploy at once.
3. Within one working day, a second person reviews what was done and writes a note on the pull request. If the revocation was
   wrong, correct it with a new, ordinary change. **Never un-revoke a key:** issue a new key. The check refuses an un-revoke.

This emergency path is a policy choice: it lets one person act alone, but only to reduce trust. If you do not want that,
require two approvals for revocation too, and accept the delay.

## Deployment

1. Put the approved file on each host in the place ZTS reads, owned by the service user or root, mode 644 or stricter, in
   directories others cannot write (ZTS refuses the file otherwise, on every use).
2. Give ZTS rollback protection: a serial store on the replay database (hot rotation), or a pinned digest (a restart per change).
   The review tool prints the digest to pin.
3. **Confirm it took.** On each host, `tower.health()` shows no `trust_root_*` failure, and the serial the host reports (the
   `describe()` of the trust root) equals the merged file's. A host still on the old serial is a host that has not rotated or
   revoked yet: treat it as an incident during an emergency.
4. Record the date, the commit, the serial and who deployed it.

## Routine

* **Monthly:** list every key, its issuer, and its window. Remove expired keys in an ordinary change. Anyone not recognised is an incident.
* **Quarterly:** run acceptance test 5 of `ACCEPTANCE_RECORD.md` (put an older trust root back) and confirm it is refused.
* **On a reviewer leaving:** remove them from the team the same day; check no pull request is waiting on only their approval.

## What this does not protect against

* A reviewer who approves without checking, or two reviewers who collude. The process makes tampering visible and slower; it does
  not make it impossible.
* Someone with administrator rights on the repository who can switch off branch protection. Keep that group tiny, alert on any
  change to the protection settings, and review it quarterly.
* Someone with write access to the hosts' files, who can replace the file directly. Serial store or pinned digest, and file
  permissions, are the defence; nothing in the pull request process helps here.
* A signed trust root (an offline key signs the file and hosts verify it) would close the last two gaps. ZTS does not support it today.
