# Process isolation: a separate release service on its own account

ZTS stops releases that go through the tower. It cannot stop code in the **same process** from calling the delivery function
directly. So the tower, the delivery credentials, the keys and the ledger live in one small service running as its own
operating-system user, and the application, with everything untrusted that runs inside it (plugins, model-generated code),
never touches any of them. It only asks the service to release something.

```
  application (account: zts-app)            release service (account: zts-release)
  untrusted code may run here    --asks-->   tower, ledger, keys, delivery credentials  --delivers--> receiver
         cannot read, write or reach          the only process that can do any of that
```

**Status: the files here are tested (`tests/test_isolation_example.py` builds the layout and runs the check as two real accounts,
and breaks the layout six ways to prove each break is caught). The unit has never been started under a real systemd, and the
release service program itself does not exist yet (below).**

## What is here

| File | What it is |
|---|---|
| `setup_accounts.sh` | creates the two accounts and the directories with the right owners and modes; never overwrites |
| `zts-release.service` | a hardened systemd unit (`systemd-analyze security` scores it 1.1, "OK"; the placeholder network allow-list inflates nothing) |
| `check_isolation.py` | acceptance test 14: tries the forbidden things as the application's account and reports what worked |
| `isolation-check.example.json` | the list of paths and addresses to try |

## What is NOT here, and why

**The service program** (`ExecStart=... -m release_service`). ZTS is a library, and the thin process that wraps your tower and
answers the application is yours to write, because its request format depends on choices only you can make: how the application
proves who it is to the service (a Unix socket with peer credentials is the usual way), how an identity reaches the service
(ZTS's release path takes a CNS identity object, not plain text), and how a grant is obtained. It must do four things:
1. listen only on a local Unix socket owned by the service, readable by the application account and nobody else;
2. check who is calling (the kernel tells you the caller's user id on a Unix socket: use it);
3. build the tower once at start, with `production=True`, and refuse to start if readiness has a FAIL;
4. return only the release outcome (delivered or the reason code), never a credential, a key or a ledger line.

If you want it, I can scope it with you as a separate piece of work. It is small, but its interface is a design decision.

## Steps

1. **Accounts and layout.** As root: `sudo ./setup_accounts.sh`. Then put the three secrets in place with the `install` command it
   prints, and install the approved trust root as root-owned (`install -o root -g root -m 0644 trust-root.json /etc/zts/`).
   The service owns its secrets and its state; it does **not** own the trust root, so a compromised service cannot rewrite who it
   trusts.
2. **Unit.** Copy `zts-release.service`. Replace the program in `ExecStart`. Replace `IPAddressDeny=any` and the commented
   `IPAddressAllow=` line with the addresses it truly needs (status service, replay database, timestamp authority, receipt
   destination, receiver). As shipped the unit blocks all networking, so it fails loudly instead of running open.
3. **Run the check as the application.** Copy `isolation-check.example.json`, put in the real paths and the receiver's address, then:
   `sudo -u zts-app python3 check_isolation.py my-check.json`. Every line must say PASS.
4. **Run the control as the service.** `sudo -u zts-release python3 check_isolation.py my-check.json --expect-access`. This shows the
   paths and the address are real, so a PASS in step 3 means "refused" and not "typo". The check treats a missing path as ERROR for
   the same reason.
5. **Record both runs** in `docs/ACCEPTANCE_RECORD.md`, test 14.

## What this does and does not give you

It gives you: a compromised application account cannot read the delivery credentials or keys, cannot rewrite the ledger or the trust
root, and cannot reach the receiver except through the service.

It does not protect against: root on the machine; a kernel exploit; a flaw in the release service itself (it is now the thing to
protect, so keep it small and review it); the application tricking the service into releasing something (that is what grants, the
status check and the identity binding are for); or an attacker who owns both accounts. Network rules outside the machine (a
firewall that lets only the service reach the receiver) are the second layer; the check can show whether that layer holds by
listing the receiver's address under `must_not_connect`.
