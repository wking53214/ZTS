# The release service

The small process that sits between your application and ZTS. It runs under its own operating-system account (see `../isolation/`) and is
the only thing that holds the tower, the keys, the ledger and the delivery credentials. The application asks it, over a local Unix
socket, to release one text. Untrusted code in the application can ask for releases it already holds a valid grant for; it cannot read a
key, rewrite the ledger, or deliver anything itself.

**Status: tested (`tests/test_release_service.py`, 78 tests, twelve deliberate breakages each caught): the protocol, the caller check
(including from a different real operating-system account), the socket's safety rules, and the reference delivery against a local TLS
receiver. NOT tested: a run against a real production tower (the example factory is untested), a real systemd, or your receiver.**

## What it decides, in order

A release goes through four independent checks. All four must say yes.

1. **The caller's account** (kernel, SO_PEERCRED). Only accounts in the config may connect, and each may present only the tenants and
   subjects listed for it. A stolen signed identity is not enough from the wrong account.
2. **The identity provider's signature** on the identity (the tower's identity hook, `docs/DEPLOYMENT.md`, `../identity_provider/`).
3. **The grant**, issued by your issuer for this exact text, single-use.
4. **The status service**, asked again just before delivery (`reask_status`).

The service adds check 1 and carries the rest. It never decides to release anything on its own.

## Files

| File | What it is |
|---|---|
| `service.py` | the service: request parsing, caller policy, the socket server, config loading, `main` |
| `client.py` | the application's side: 20 lines, standard library only |
| `delivery.py` | a reference HTTPS delivery and confirmation (replace it if your receiver differs) |
| `assemble_example.py` | an example tower factory: the guide's production assembly. **Untested** against real components |
| `release-service.example.json` | an example config |

## Protocol

One request per connection: a line of JSON; one line of JSON back; the service closes. Request fields: `release_id`, `scope`, `text`,
`grant` (base64 of the grant bytes) and `identity` (tenant_id, subject_id, roles, trust_level, authentication_method, verified,
signature). Any other field, a repeated key, or a wrong type is refused. Answer: `released`, `outcome`, `reason_code`, `authorized`, and
nothing else. `outcome` is the tower's (`delivered`, `denied`, `failed_before_delivery`, `delivery_unknown`, ...) or one the service
says itself before asking the tower:

| `reason_code` (outcome `refused`) | Meaning |
|---|---|
| `BAD_REQUEST` | not valid, strict, exact-field JSON, or a field of the wrong type |
| `IDENTITY_INVALID` | the identity could not be built (for example an unknown trust level) |
| `CALLER_NOT_ALLOWED` | the account is not in the config, or may not present this tenant or subject. Logged with the account |
| `TOO_LARGE` | over `max_request_bytes` (default 256 KiB) |
| `BUSY` | every slot is in use (`max_concurrent`, default 8). Try again |
| `SERVICE_ERROR` (outcome `service_error`) | something unexpected; the log has the detail, the caller gets none |

## Deploying it

1. Build the isolation layout (`../isolation/setup_accounts.sh`) and copy this folder to `/opt/zts/release_service`.
2. Copy `assemble_example.py` over itself with your addresses, or write your own factory: a function `build_tower(config) -> tower`.
   Put its `module:function` in the config's `tower_factory`.
3. Write `/etc/zts/release-service.json` (root-owned, mode 644): the socket path, the group that may open the socket, and the
   `callers`. A caller is a numeric account id; `["*"]` means "any", and it has to be written out on purpose.
4. Install `../isolation/zts-release.service`. It runs `service.py` with that config.
5. The service refuses to start if the tower has no Enforcer release gate or its readiness has any FAIL, if the socket's directory is
   writable by others, if the path holds something that is not a socket, or if another service is already listening there.

## What this does not do

* **It runs on one machine.** SO_PEERCRED is a local-socket feature. For other machines you want a different transport and a different
  caller check; that is not built.
* **It trusts its config and its tower factory.** Both are loaded as code or policy from root-owned files. Protect them like the keys.
* **It does not authenticate people.** That is the identity provider's signature (check 2).
* **A compromised application account can still submit releases it holds grants and signed identities for.** The grant is bound to the
  exact text, so it cannot release different text; but it can release that text.
* **Denial of service:** a caller that holds connections open uses the slots until the read timeout (10 s). The slots are shared by all
  callers. Put a per-account limit in front if that matters to you.
