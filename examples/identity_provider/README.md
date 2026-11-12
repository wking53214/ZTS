# Identity provider side: signing the identity ZTS checks

ZTS can check that the caller really is the subject (the `identity_verifier` hook; `zts.identity.Ed25519IdentityVerifier`). The
proof is a signature from **your identity provider**, carried in the `signature` field of the CNS `IdentityContext`. This folder
is the signing half. ZTS holds public keys only and contains no signing code.

**Status: `sign_identity.py` is tested against ZTS's verifier (`tests/test_identity_auth.py`). It has not been connected to a real
identity provider (Okta, Entra, Keycloak, your own); that integration is yours.**

## What your identity provider must do

1. **Authenticate the person or service first**, by whatever means you trust (a password and a second factor, a client
   certificate, a workload identity). `verified` in the signed identity is always `true`: you sign only what you authenticated.
2. **Hold an Ed25519 private key** that never leaves it (an HSM or the provider's own key store is best). Register the PUBLIC key
   in the trust root with role `identity` (`key_id()` in `sign_identity.py` gives the key id; the trust-root review process in
   `docs/TRUST_ROOT_PROCEDURE.md` applies). Use a key that is used for nothing else.
3. **Sign the identity with `sign_identity()`** (or an equivalent that follows the format in `src/zts/identity.py`) and put the
   result in `IdentityContext.signature`. The signature covers the tenant, subject, roles, trust level and authentication
   method, so none can be changed afterwards.
4. **Set an audience** that names the ZTS deployment (for example `zts-release/prod`), so an identity signed for another service
   is useless here. ZTS is configured with the same audience.
5. **Keep it short.** The default maximum life is 300 seconds; 120 is a good choice. The signed identity is a bearer
   credential: anyone who holds it can present it until it expires.

## Ordering matters

The grant issuer signs the subject digest into the grant, and the digest covers the `signature` field. So the signed identity is
created FIRST, then the grant is requested for that exact identity, then the release is made, all within the identity's life. A new
signed identity (even for the same person) needs a new grant.

## ZTS side

```python
from zts.identity import Ed25519IdentityVerifier

gate = EnforcerReleaseGate(gate_enforcer, policy_version="2026-11", timeout=5.0,
                           identity_verifier=Ed25519IdentityVerifier(trust, audience="zts-release/prod"))
```

`tower.readiness()` then shows `identity_authentication` as PASS when the trust root holds a usable `identity` key, and
`health()` shows `trust_root_identity_keys`. PASS means ZTS can verify signatures from a key in its trust root. It cannot say that
your identity provider authenticates people properly: that is your assurance, not ZTS's.

## What this does not do

* It does not stop a stolen signed identity being used until it expires. Keep it short and send it only over verified TLS.
* It does not replace the grant issuer's own checks. Both must say yes.
* It does not authenticate the identity provider's operators: whoever can use the signing key can vouch for anyone. Protect it as
  you protect the grant-signing key.
