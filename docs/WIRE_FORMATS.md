# Wire formats

Everything an issuer, a status service or an operator must produce for ZTS to accept it. ZTS only
verifies; it never issues. Byte-exact vectors with fixed (public, test-only) seeds are in
`tests/test_wire_vectors.py`; build against those. The keys in them are published here: never use them.

## Signed documents (grants and status answers)

Four dot-separated ASCII fields:

```
<type> . b64u(header) . b64u(body) . b64u(signature)
```

* `<type>` is `zts-grant-1` or `zts-status-1`, exactly.
* `b64u` is **unpadded** base64url, and must be canonical: padding, other alphabets, and spellings whose
  unused trailing bits are not zero are refused (an Ed25519 signature has such spare bits, so a non-canonical
  twin of a good signature is not accepted as a second valid proof).
* `header` is a JSON object with exactly `alg`, `kid`, `typ`: `alg` is `"Ed25519"` (nothing else is
  accepted, and the algorithm is inside the signed header so a caller cannot choose a weaker one), `kid` is
  the key id, `typ` repeats `<type>`.
* `signature` is Ed25519 over the bytes `<type> 0x00 b64u(header) . b64u(body)`: the type, a zero byte, then
  the two base64url fields exactly as transmitted. The signature is checked **before** the body is parsed.
* JSON must be UTF-8, with no duplicate keys, no `NaN`/`Infinity`, and exactly the fields listed. Maximum
  size: 8 KiB for a grant, 64 KiB for a status answer.
* Timestamps are ISO-8601 **with an offset** (`2026-11-04T12:00:00+00:00`). Naive times are refused.

### Key id

`ed25519-` plus the first 16 hex characters of SHA-256 over the raw 32-byte public key. This is the id TIE
and HERALD already use. The trust root refuses a key whose id is not derived from its bytes.

### Grant body (`zts-grant-1`)

The thirteen fields of Enforcer's `GrantClaims`, no more and no fewer: `issuer_id`, `subject_id`, `action`,
`target_type`, `target_id`, `evidence_sha256` (or `null`), `request_id`, `parameters_sha256`,
`policy_version`, `schema_version` (the integer 1), `issued_at`, `expires_at`, `nonce`.

The values must equal what ZTS puts in the Enforcer envelope for that release (see
[RELEASE_BOUNDARY.md](RELEASE_BOUNDARY.md), "The envelope"): `subject_id` is the CNS subject digest of the
identity, `action` the operation (`zts.release`), `target_type` `zts.output`, `target_id` the scope,
`request_id` the release id, `evidence_sha256` the SHA-256 of the artifact's UTF-8 bytes,
`parameters_sha256` the SHA-256 of the parameter document, `policy_version` the gate's policy version.
ZTS hands the issuer a `ReleaseCandidate` carrying the canonical envelope bytes, so an issuer can copy the
fields instead of recomputing them. The issuer must also keep each grant short-lived (Enforcer caps the
lifetime, five minutes by default) and give every grant a unique `nonce`.

The signing key must belong to the issuer named in `issuer_id` (the trust root binds each key to one issuer),
have role `grant`, be `active`, and cover the grant's whole lifetime: `not_before <= issued_at` and
`expires_at <= not_after`.

### Status exchange (`zts-status-1`)

Request, `POST <base_url>/v1/status`, `Content-Type: application/json`:

```json
{"challenge": "<b64u of 16 random bytes>", "envelope_sha256": "...", "policy_version": "...",
 "issuer_id": "...", "nonce": "..."}
```

Answer, status `200` (a redirect is never followed), body a signed document of type `zts-status-1` whose
body is exactly:

```json
{"status": "CURRENT" | "REVOKED" | "UNKNOWN", "challenge": "...", "envelope_sha256": "...",
 "policy_version": "...", "issuer_id": "...", "nonce": "...",
 "checked_at": "...", "valid_until": "..."}
```

`challenge`, `envelope_sha256`, `policy_version`, `issuer_id` and `nonce` must echo the request. The
signing key must have role `status` and belong to the same issuer. `valid_until - checked_at` and the age of
`checked_at` must fit Enforcer's freshness bound (30 seconds by default); Enforcer, not ZTS, enforces that.
The URL must be `https`; the server certificate is verified with the default store or a context you supply
(add a client certificate there for mutual TLS). Reply `REVOKED` or `UNKNOWN` rather than an error when you
know the state: an error is also a denial, but a signed `REVOKED` is evidence.

## Trust root

A JSON file (mode 644 or stricter, owned by the running user or root):

```json
{"version": 1,
 "serial": 7,
 "keys": [{"kid": "ed25519-...", "issuer_id": "issuer-a", "role": "grant",
           "public_key": "<b64u raw 32 bytes>", "not_before": "...", "not_after": "...",
           "status": "active"}]}
```

The file is parsed as strictly as a grant: a repeated JSON key (at any depth), `NaN` and `Infinity` are refused,
so an edit cannot hide a second `"status"` behind the first. It must be a regular file of at most 1 MiB, owned by
the running user or root, not writable by group or others. Every directory that decides what the path means
must also be owned by the running user or root and not writable by others: the parents of the path as written,
the target of each symbolic link on the way (followed one step at a time), and the parents of the file it
finally resolves to. Symbolic links are allowed, since configuration systems use them. A sticky directory such as
`/tmp` is accepted, because others cannot replace a file they do not own there. These checks run on every use,
so a directory made writable later is noticed. The file is opened once and its owner, mode and kind are read from
that open file, so it cannot be swapped between the check and the read.

Unknown fields, duplicate ids, a wrong id, roles other than `grant`/`status`, statuses other than
`active`/`revoked`, and a window that ends before it starts are refused, and the whole file is refused with
them. The file is re-read when it changes. A change that breaks it makes **every** proof and status answer
fail until it is fixed; there is no fallback to the old contents.

`serial` is optional: a positive integer that you raise on every edit. **Rollback.** Putting an older copy of the
file back would un-revoke a key. There are two defences, and they trade off. Pin the file's SHA-256 out of band
(`FileTrustRoot(path, expected_sha256=...)`): no other content is accepted, but every rotation needs a restart
with the new pin. Or give `FileTrustRoot` a serial store (`FileSerialStore` on one host, `PostgresSerialStore`
across hosts): rotation stays hot and any file whose `serial` is lower than one already accepted is refused, as is
a different file claiming the same serial. A serial store does not stop someone who can write the file from
writing a new one with a higher serial; that takes file permissions or a signed trust root. With a serial store a
host re-checks every 30 s, so one whose file fell behind a newer root accepted elsewhere is refused rather than
left on stale keys. A file without `serial` is refused when a serial store is configured.

* **Rotate:** add the new key with a start time before first use, switch the issuer to it, let old grants
  expire, then mark the old key `revoked` (or let `not_after` pass).
* **Revoke after compromise:** set `status` to `revoked`. Every grant under that key fails from the next
  verification, whatever its expiry.

## Ledger and anchor files

* **Ledger** (`FileLedgerStore`): JSON Lines, one `LedgerEntry` per line, `sort_keys`, newline-terminated.
* **Anchor head** (`FileLedgerAnchor`): JSON Lines of `{"head": ..., "sequence": ...}`.
* **RFC 3161 receipts** (`Rfc3161Anchor`): JSON Lines of `{"gen_time", "head", "sequence", "token"}` with the
  DER `TimeStampToken` in base64. The stamped value is
  `SHA-256( "zts-ledger-head-v1" 0x00 || {"head":"<hex>","sequence":<n>} )` with the JSON compact and
  key-sorted. Tokens are verified against the TSA signing certificates you pin: RSA PKCS#1 v1.5 or ECDSA
  with SHA-256/384/512, a certificate with a critical time-stamping extended key usage that was valid at the
  stamped time. No chain building, no revocation check: pin the signing certificate itself.

## Replay table (PostgreSQL)

```sql
CREATE TABLE zts_consumed_grants (
  issuer_id text NOT NULL, nonce text NOT NULL, request_id text NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz,
  PRIMARY KEY (issuer_id, nonce), UNIQUE (request_id));
```

`PostgresReplayStore` creates it if missing. A table that exists without either uniqueness constraint is refused
when the store is built, and `consume` re-checks that both are present on every call, denying the release if not.
Give the release hosts `INSERT`/`SELECT`, and `DELETE` only to whatever runs `prune()`.

The trust-root serial store (`PostgresSerialStore`) keeps one row per name in `zts_trust_serial`
(`name text PRIMARY KEY, serial bigint NOT NULL CHECK (serial > 0), digest text NOT NULL, updated_at`).
