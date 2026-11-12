# Acceptance record

Copy this file, fill it in on a **staging** copy of the real stack (your issuer, status service, PostgreSQL, timestamp
authority and a test sink), and keep the filled copy with your go-live evidence. Several tests turn components off on
purpose, so do not run them against production. The tests and their expected results come from
[DEPLOYMENT.md](DEPLOYMENT.md) section 9; if the two ever disagree, DEPLOYMENT.md is right and this file is stale.

Run all 14 before go-live, and run the affected ones again after any change to the issuer, the status service, the
timestamp authority, the database, the trust root or the ZTS version.

## The run

| | |
|---|---|
| Date and time (UTC) | |
| Run by | |
| Environment name (staging, not production) | |
| ZTS commit or version | |
| Enforcer version (`pip show tack-enforcer`) | |
| CNS version (`pip show cns`) | |
| Trust root file SHA-256 and serial (`python scripts/trust_root_review.py FILE`) | |
| Timestamp authority URL and the pinned certificate's SHA-256 | |
| Receipt destination (step 1) | |
| `tower.readiness()` before starting: every FAIL (must be none), every UNKNOWN (list them) | |

## How to fill each test in

For each test: do the action, write what you **saw** (not what you expected), attach the evidence named, tick one result,
and put your initials. A test passes only if what you saw matches **Expect**. If it does not, tick Fail, write what
happened, and do not go live until it is fixed and the test is run again.

---

### 1. Release with a valid grant

- **Do:** issue a grant for a test artifact and release it through the tower.
- **Expect:** outcome `delivered`; `audit_anchored` true.
- **Evidence:** the result object; the `zts.release` INFO log line.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 2. Present the same grant to a second host

- **Do:** after test 1, send the same grant to a second host that shares the replay database.
- **Expect:** `GRANT_REPLAYED`. Nothing delivered.
- **Evidence:** the result; `replays_detected` in the metrics; the ERROR log line.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 3. Revoke at the status service, then release again

- **Do:** issue a grant, revoke it at the status service, release it. Note the clock time of the revocation and of the refusal.
- **Expect:** `GRANT_REVOKED`.
- **Measure:** seconds from revocation to refusal: ______ s. (This is how long a revoked grant stays usable through your
  status service, including any caching you added.)
- **Evidence:** the result; `security_denials` in the metrics.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 4. Release under an expired, revoked or unknown key

- **Do:** three releases: grants signed by a key past its window, a key marked revoked in the trust root, and a key not in the trust root.
- **Expect:** each `PROOF_INVALID`.
- **Evidence:** the three results; the `on_reject` reasons.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 5. Put an older trust root back

- **Do:** with a serial store configured, replace the live trust root file with an older copy (lower serial).
- **Expect:** the trust root is refused; `health()` lists `trust_root_grant_keys`; releases are denied until the current file is restored.
- **Evidence:** `health()` output before, during and after.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 6. Block the timestamp authority, keep releasing, then block longer

- **Do:** block the authority at your firewall. Keep releasing. Continue until the unstamped limit is passed (default 500 entries or 300 s). Then unblock.
- **Expect:** deliveries continue unanchored at first, then `ANCHOR_BEHIND`; after unblocking the hold lifts by itself.
- **Measure:** releases (or seconds) before `ANCHOR_BEHIND` appeared: ______
- **Evidence:** `anchor_failures` and `anchor_backlog` in `health()`.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 7. Stop the replay database

- **Do:** stop PostgreSQL. Try several releases. Start it again.
- **Expect:** every release denied `REPLAY_STORE_ERROR` while it is down; recovers when it returns, with no restart.
- **Evidence:** the results; `availability_failures` in the metrics.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 8. Drop a replay constraint (on a test copy only)

- **Do:** on a throwaway copy of the replay table, drop one of its uniqueness constraints. Release.
- **Expect:** releases are denied; `health()` lists `replay_store_live`.
- **Evidence:** `health()` output; the results.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 9. Make the status service answer slowly

- **Do:** make the status service take longer than the gate `timeout`, including a response that trickles one byte at a time.
- **Expect:** the release is denied within about the `timeout`, not after the slow response finishes.
- **Measure:** seconds until the release was denied: ______ (the configured timeout was ______ s)
- **Evidence:** the result; `availability_failures`.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 10. Make the identity hook return false

- **Do:** make your identity authenticator reject the subject.
- **Expect:** `IDENTITY_NOT_AUTHENTICATED`; nothing delivered, and the grant is not spent.
- **Evidence:** the result; `security_denials`; the ERROR log line.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 11. Kill the process mid-delivery

- **Do:** make the sink pause; send SIGKILL to the process while it is paused; restart; open the ledger.
- **Expect:** the ledger opens and verifies. The release has `ATTEMPT` and `RELEASING` entries and **no final entry**. Run
  `unfinished_releases(ledger)` (DEPLOYMENT.md, after section 9): it lists the release id. Ask the receiver whether it holds
  the artifact. A retry with the same grant is denied `GRANT_REPLAYED`; a new grant under a new release id delivers.
- **Evidence:** the helper's output; the receiver's answer; the denied retry.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 12. Restore an old ledger and its receipts together

- **Do:** copy the ledger and receipts file aside, release a few more times, then put the old copies back.
- **Expect:** detected **only if your off-box receipts (step 1) are newer** than the restored ones. Compare the highest
  sequence in the off-box bucket with the restored host's newest receipt.
- **Measure:** highest sequence off-box: ______  newest on the restored host: ______
- **Evidence:** the two numbers; whatever alarm you set up.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 13. Fail the receipt export destination

- **Do:** make the receipt destination refuse or time out. Release. Then restore it and run `exporter.resend(anchor, after_sequence=N)`.
- **Expect:** `receipt_export_live` appears in `health()`; the release still delivers; after `resend`, the destination holds every sequence with no gap.
- **Evidence:** `health()` before and after; the destination's list of sequences.
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

### 14. Try section 8's checks as the application user

- **Do:** log in as the account the application runs as. Try each: read the delivery credentials; reach the receiver directly;
  write the trust root, the ledger, the receipts, the ledger key and the release signature key; read the replay database credentials.
- **Expect:** every one fails.
- **Evidence:** the commands and their error messages (this one has no automated evidence: it is about your operating system accounts).
- **Saw:** 
- Result: [ ] Pass  [ ] Fail   Initials: ____

---

## Sign-off

| | |
|---|---|
| All 14 passed | [ ] yes  [ ] no, open items listed below |
| Open items and who owns each | |
| Approved for go-live by | |
| Date | |

A filled record shows what you tested and saw on one day. It does not make the system safe, and it goes stale when anything it covers changes.
