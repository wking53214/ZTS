# Off-box receipt receiver (AWS S3, Object Lock)

An example you deploy **in a separate AWS account from the releasing host**. ZTS's `HttpsReceiptExporter` posts each
timestamp receipt here; the receiver checks it and writes it to a write-once bucket. The point is that someone who takes
over the releasing host cannot quietly swap in an older ledger and its older receipts, because the newer receipts are
somewhere that host cannot touch.

**Status: the receiver logic is tested (`tests/test_receipt_receiver.py`, including the real exporter over TLS and real
timestamp tokens from OpenSSL's authority). The S3 calls are tested only against a stand-in client. Nothing here has run
against real AWS.** Do the trial in section 5 before you rely on it.

## 1. The separation that matters

| Who | Holds | Can do |
|---|---|---|
| The releasing host | one bearer token for this endpoint | add receipts. Cannot read, change or delete any |
| The receiver (Lambda) | an IAM role for this bucket only | write new objects, read them back to compare |
| Nobody, including the account root | | delete or shorten a COMPLIANCE-locked object before its date |

If the releasing host also held AWS credentials for this bucket, the separation would be gone. It must not.

## 2. Bucket (once)

1. Create the bucket **with Object Lock enabled** (it cannot be turned on later without support) in the audit account.
   Versioning is enabled automatically.
2. Do not set a default retention; the receiver sets it per object. Block all public access.
3. Bucket policy: deny `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:PutBucketObjectLockConfiguration` and
   `s3:BypassGovernanceRetention` to everyone except a named break-glass role you can account for.
4. **Retention is a decision you cannot undo in COMPLIANCE mode.** Pick it at least as long as you keep the ledger it
   protects (400 days is a common starting point), and know that you pay for the storage until then. For a trial, run with
   `RECEIPT_LOCK_MODE=GOVERNANCE` and a short `RECEIPT_RETAIN_DAYS`, then switch.

## 3. Receiver role (least privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject"],
     "Resource": "arn:aws:s3:::YOUR-BUCKET/receipts/*"},
    {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}
  ]
}
```

No `ListBucket`, no delete of any kind. (`GetObject` is only so the receiver can recognise a repeat of the same receipt.)

## 4. Lambda

Package `receiver.py`. To verify timestamp tokens (recommended) also package the `zts` package with `cryptography` and
`asn1crypto`, and set `RECEIPT_TSA_CERT_PEM` to the authority's signing certificate, the same one ZTS pins.

| Variable | Meaning |
|---|---|
| `RECEIPT_BUCKET` | the bucket |
| `RECEIPT_RETAIN_DAYS` | retention in days |
| `RECEIPT_LOCK_MODE` | `COMPLIANCE` (default) or `GOVERNANCE` for a trial |
| `RECEIPT_TOKEN` | the bearer token, 32 or more characters. Better: read it from Secrets Manager in your own wrapper |
| `RECEIPT_TSA_CERT_PEM` | optional but recommended: refuse receipts whose token does not verify |

Expose it with a Lambda function URL (HTTPS, auth type NONE: the bearer token is the check) or API Gateway. Set the
function timeout to a few seconds; the exporter gives up after 3.

On the releasing host:

```python
from zts.receipts import HttpsReceiptExporter
exporter = HttpsReceiptExporter("https://YOUR-FUNCTION-URL/", headers={"Authorization": "Bearer " + load_secret("receipt-token")})
anchor = Rfc3161Anchor(..., on_receipt=exporter)
```

After an outage: `exporter.resend(anchor, after_sequence=N)` where N is the highest `NNNNNNNNNNNN.json` in the bucket.

## 5. Trial (do this before relying on it)

1. Deploy with `GOVERNANCE` and `RECEIPT_RETAIN_DAYS=1`. Release a few times. Confirm one object per sequence appears.
2. Run `exporter.resend(anchor)`: every receipt must answer 200 and nothing new appears.
3. POST a receipt with a changed `head` for an existing sequence: expect 409, and the stored object unchanged.
4. Try to delete a stored object as the receiver role and as an admin: expect it refused until the retention date.
5. Check that the releasing host's credentials cannot read the bucket.
6. Only then set `COMPLIANCE` and the real retention.

## 6. Watching it

Alarm on any 409 (a conflicting receipt: a bug or an attack), a run of 401s (a wrong or leaked token), and on ZTS's own
`receipt_export_live` failing in `health()`. For acceptance test 12, compare the highest sequence in the bucket with the
newest receipt on the host: the bucket should never be behind it by more than a few receipts.

## What this does not do

It does not decide who may hold the break-glass role, rotate the token for you, or alert anyone. It does not make the
timestamp authority trustworthy; it only keeps the receipts it signed.
