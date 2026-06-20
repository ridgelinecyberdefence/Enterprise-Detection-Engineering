# IAM Access Key — Concurrent Internal and External Use

Detects a long-term IAM access key making API calls from both an internal/known source range and an external address inside the same window. A single key cannot be in two places at once, so concurrent use is the cloud equivalent of impossible travel and indicates the credential is held by more than one party.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts
- **Tactic:** Initial Access, Persistence, Privilege Escalation, Defense Evasion

## Severity

**High.** Concurrent internal and external use is close to conclusive evidence of credential theft, because unlike one odd login it cannot be explained as the owner travelling. It is not Critical only because a few architectures (split egress paths, shared CI keys) reproduce the pattern benignly.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table in Athena
- Requires: a CloudTrail trail delivering to S3 with an Athena table defined; ports to CloudTrail Lake or Security Lake (OCSF) by mapping the field names

## Query

```sql
SELECT
    useridentity.accesskeyid AS access_key,
    useridentity.arn         AS principal,
    COUNT_IF(regexp_like(sourceipaddress,
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))     AS internal_calls,
    COUNT_IF(NOT regexp_like(sourceipaddress,
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))     AS external_calls,
    array_distinct(filter(array_agg(sourceipaddress),
        ip -> NOT regexp_like(ip,'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))) AS external_sources,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE useridentity.type = 'IAMUser'
  AND useridentity.accesskeyid LIKE 'AKIA%'
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY useridentity.accesskeyid, useridentity.arn
HAVING COUNT_IF(regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')) > 0
   AND COUNT_IF(NOT regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')) > 0
ORDER BY external_calls DESC;
```

## What Triggers This

A single long-term access key used from two distinct location classes in one window:

- Internal or known-good source ranges, the owner working normally
- External addresses, the same credential in someone else's hands
- The two overlapping in time, which is what makes it strong

The key's own history is the baseline; the deviation is visible in the same result that contains the norm.

## False Positives

1. **Split egress paths.** A workload reaching some APIs over a VPC endpoint (private source) and others over the internet (public source) can straddle the boundary. Confirm against the workload's known paths.
2. **Shared CI keys.** CI/CD driving a key from an external runner while a developer uses it internally will match; the real problem there is the shared key, not an intrusion.
3. **VPN mode changes.** A corporate VPN moving between split-tunnel and full-tunnel can shift the observed source.

## Tuning Notes

- **Define internal properly.** Replace the RFC1918 regex with your known-good source CIDRs (corporate egress, VPC endpoint ranges, CI provider ranges) maintained as an allowlist.
- **Bound the scan.** Add a partition predicate (for example a `date` or `region` partition) to control Athena cost.
- **Window.** Widen for low-and-slow keys; exclude service-linked and automation roles whose source legitimately varies.

## Validation

1. From an out-of-band host on a different public IP, run a benign permitted call such as `aws sts get-caller-identity` using a test key that is also exercised internally in the same window.
2. Confirm the key surfaces with both `internal_calls` and `external_calls` greater than zero and the external IP listed in `external_sources`.

## Learn More

- [AWS Incident Detection and Response — Detecting Credential Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — the per-principal source baseline and cloud impossible travel
- [Detection Engineering — Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — baseline-relative anomaly design
