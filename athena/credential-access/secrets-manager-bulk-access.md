# Secrets Manager — Bulk Secret Retrieval

Detects a single principal reading many distinct secrets from AWS Secrets Manager in a short window. Legitimate workloads read the one or two secrets they own; an attacker who has landed on a role enumerates and pulls everything it can reach, so breadth across distinct secrets is the signal.

## ATT&CK

- **Technique:** T1555.006 — Credentials from Password Stores: Cloud Secrets Management Stores
- **Tactic:** Credential Access

## Severity

**High.** A principal sweeping Secrets Manager is harvesting the credentials that unlock databases, third-party APIs, and downstream services, so a single anomalous reader can become access to everything those secrets protect.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table (`GetSecretValue`, `secretsmanager.amazonaws.com`)
- Requires: CloudTrail capturing Secrets Manager management events

## Query

```sql
SELECT
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    COUNT(*)         AS reads,
    COUNT(DISTINCT json_extract_scalar(requestparameters, '$.secretId')) AS distinct_secrets,
    array_agg(DISTINCT json_extract_scalar(requestparameters, '$.secretId')) AS secrets,
    min(eventtime) AS first_read,
    max(eventtime) AS last_read
FROM cloudtrail_logs
WHERE eventsource = 'secretsmanager.amazonaws.com'
  AND eventname   = 'GetSecretValue'
  AND eventtime  >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(DISTINCT json_extract_scalar(requestparameters, '$.secretId')) >= 5
ORDER BY distinct_secrets DESC;
```

## What Triggers This

One principal reading five or more distinct secrets in a short window:

- The breadth across distinct `secretId` values, not raw call count, is the anomaly
- The owner of a workload reads its own one or two secrets repeatedly, never the estate
- An attacker on a stolen role pulls every secret the role can see

## False Positives

1. **Rotation Lambdas.** A secrets-rotation function legitimately reads many secrets on schedule. Exclude it by ARN.
2. **Deployment pipelines.** A deploy run may pull several secrets at once. Confirm the principal is the known deploy role and the source is expected automation.
3. **Config management.** Bootstrap and config runs read broadly on first apply. Distinguish by host and cadence.

## Tuning Notes

- **Threshold.** Lower `distinct_secrets` for small estates; raise it where broad rotation jobs run.
- **Allowlist by ARN.** Exclude rotation and deployment roles rather than hard-coding names.
- **Baseline.** For higher fidelity, join each principal's 30-day distinct-secret count and alert only when the window exceeds it.

## Validation

1. With a test role, call `aws secretsmanager get-secret-value` against five or more distinct test secrets inside the window.
2. Confirm the principal surfaces with `distinct_secrets >= 5` and the secrets listed.

## Learn More

- [AWS Incident Detection and Response — Compute Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — role-credential theft and the secret harvesting that follows
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — breadth-based detection over cloud audit logs
