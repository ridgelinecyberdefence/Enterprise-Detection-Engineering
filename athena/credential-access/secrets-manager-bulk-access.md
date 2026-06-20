# Secrets Manager Bulk or Anomalous Secret Retrieval

**ATT&CK:** T1555.006 Credentials from Password Stores: Cloud Secrets Management Stores. Tactic: Credential Access.

**Severity:** High. A principal sweeping Secrets Manager is harvesting the credentials that unlock databases, third-party APIs, and downstream services, so a single anomalous reader can become access to everything those secrets protect.

**Data Sources:** AWS CloudTrail management events over the `cloudtrail_logs` Athena table (`GetSecretValue`, `secretsmanager.amazonaws.com`).

**Query:**

```sql
SELECT
    useridentity.arn       AS principal,
    sourceipaddress        AS source_ip,
    COUNT(*)               AS reads,
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

**What Triggers This:** One principal reading five or more distinct secrets in a short window. Legitimate workloads read the same one or two secrets they own, repeatedly; an attacker who has landed on a role enumerates and pulls every secret it can reach, so breadth across distinct `secretId` values is the signal, not raw call count.

**False Positives:** A secrets-rotation Lambda, a config-management run, or a deployment pipeline can legitimately read many secrets at once. Distinguish by whether the principal is the known rotation or deploy role and whether the source is expected automation infrastructure.

**Tuning Notes:** Lower the `distinct_secrets` threshold for small environments and raise it where broad rotation jobs run. Exclude the rotation and deployment roles by ARN via an allowlist rather than hard-coding. Add a partition predicate to bound the scan. For higher fidelity, join the principal's 30-day baseline of distinct secrets and alert only when the window exceeds it.

**Validation:** With a test role, call `aws secretsmanager get-secret-value` against five or more distinct test secrets inside the window and confirm the principal surfaces with `distinct_secrets >= 5`.

**Learn More:** [AWS Incident Detection and Response: Compute Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers role-credential theft from instances and the secret-harvesting that follows.
