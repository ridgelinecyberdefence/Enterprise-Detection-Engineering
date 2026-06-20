# STS AssumeRole Spike — Role Enumeration from One Source

Detects a single source making a burst of `AssumeRole` calls, including the SAML and web-identity variants. An attacker holding one credential probes which roles it can assume to widen access, so a spike of role assumptions from one source is the escalation-mapping signature.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts
- **Tactic:** Credential Access, Privilege Escalation

## Severity

**High.** A burst of role assumptions from one source maps the account's privilege graph and frequently precedes lateral movement into a more powerful role.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table (`sts.amazonaws.com`)
- Requires: CloudTrail capturing STS calls

## Query

```sql
SELECT
    sourceipaddress AS source_ip,
    COUNT(*)        AS assume_calls,
    COUNT(DISTINCT json_extract_scalar(requestparameters, '$.roleArn')) AS distinct_roles,
    COUNT_IF(errorcode = 'AccessDenied') AS denied,
    array_distinct(array_agg(eventname)) AS verbs,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventname IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY sourceipaddress
HAVING COUNT(DISTINCT json_extract_scalar(requestparameters, '$.roleArn')) >= 5
ORDER BY distinct_roles DESC;
```

## What Triggers This

A source probing the role graph:

- Five or more distinct target roles assumed from one source in the window
- A mix of successes and `AccessDenied`, which signals enumeration rather than normal use
- An external or previously unseen source

## False Positives

1. **CI/CD and orchestration.** Pipelines assume several roles legitimately. Allowlist their sources and roles.
2. **Cross-account automation.** Hub-and-spoke automation assumes many roles. Confirm the source is the known automation.
3. **Federated portals.** SSO portals generate `AssumeRoleWithSAML` at volume. Exclude the IdP source.

## Tuning Notes

- **Allowlist automation sources.** Exclude CI/CD, orchestration, and IdP sources, which are the main false positives.
- **Weight the denials.** A high `denied` count alongside successes is strong enumeration evidence; surface it.
- **Tune the role count.** Set `distinct_roles` to your environment's normal per-source breadth.

## Validation

1. From a test source, assume five or more distinct roles (some permitted, some denied) within the window.
2. Confirm the source surfaces with `distinct_roles >= 5` and the denials counted.

## Learn More

- [AWS Incident Detection and Response — Detecting Credential Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — STS abuse and role enumeration
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — privilege-graph enumeration detection
