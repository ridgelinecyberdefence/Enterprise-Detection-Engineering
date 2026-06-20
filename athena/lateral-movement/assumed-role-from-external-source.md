# Role Credentials Used from an External Source

**ATT&CK:** T1078.004 Valid Accounts: Cloud Accounts. Tactics: Lateral Movement, Defense Evasion, Persistence.

**Severity:** High. Instance and SSO role credentials are meant to be used from inside AWS or known corporate ranges. The same role driving API calls from external infrastructure indicates the temporary credentials were exfiltrated (commonly from instance metadata) and are being replayed off-box.

**Data Sources:** AWS CloudTrail management events over `cloudtrail_logs` (`useridentity.type = 'AssumedRole'`).

**Query:**

```sql
SELECT
    useridentity.sessioncontext.sessionissuer.username AS role,
    COUNT(DISTINCT sourceipaddress)                     AS external_sources,
    COUNT(*)                                            AS external_sessions,
    array_distinct(array_agg(sourceipaddress))          AS sources,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE useridentity.type = 'AssumedRole'
  AND NOT regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND sourceipaddress NOT LIKE '%.amazonaws.com'
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY useridentity.sessioncontext.sessionissuer.username
ORDER BY external_sessions DESC;
```

**What Triggers This:** A role whose temporary credentials are used from an address that is neither internal nor an AWS service endpoint. Role credentials retrieved from instance metadata are bound to the workload, so off-box use from attacker infrastructure is a strong theft signal.

**False Positives:** Roles legitimately assumed by external CI/CD, SaaS integrations, or partner accounts will appear external. Distinguish by whether the role is designed for external assumption and whether the source belongs to a known integration.

**Tuning Notes:** Replace the internal regex and the `amazonaws.com` exclusion with your organisation's known-good source ranges and integration IPs maintained as an allowlist. Scope to roles attached to instances or SSO if you can enumerate them, since those should never appear externally. Add a partition predicate to bound the scan.

**Validation:** Assume a test role and make one permitted call from an external host; confirm the role surfaces with `external_sources >= 1`.

**Learn More:** [AWS Incident Detection and Response: Compute Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers instance-credential theft and detecting role replay from outside the environment.
