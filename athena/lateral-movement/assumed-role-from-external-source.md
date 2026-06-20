# Assumed Role — Credentials Used from an External Source

Detects temporary role credentials being used from an address that is neither internal nor an AWS service endpoint. Role credentials retrieved from instance metadata are bound to the workload, so off-box use from external infrastructure is a strong theft signal.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts
- **Tactic:** Lateral Movement, Defense Evasion, Persistence

## Severity

**High.** Instance and SSO role credentials are meant to be used from inside AWS or known corporate ranges. The same role driving API calls from external infrastructure indicates the temporary credentials were exfiltrated, commonly from the metadata service, and are being replayed off-box.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table (`useridentity.type = 'AssumedRole'`)
- Requires: CloudTrail capturing the assuming sessions across regions

## Query

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

## What Triggers This

A role whose temporary credentials appear from outside the environment:

- The source is neither an internal range nor an AWS service endpoint
- The role is one normally exercised by an instance or SSO session, which should never appear externally
- The credentials were lifted from instance metadata and replayed from attacker infrastructure

## False Positives

1. **External integrations by design.** Roles assumed by external CI/CD, SaaS, or partner accounts will appear external. Confirm the role is intended for external assumption.
2. **Third-party tooling.** Posture and backup vendors assume roles from their own ranges. Exclude known integration sources.
3. **NAT or proxy egress.** Workloads egressing through an unexpected public path can look external. Map the source to the integration.

## Tuning Notes

- **Define internal and integrations.** Replace the internal regex and the `amazonaws.com` exclusion with your known-good ranges and integration IPs as an allowlist.
- **Scope to instance and SSO roles.** Where you can enumerate them, restrict to roles that should only ever be used in-environment.
- **Bound the scan.** Add a partition predicate to control cost.

## Validation

1. Assume a test role and make one permitted call from an external host.
2. Confirm the role surfaces with `external_sources >= 1` and the external IP listed.

## Learn More

- [AWS Incident Detection and Response — Compute Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — instance-credential theft and detecting role replay from outside
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — session-context fields and where-used baselining
