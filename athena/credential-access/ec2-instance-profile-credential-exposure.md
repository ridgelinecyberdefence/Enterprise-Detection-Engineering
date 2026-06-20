# EC2 Instance-Profile Credentials Used Off-Instance — IMDS Theft

Detects temporary credentials belonging to an EC2 instance role being used from anywhere other than the instance itself. Server-side request forgery and on-box compromise both lead to credentials lifted from the instance metadata service, and those credentials are bound to the instance, so any off-instance use is theft.

## ATT&CK

- **Technique:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
- **Tactic:** Credential Access

## Severity

**High.** Instance-profile credentials carry whatever the workload's role can do. Used from outside the instance, they are an attacker operating with the workload's permissions from their own infrastructure.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table (`useridentity.type = 'AssumedRole'`)
- Requires: CloudTrail capturing assumed-role sessions; instance-role ARNs identifiable by naming or tag convention

## Query

```sql
WITH role_sources AS (
    SELECT
        useridentity.sessioncontext.sessionissuer.username AS role,
        sourceipaddress AS source_ip,
        COUNT(*) AS calls,
        BOOL_OR(regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
                OR sourceipaddress LIKE '%.amazonaws.com') AS is_internal
    FROM cloudtrail_logs
    WHERE useridentity.type = 'AssumedRole'
      AND useridentity.sessioncontext.sessionissuer.username LIKE '%instance%'   -- adjust to your instance-role naming
      AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
    GROUP BY useridentity.sessioncontext.sessionissuer.username, sourceipaddress
)
SELECT role, source_ip, calls
FROM role_sources
WHERE is_internal = false
ORDER BY calls DESC;
```

## What Triggers This

An instance role acting from somewhere the instance is not:

- An instance-profile role's temporary credentials seen from an external source
- The same role normally operating only from internal or AWS-service sources
- Calls from attacker infrastructure carrying the workload's permissions

## False Positives

1. **NAT and egress paths.** An instance reaching APIs over an unexpected public path. Map the source to the instance's known egress.
2. **Role-name matching.** The `%instance%` filter is a heuristic; tune it to your actual instance-role naming or tag the roles. A mismatch causes misses or noise.
3. **Hybrid connectivity.** On-prem-to-AWS paths can present unexpected sources. Allowlist those ranges.

## Tuning Notes

- **Identify instance roles precisely.** Replace the name heuristic with your real instance-role naming or a tag-based allowlist of which roles are instance-bound.
- **Baseline per role.** Learn each instance role's normal source set and alert on first deviation rather than a static internal test.
- **Correlate with the instance.** Tie the role session back to the launching instance to confirm the source is not that instance.

## Validation

1. Assume an instance-profile role's credentials from an external host (or simulate an external assumed-role session in test data).
2. Confirm the role surfaces with the external source listed.

## Learn More

- [AWS Incident Detection and Response — Compute Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — instance metadata theft and off-instance credential use
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — credential-binding and where-used detection
