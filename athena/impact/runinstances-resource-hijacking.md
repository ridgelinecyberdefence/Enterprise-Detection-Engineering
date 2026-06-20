# RunInstances Resource Hijacking — Unexpected Compute Launch

Detects EC2 instance launches that fit the resource-hijacking pattern: launched from an external source, in an unusual region, or at unusual scale or instance type. Stolen credentials are routinely used to spin up compute for cryptomining, billed to the victim.

## ATT&CK

- **Technique:** T1496 — Resource Hijacking, T1578.002 — Modify Cloud Compute Infrastructure: Create Cloud Instance
- **Tactic:** Impact, Defense Evasion

## Severity

**High.** Unexpected compute launches run up cost and provide attacker infrastructure inside the account. A burst of large instances or GPU types from an external source is the cryptomining signature.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table (`RunInstances`)
- Requires: CloudTrail capturing EC2 management events

## Query

```sql
SELECT
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    awsregion        AS region,
    json_extract_scalar(requestparameters, '$.instanceType') AS instance_type,
    json_extract_scalar(requestparameters, '$.maxCount')     AS requested_count,
    json_extract_scalar(requestparameters, '$.imageId')      AS image_id,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen,
    COUNT(*)       AS launches
FROM cloudtrail_logs
WHERE eventname = 'RunInstances'
  AND NOT regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY useridentity.arn, sourceipaddress, awsregion,
         json_extract_scalar(requestparameters, '$.instanceType'),
         json_extract_scalar(requestparameters, '$.maxCount'),
         json_extract_scalar(requestparameters, '$.imageId')
ORDER BY launches DESC;
```

## What Triggers This

Compute launched in a way that does not fit normal operations:

- Launches initiated from an external source rather than internal automation
- Large instance counts or GPU and compute-optimised types associated with mining
- Launches in an unused region or from an unfamiliar AMI

## False Positives

1. **Auto-scaling and IaC.** Scaling events and infrastructure-as-code launch instances by design, usually from AWS service principals or internal automation. Allowlist those principals.
2. **Batch and CI.** Build farms and batch jobs launch at scale. Confirm the principal and instance profile.
3. **Legitimate GPU workloads.** ML training uses GPU types. Confirm against known workloads and accounts.

## Tuning Notes

- **Allowlist scaling and IaC.** Exclude auto-scaling, IaC, and batch principals, which dominate normal launches.
- **Baseline instance types.** Maintain a list of expected types so GPU and compute-optimised launches stand out.
- **Combine signals.** External source plus unused region plus unusual type together is high confidence; any one alone is weaker.

## Validation

1. In a test account, launch a small instance from outside the internal ranges (or simulate by reviewing a known launch).
2. Confirm the launch surfaces with the source, region, and instance type captured.

## Learn More

- [AWS Incident Detection and Response — Compute Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — resource hijacking and cryptomining launch patterns
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — multi-signal launch detection
