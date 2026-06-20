# Activity in an Unused Region — Out-of-Footprint Operations

Detects API activity in an AWS region the organisation does not normally operate in. Attackers favour unused regions because monitoring and guardrails are often weaker there, making an out-of-footprint region a deliberate evasion choice.

## ATT&CK

- **Technique:** T1535 — Unused/Unsupported Cloud Regions
- **Tactic:** Defense Evasion

## Severity

**Medium.** Region drift is suspicious rather than conclusive on its own, so it sits at Medium. It rises sharply when the activity is compute launches (cryptomining) or identity changes rather than read-only calls.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table (`awsregion`)
- Requires: a multi-region trail; single-region trails cannot see the drift

## Query

```sql
SELECT
    awsregion        AS region,
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    COUNT(*)         AS calls,
    array_distinct(array_agg(eventname)) AS actions,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE awsregion NOT IN ('eu-west-2', 'eu-west-1')   -- replace with your operating regions
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY awsregion, useridentity.arn, sourceipaddress
ORDER BY calls DESC;
```

## What Triggers This

Operations outside the normal regional footprint:

- Any management activity in a region not on the operating list
- Compute launches (`RunInstances`) or identity changes there, the high-severity cases
- A principal that normally operates only in the home regions appearing elsewhere

## False Positives

1. **Global services.** IAM, STS, CloudFront, and Route 53 log against `us-east-1` regardless of where you operate. Exclude global-service event sources or pin them out.
2. **Planned expansion.** A genuine new region rollout. Update the operating-region list when footprint changes.
3. **Disaster-recovery tests.** DR exercises touch standby regions. Allowlist the DR region during the window.

## Tuning Notes

- **Maintain the operating-region list.** Replace the hard-coded regions with your real footprint and keep it current.
- **Exclude global services.** Pin out IAM/STS/CloudFront/Route 53 so `us-east-1` global logging does not dominate.
- **Escalate by action.** Weight `RunInstances` and IAM changes in an unused region far above read-only calls.

## Validation

1. In a test account, run a benign call such as `aws ec2 describe-instances` in a region outside your operating list.
2. Confirm the region surfaces with the principal and action listed.

## Learn More

- [AWS Incident Detection and Response — Defense Evasion](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — region drift as an evasion signal
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — footprint-relative anomaly design
