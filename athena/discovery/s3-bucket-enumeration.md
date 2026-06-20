# S3 Bucket Enumeration: Account-Wide Listing

Detects a principal making a burst of bucket- and ACL-listing calls. Enumerating buckets is the reconnaissance that precedes cloud data theft: low-cost for the attacker, easy to miss, and a clear tell when a principal that normally touches one bucket suddenly maps the estate.

## ATT&CK

- **Technique:** T1619. Cloud Storage Object Discovery, T1580, Cloud Infrastructure Discovery
- **Tactic:** Discovery

## Severity

**Medium.** Enumeration is reconnaissance, not yet theft, so it sits at Medium on its own. It rises when the same principal then reads or copies objects, or when `ListBuckets` comes from a role that operates on a single bucket.

## Data Sources

- AWS CloudTrail management events. `cloudtrail_logs` table (`ListBuckets`, `GetBucketAcl`, `GetBucketPolicy`)
- Requires: CloudTrail capturing S3 management events

## Query

```sql
SELECT
    useridentity.arn  AS principal,
    useridentity.type AS principal_type,
    sourceipaddress   AS source_ip,
    COUNT(*)          AS enum_calls,
    array_distinct(array_agg(eventname)) AS actions,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('ListBuckets', 'ListObjects', 'ListObjectsV2',
                    'GetBucketAcl', 'GetBucketPolicy', 'GetBucketLocation')
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, useridentity.type, sourceipaddress
HAVING COUNT(*) >= 20
ORDER BY enum_calls DESC;
```

## What Triggers This

A principal measuring what storage is exposed:

- `ListBuckets`, which is account-wide and rare for an application role
- ACL and policy reads across many buckets, measuring exposure
- A burst concentrated in a short window rather than steady access

## False Positives

1. **Posture tools.** Cloud security posture management enumerates buckets and ACLs by design and is usually the loudest source. Allowlist it by ARN.
2. **Backup discovery.** Backup and inventory jobs list buckets. Confirm the principal is the known job role.
3. **Audit tooling.** Compliance scans read bucket policies broadly. Exclude known scanners.

## Tuning Notes

- **Allowlist scanners first.** Posture, backup, and inventory roles are the dominant false positives; exclude them by ARN before tuning thresholds.
- **Weight `ListBuckets`.** Treat it as higher severity from a role that normally operates on a single bucket.
- **Tune to baseline.** Set the threshold and window to your environment's normal enumeration volume.

## Validation

1. With a test role, run `aws s3api list-buckets` and several `get-bucket-acl` calls within the window.
2. Confirm the principal surfaces above the threshold with the actions listed.

## Learn More

- [AWS Incident Detection and Response: S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). enumeration as the precursor to cloud data theft
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). recon-burst detection over audit logs
