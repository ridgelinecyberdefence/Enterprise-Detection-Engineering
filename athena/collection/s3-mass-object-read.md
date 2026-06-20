# S3 Mass Object Read — Bulk Collection by One Principal

Detects one principal reading a large number of S3 objects in a short window, especially across buckets it does not normally touch. Bulk reads from buckets holding backups, exports, or customer data are the staging step of cloud data theft.

## ATT&CK

- **Technique:** T1530 — Data from Cloud Storage
- **Tactic:** Collection

## Severity

**High.** The volume and concentration on one principal or source separate collection from the steady trickle of normal application access. Bulk reads from sensitive buckets are the stage immediately before exfiltration.

## Data Sources

- S3 data events in CloudTrail (`GetObject`) and, where enabled, S3 server access logs — `cloudtrail_logs` and `s3_access_logs`
- Requires: S3 data-event logging enabled; object reads are not captured otherwise

## Query

```sql
SELECT
    useridentity.arn  AS principal,
    useridentity.type AS principal_type,
    sourceipaddress   AS source_ip,
    COUNT(*)          AS object_reads,
    COUNT(DISTINCT json_extract_scalar(requestparameters, '$.bucketName')) AS buckets,
    min(eventtime) AS first_read,
    max(eventtime) AS last_read
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname   = 'GetObject'
  AND eventtime  >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, useridentity.type, sourceipaddress
HAVING COUNT(*) >= 500
ORDER BY object_reads DESC;
```

## What Triggers This

One principal reading objects in bulk:

- A large count of `GetObject` calls in a short window
- Reads spanning buckets the principal does not normally access
- Concentration on one principal or source, unlike dispersed normal access

## False Positives

1. **Backup and replication.** These read in bulk by design. Allowlist the job roles by ARN.
2. **Analytics pipelines.** ETL and reporting jobs scan large object sets. Confirm the principal and its usual buckets.
3. **Data-export features.** Customer or admin exports read many objects. Distinguish by the feature's service role.

## Tuning Notes

- **Threshold to baseline.** Set `object_reads` to your normal per-principal read volume; 500 per hour is a starting point.
- **Allowlist jobs by ARN.** Exclude backup, analytics, and replication roles.
- **Weight on bytes.** Where S3 server access logs exist, corroborate with `SUM(bytessent)` from `s3_access_logs` to rank on data moved, not object count.

## Validation

1. With a test role, read several hundred small objects from a test bucket inside the window.
2. Confirm the principal surfaces with `object_reads` above the threshold.

## Learn More

- [AWS Incident Detection and Response — S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — distinguishing bulk collection from normal object access
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — volume and concentration as collection signals
