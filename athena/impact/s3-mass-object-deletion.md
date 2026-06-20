# S3 Mass Object Deletion — Destructive Impact

Detects a principal deleting many objects in a short window, particularly from backup or recovery buckets. Bulk deletion is destructive impact and frequently the final move of a cloud ransom or sabotage operation, where speed of detection determines whether recovery is possible.

## ATT&CK

- **Technique:** T1485 — Data Destruction
- **Tactic:** Impact

## Severity

**Critical.** Deletion concentrated on a backup or recovery bucket, or paired with a recent change that stripped protection, is an active destructive event. Response time determines whether the data is recoverable.

## Data Sources

- S3 data events in CloudTrail — `cloudtrail_logs` table (`DeleteObject`, `DeleteObjects`)
- Requires: S3 data-event logging enabled

## Query

```sql
SELECT
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
    COUNT(*)         AS deletes,
    min(eventtime)   AS first_delete,
    max(eventtime)   AS last_delete
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname  IN ('DeleteObject', 'DeleteObjects')
  AND eventtime  >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, sourceipaddress,
         json_extract_scalar(requestparameters, '$.bucketName')
HAVING COUNT(*) >= 100
ORDER BY deletes DESC;
```

## What Triggers This

A principal destroying objects at volume:

- Many `DeleteObject` or `DeleteObjects` calls in a short window
- Deletion concentrated on a backup or recovery bucket
- A preceding `PutBucketVersioning` or `DeleteBucketPolicy` that removed protection first

## False Positives

1. **Lifecycle cleanup.** Purge jobs delete in bulk, though many use lifecycle rules rather than API deletes. Allowlist cleanup roles by ARN.
2. **CI teardown.** Pipelines tearing down working buckets. Confirm the bucket is transient, not protected.
3. **Expired-data jobs.** Scheduled removal of aged data. Distinguish by the principal and target bucket.

## Tuning Notes

- **Tier by bucket.** Lower the threshold for backup and recovery buckets, where any bulk delete is notable; raise it for transient working buckets.
- **Allowlist by ARN.** Exclude lifecycle and CI roles.
- **Correlate protection stripping.** Flag versioning or object-lock changes immediately preceding the deletes, which indicate protection was removed first.

## Validation

1. In a test bucket, delete a hundred or more disposable objects within the window.
2. Confirm the principal surfaces with `deletes >= 100`.

## Learn More

- [AWS Incident Detection and Response — S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — destructive S3 activity and the protection-stripping that precedes it
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — impact-stage detection design
