# S3 Mass Object Deletion

**ATT&CK:** T1485 Data Destruction. Tactic: Impact.

**Severity:** Critical. Bulk deletion of objects, particularly from backup or recovery buckets, is destructive impact and frequently the final move of a cloud ransom or sabotage operation. Speed of detection determines whether recovery is possible.

**Data Sources:** S3 data events in CloudTrail (`DeleteObject`, `DeleteObjects`). Requires data-event logging.

**Query:**

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

**What Triggers This:** A principal deleting many objects in a short window. The strongest case is deletion concentrated on a backup or recovery bucket, or paired with a recent `PutBucketVersioning` or `DeleteBucketPolicy` that removed protection first.

**False Positives:** Lifecycle cleanup jobs, expired-data purges, and CI teardown delete in bulk by design, though many use lifecycle rules rather than API deletes. Distinguish by whether the principal is the known cleanup role and whether the bucket is a working bucket rather than a protected one.

**Tuning Notes:** Lower the threshold for backup and recovery buckets (any bulk delete there is notable) and raise it for transient working buckets. Allowlist lifecycle and CI roles by ARN. Correlate with versioning or object-lock changes immediately preceding the deletes, which indicate protection was stripped first.

**Validation:** In a test bucket, delete a hundred or more disposable objects within the window and confirm the principal surfaces with `deletes >= 100`.

**Learn More:** [AWS Incident Detection and Response: S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers destructive S3 activity and the protection-stripping that precedes it.
