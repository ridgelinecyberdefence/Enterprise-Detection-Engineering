# S3 Mass Object Read by a Single Principal

**ATT&CK:** T1530 Data from Cloud Storage. Tactic: Collection.

**Severity:** High. Bulk reads from a bucket holding backups, exports, or customer data are the staging step of cloud data theft. The volume and concentration on one principal or source separate it from the steady trickle of normal application access.

**Data Sources:** S3 data events in CloudTrail (`GetObject`) and, where enabled, S3 server access logs (`s3_access_logs`). S3 object reads are only captured when data-event logging is turned on.

**Query:**

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

**What Triggers This:** One principal reading a large number of objects in a short window, especially across buckets it does not normally touch. The course's lesson applies directly: legitimate access is dispersed and steady, while collection is concentrated and bursty.

**False Positives:** Backup jobs, analytics pipelines, replication, and data-export features read in bulk by design. Distinguish by whether the principal is the known job role and whether the buckets are its usual targets.

**Tuning Notes:** Set the `object_reads` threshold to your environment's normal per-principal read volume; 500 per hour is a starting point. Allowlist backup, analytics, and replication roles by ARN. If S3 server access logs are available, corroborate with `SUM(bytessent)` from `s3_access_logs` to weight on bytes moved rather than object count. Requires S3 data events enabled.

**Validation:** With a test role, read several hundred small objects from a test bucket inside the window; confirm the principal surfaces with `object_reads` above the threshold.

**Learn More:** [AWS Incident Detection and Response: S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers distinguishing bulk collection from normal object access.
