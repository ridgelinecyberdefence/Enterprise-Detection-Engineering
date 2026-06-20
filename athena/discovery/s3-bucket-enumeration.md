# S3 Bucket Enumeration

**ATT&CK:** T1619 Cloud Storage Object Discovery; T1580 Cloud Infrastructure Discovery. Tactic: Discovery.

**Severity:** Medium. Enumerating buckets is the reconnaissance that precedes cloud data theft. It is low-cost for the attacker and easy to miss, but a principal that suddenly lists the whole estate when it normally touches one or two buckets is mapping targets.

**Data Sources:** CloudTrail management events over `cloudtrail_logs` (`ListBuckets`, `ListObjects`, `GetBucketAcl`, `GetBucketPolicy`).

**Query:**

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

**What Triggers This:** A principal making a burst of bucket- and ACL-listing calls. `ListBuckets` is account-wide and rarely used by application roles, so it is a particularly useful anchor; combined with ACL and policy reads it shows an actor measuring what is exposed.

**False Positives:** Cloud security posture tools, backup discovery, and inventory jobs enumerate buckets and ACLs by design and will be the loudest sources. Distinguish by whether the principal is a known scanner or inventory role.

**Tuning Notes:** Allowlist posture-management, backup, and inventory roles by ARN; these are the dominant false positives and should be excluded first. Treat `ListBuckets` from a role that normally operates on a single bucket as higher severity. Tighten the window and threshold to your environment's baseline.

**Validation:** With a test role, run `aws s3api list-buckets` and several `get-bucket-acl` calls within the window; confirm the principal surfaces above the threshold.

**Learn More:** [AWS Incident Detection and Response: S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers enumeration as the precursor to cloud data theft.
