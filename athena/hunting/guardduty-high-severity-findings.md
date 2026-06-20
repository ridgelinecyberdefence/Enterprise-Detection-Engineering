# GuardDuty High-Severity Findings — Surface and Correlate

Surfaces high-severity Amazon GuardDuty findings from the exported findings table and groups them by type, resource, and account for triage. GuardDuty already does detection; the value here is ingesting its output alongside your CloudTrail rules so a managed finding and your own queries corroborate into one picture.

## ATT&CK

- **Technique:** Correlation across GuardDuty finding types (credential access, discovery, exfiltration, impact)
- **Tactic:** Multiple — managed-detection ingestion

## Severity

**High.** A GuardDuty finding at severity 7 or above is the platform's own high-confidence verdict that something is wrong. Stacking it with your CloudTrail detections on the same resource is a strong, corroborated signal.

## Data Sources

- Amazon GuardDuty findings exported to S3 and defined as an Athena table — `guardduty_findings`
- Requires: GuardDuty enabled with findings exported (EventBridge to Firehose to S3, or Security Lake) and a table over the JSON

## Query

```sql
SELECT
    type        AS finding_type,
    severity,
    accountid   AS account,
    region,
    json_extract_scalar(resource, '$.resourceType')              AS resource_type,
    json_extract_scalar(service, '$.action.actionType')          AS action_type,
    COUNT(*)    AS occurrences,
    min(from_iso8601_timestamp(json_extract_scalar(service, '$.eventFirstSeen'))) AS first_seen,
    max(from_iso8601_timestamp(json_extract_scalar(service, '$.eventLastSeen')))  AS last_seen
FROM guardduty_findings
WHERE severity >= 7
  AND from_iso8601_timestamp(updatedat) >= current_timestamp - interval '24' hour
GROUP BY type, severity, accountid, region,
         json_extract_scalar(resource, '$.resourceType'),
         json_extract_scalar(service, '$.action.actionType')
ORDER BY severity DESC, occurrences DESC;
```

## What Triggers This

A managed high-confidence finding worth acting on:

- A GuardDuty finding at severity 7 or above (the high band on the 1 to 8.9 scale)
- Grouped by finding type, resource type, and account so duplicates collapse into one row
- The first- and last-seen times, for scoping how long the activity has run

## False Positives

1. **Known benign patterns.** GuardDuty findings that your environment generates legitimately (for example port-probe findings against an internet-facing service). Suppress those finding types or resources at source in GuardDuty.
2. **Penetration tests.** Authorized testing generates findings. Coordinate and suppress during the engagement.
3. **Severity drift.** A finding type consistently over- or under-scored for your context. Adjust the threshold per type.

## Tuning Notes

- **Manage suppression at source.** Use GuardDuty suppression rules for known-benign finding types so they never reach this table, rather than filtering here.
- **Correlate with CloudTrail rules.** Join `resource` to the principals in your CloudTrail detections so a GuardDuty finding and your own query on the same resource escalate together.
- **Tier by band.** Route severity 7+ to alert and 4 to 6.9 (medium) to a review queue.

## Validation

1. Generate a GuardDuty sample finding (`aws guardduty create-sample-findings`) and let it export to the table.
2. Confirm the finding surfaces with its type and severity.

## Learn More

- [AWS Incident Detection and Response — Cloud Incident Response](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — ingesting GuardDuty alongside CloudTrail detection
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — combining managed detection with custom analytics
