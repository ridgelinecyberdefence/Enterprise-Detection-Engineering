# Snapshot or AMI Shared Externally — Data Transfer to Another Account

Detects an EBS snapshot or AMI being shared with an external AWS account or made public. Sharing a snapshot is a quiet exfiltration path: the attacker copies the data into infrastructure they control without a single byte crossing your egress.

## ATT&CK

- **Technique:** T1537 — Transfer Data to Cloud Account
- **Tactic:** Exfiltration

## Severity

**High.** A snapshot shared to an unknown account is whole volumes of data leaving your control through the control plane, invisible to network egress monitoring.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table (EC2)
- Requires: CloudTrail capturing `ModifySnapshotAttribute` and `ModifyImageAttribute`

## Query

```sql
SELECT
    eventtime,
    eventname,
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    json_extract_scalar(requestparameters, '$.snapshotId') AS snapshot_id,
    json_extract_scalar(requestparameters, '$.imageId')    AS image_id,
    json_extract_scalar(requestparameters, '$.attributeType') AS attribute,
    requestparameters AS raw_request
FROM cloudtrail_logs
WHERE eventname IN ('ModifySnapshotAttribute', 'ModifyImageAttribute')
  AND ( requestparameters LIKE '%"group":"all"%'
        OR regexp_like(requestparameters, '"userId":"[0-9]{12}"') )
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
```

## What Triggers This

A volume or image opened to another account:

- `ModifySnapshotAttribute` or `ModifyImageAttribute` adding a create-volume or launch permission
- A grant to `group: all`, making the snapshot or AMI public
- A grant to an external twelve-digit account ID that is not one of yours

## False Positives

1. **Cross-account sharing by design.** Organisations that share AMIs or snapshots between their own accounts. Allowlist your known account IDs.
2. **Vendor and marketplace flows.** Sharing with a partner or marketplace account. Confirm the recipient.
3. **Backup tooling.** Some backup products share snapshots to a vault account. Exclude the backup account ID.

## Tuning Notes

- **Allowlist your account IDs.** Maintain the set of internal and trusted partner accounts so only external grants surface.
- **Treat public as Critical.** A `group: all` grant exposes data to anyone and should escalate immediately.
- **Resolve the recipient.** Extract and check the granted account ID against your allowlist rather than alerting on every share.

## Validation

1. In a test account, share a disposable snapshot with a second test account, then revoke the share.
2. Confirm the `ModifySnapshotAttribute` event surfaces with the recipient account ID.

## Learn More

- [AWS Incident Detection and Response — S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — control-plane exfiltration paths beyond S3
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — detecting data transfer through resource sharing
