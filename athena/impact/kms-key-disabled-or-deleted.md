# KMS Key Disabled or Scheduled for Deletion: Recovery Inhibition

Detects a KMS key being disabled, scheduled for deletion, or having rotation turned off. Destroying or disabling the key that protects encrypted data makes that data permanently inaccessible, which is a destructive impact action and a cloud ransom lever.

## ATT&CK

- **Technique:** T1485, Data Destruction
- **Tactic:** Impact

## Severity

**Critical.** A scheduled key deletion is a countdown to permanent data loss for everything that key protects. It should fire immediately, because the protective action (cancelling the deletion) has a deadline.

## Data Sources

- AWS CloudTrail management events, `cloudtrail_logs` table (`kms.amazonaws.com`)
- Requires: CloudTrail capturing KMS management events

## Query

```sql
SELECT
    eventtime,
    eventname,
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    json_extract_scalar(requestparameters, '$.keyId')               AS key_id,
    json_extract_scalar(requestparameters, '$.pendingWindowInDays') AS pending_days
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname IN ('ScheduleKeyDeletion', 'DisableKey', 'DisableKeyRotation', 'PutKeyPolicy')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
```

## What Triggers This

An action that weakens or removes key protection:

- `ScheduleKeyDeletion`, the highest-severity case, with the pending window noted
- `DisableKey` or `DisableKeyRotation`, weakening protection without deleting
- `PutKeyPolicy` that grants an external principal or removes guardrails

## False Positives

1. **Key lifecycle management.** Planned retirement of an unused key. Correlate with change records and the key's usage.
2. **IaC reconciliation.** Infrastructure-as-code managing key state. Allowlist the IaC principal.
3. **Rotation policy changes.** Deliberate rotation adjustments. Confirm the actor and intent.

## Tuning Notes

- **Treat ScheduleKeyDeletion as immediate.** The pending window is the only response time you have; route it straight to alert.
- **Allowlist IaC by ARN.** Exclude infrastructure automation that manages key state.
- **Weight external policy grants.** A `PutKeyPolicy` adding an external principal is a separate, high-severity concern.

## Validation

1. In a test account, schedule deletion of a disposable KMS key, then cancel it immediately.
2. Confirm the `ScheduleKeyDeletion` event surfaces with the key ID and pending window.

## Learn More

- [AWS Incident Detection and Response: Defense Evasion](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). destructive control-plane actions and recovery inhibition
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). alerting on protective-control removal
