# Cloud Logging and Detection Disabled: CloudTrail, Config, GuardDuty

Detects any call that stops, deletes, or narrows logging and detection: CloudTrail trails and event selectors, GuardDuty detectors and members, AWS Config recorders, and VPC flow logs. Turning these off shortly after access is an attacker going dark, not routine administration.

## ATT&CK

- **Technique:** T1562.008. Impair Defenses: Disable or Modify Cloud Logs, T1562.001, Disable or Modify Tools
- **Tactic:** Defense Evasion

## Severity

**High.** The disabling event is itself one of the highest-value detections in a cloud estate, because everything after it may be invisible. It should fire immediately and is treated as an active incident when the actor or source is unexpected.

## Data Sources

- AWS CloudTrail management events, `cloudtrail_logs` table
- Requires: at least one trail still delivering; multi-region trails reduce the blind spot a regional disable creates

## Query

```sql
SELECT
    eventtime,
    eventname,
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    awsregion        AS region,
    errorcode        AS error
FROM cloudtrail_logs
WHERE eventname IN (
        'StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors',
        'DeleteDetector', 'UpdateDetector', 'DeleteMembers', 'DisassociateMembers',
        'StopConfigurationRecorder', 'DeleteConfigurationRecorder', 'DeleteFlowLogs')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
```

## What Triggers This

A call that removes or weakens visibility:

- CloudTrail `StopLogging`, `DeleteTrail`, or a narrowing `UpdateTrail` / `PutEventSelectors`
- GuardDuty `DeleteDetector`, `UpdateDetector`, or member removal
- AWS Config recorder stopped or deleted, or VPC flow logs deleted

`UpdateTrail` and `PutEventSelectors` are included because attackers often weaken rather than delete, leaving the trail present but blind.

## False Positives

1. **Planned teardown.** Account decommissioning and environment teardown generate these events. Correlate with change records.
2. **IaC drift correction.** Infrastructure-as-code reconciling logging configuration. Allowlist the IaC principal by ARN.
3. **Cost-driven selector changes.** Narrowing event selectors to manage spend. Confirm the actor and intent.

## Tuning Notes

- **Allowlist by ARN.** Exclude IaC and platform-automation principals rather than suppressing the event names.
- **Tier the verbs.** Route `UpdateTrail` and `PutEventSelectors` slightly below outright `StopLogging` / `DeleteTrail` if volume requires.
- **Escalate unexpected actors.** Any of these from an unknown principal or external source is immediate.

## Validation

1. In a test account, run `aws cloudtrail stop-logging` against a disposable trail.
2. Confirm the event surfaces, then re-enable logging immediately.

## Learn More

- [AWS Incident Detection and Response: Defense Evasion](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). logging and detection tampering as a high-priority signal
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). alerting on the absence and disabling of telemetry
