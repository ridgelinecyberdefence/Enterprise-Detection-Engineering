# Cloud Logging or Threat Detection Disabled

**ATT&CK:** T1562.008 Impair Defenses: Disable or Modify Cloud Logs; T1562.001 Disable or Modify Tools. Tactic: Defense Evasion.

**Severity:** High. Turning off CloudTrail, Config, or GuardDuty right after access is an attacker going dark, not routine administration. The disabling event is itself one of the highest-value detections in a cloud estate, and it should fire immediately because everything after it may be invisible.

**Data Sources:** AWS CloudTrail management events over `cloudtrail_logs`.

**Query:**

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
        'StopConfigurationRecorder', 'DeleteConfigurationRecorder',
        'DeleteFlowLogs')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
```

**What Triggers This:** Any call that stops, deletes, or narrows logging and detection: CloudTrail trails and event selectors, GuardDuty detectors and members, AWS Config recorders, and VPC flow logs. `UpdateTrail` and `PutEventSelectors` are included because attackers often weaken rather than delete, leaving the trail present but blind.

**False Positives:** Planned teardown, account decommissioning, IaC drift correction, and cost-driven selector changes all generate these events. Distinguish by whether the actor is a known platform or IaC role and whether a change ticket exists.

**Tuning Notes:** Allowlist your IaC and platform-automation principals by ARN rather than suppressing the event names. Keep `UpdateTrail` and `PutEventSelectors` in scope but route them at a slightly lower severity than outright `StopLogging`/`DeleteTrail` if alert volume requires. Treat any of these from an unexpected principal or external source as immediate.

**Validation:** In a test account, run `aws cloudtrail stop-logging` against a disposable trail and confirm the event surfaces; re-enable immediately.

**Learn More:** [AWS Incident Detection and Response: Defense Evasion](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers logging and detection tampering as a high-priority incident signal.
