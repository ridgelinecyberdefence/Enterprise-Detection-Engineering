# AWS Logging or Detection Disabled: CloudTrail, Config, GuardDuty

Detects API calls that stop, delete, or weaken AWS logging and threat detection. Turning off CloudTrail, Config, or GuardDuty shortly after access is an attacker going dark, and the disabling event is one of the highest-value signals in a cloud estate because everything after it may be invisible.

## ATT&CK

- **Technique:** T1562.008. Impair Defenses: Disable or Modify Cloud Logs, T1562.001, Disable or Modify Tools
- **Tactic:** Defense Evasion

## Severity

**High.** This should fire immediately and is treated as an active incident when the actor or source is unexpected, because it blinds every detection downstream.

## Data Sources

- AWS CloudTrail management events (any SIEM ingesting CloudTrail)
- Requires: at least one trail still delivering; a multi-region trail reduces the blind spot a regional disable creates

## Query: Sigma

```yaml
title: AWS Logging or Detection Disabled
id: rc-sigma-aws-001
status: production
description: |
  Detects CloudTrail, Config, GuardDuty, and VPC flow log tampering that
  removes or weakens visibility in an AWS account.
author: Ridgeline Cyber Detection Engineering
date: 2026/06/20
tags:
  - attack.defense_evasion
  - attack.t1562.008
  - attack.t1562.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - 'StopLogging'
      - 'DeleteTrail'
      - 'UpdateTrail'
      - 'PutEventSelectors'
      - 'DeleteDetector'
      - 'UpdateDetector'
      - 'DeleteMembers'
      - 'StopConfigurationRecorder'
      - 'DeleteConfigurationRecorder'
      - 'DeleteFlowLogs'
  condition: selection
falsepositives:
  - Planned account decommissioning or environment teardown
  - Infrastructure-as-code reconciling logging configuration
  - Cost-driven event-selector changes
level: high
```

## What Triggers This

A call that removes or weakens visibility:

- CloudTrail `StopLogging`, `DeleteTrail`, or a narrowing `UpdateTrail` or `PutEventSelectors`
- GuardDuty detector or member removal
- AWS Config recorder stopped or deleted, or VPC flow logs deleted

## False Positives

1. **Planned teardown.** Account decommissioning generates these events. Correlate with change records.
2. **IaC reconciliation.** Infrastructure-as-code managing logging. Allowlist the IaC principal upstream.
3. **Selector tuning.** Cost-driven narrowing of event selectors. Confirm the actor and intent.

## Tuning Notes

- **Allowlist automation upstream.** Exclude IaC and platform-automation principals in the SIEM enrichment, not by dropping event names.
- **Tier the verbs.** Route `UpdateTrail` and `PutEventSelectors` slightly below outright `StopLogging` and `DeleteTrail` if volume requires.
- **Conversion.** `sigma convert -t splunk sigma/cloud/cloudtrail-logging-detection-disabled.yml`; the Athena equivalent ships in this repo under `athena/defense-evasion/`.

## Validation

1. In a test account, run `aws cloudtrail stop-logging` against a disposable trail.
2. Confirm the rule fires, then re-enable logging immediately.

## Learn More

- [AWS Incident Detection and Response: Defense Evasion](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). logging and detection tampering as a high-priority signal
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). alerting on telemetry tampering
