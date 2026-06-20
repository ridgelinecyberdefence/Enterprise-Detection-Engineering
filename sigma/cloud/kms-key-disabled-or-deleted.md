# AWS KMS Key Disabled or Scheduled for Deletion — Recovery Inhibition

Detects a KMS key being disabled, scheduled for deletion, or having rotation turned off. Destroying or disabling the key that protects encrypted data makes that data permanently inaccessible, a destructive impact action and a cloud ransom lever.

## ATT&CK

- **Technique:** T1485 — Data Destruction
- **Tactic:** Impact

## Severity

**Critical.** A scheduled key deletion is a countdown to permanent data loss for everything that key protects. It should fire immediately, because cancelling the deletion has a deadline.

## Data Sources

- AWS CloudTrail management events (`kms.amazonaws.com`)
- Requires: CloudTrail capturing KMS management events

## Query — Sigma

```yaml
title: AWS KMS Key Disabled or Scheduled for Deletion
id: rc-sigma-aws-005
status: production
description: |
  Detects KMS actions that weaken or remove key protection, including
  scheduling a key for deletion (the highest-severity case, on a countdown).
author: Ridgeline Cyber Detection Engineering
date: 2026/06/20
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'kms.amazonaws.com'
    eventName:
      - 'ScheduleKeyDeletion'
      - 'DisableKey'
      - 'DisableKeyRotation'
  condition: selection
falsepositives:
  - Planned retirement of an unused key
  - Infrastructure-as-code managing key state
  - Deliberate rotation-policy changes
level: high
```

## What Triggers This

An action that weakens or removes key protection:

- `ScheduleKeyDeletion`, the highest-severity case, on a deletion countdown
- `DisableKey`, removing access to data the key protects
- `DisableKeyRotation`, weakening the key's posture

## False Positives

1. **Key lifecycle management.** Planned retirement of an unused key. Correlate with change records and the key's usage.
2. **IaC reconciliation.** Infrastructure-as-code managing key state. Allowlist the IaC principal.
3. **Rotation changes.** Deliberate rotation adjustments. Confirm the actor and intent.

## Tuning Notes

- **Treat ScheduleKeyDeletion as immediate.** The pending window is the only response time you have; route it straight to alert.
- **Allowlist IaC upstream.** Exclude infrastructure automation that manages key state.
- **Conversion.** Convert to your AWS SIEM backend; the Athena equivalent ships under `athena/impact/`.

## Validation

1. In a test account, schedule deletion of a disposable KMS key, then cancel it immediately.
2. Confirm the rule fires on the `ScheduleKeyDeletion` event.

## Learn More

- [AWS Incident Detection and Response — Defense Evasion](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — destructive control-plane actions and recovery inhibition
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — alerting on protective-control removal
