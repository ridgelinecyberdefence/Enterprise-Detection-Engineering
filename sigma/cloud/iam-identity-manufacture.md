# AWS IAM Identity Manufacture: Burst of Create Verbs

Detects one actor performing several distinct IAM identity-creation actions, the construction of a backdoor identity that survives the original credential being rotated. Create a user, mint a key, add a console login, attach a policy: done together quickly, this is manufacture, not routine administration.

## ATT&CK

- **Technique:** T1136.003. Create Account: Cloud Account, T1098, Account Manipulation
- **Tactic:** Persistence, Privilege Escalation

## Severity

**High.** A manufactured identity is durable, attacker-controlled access. The signature is breadth of distinct create verbs from one actor in a short span.

## Data Sources

- AWS CloudTrail management events (IAM)
- Requires: CloudTrail capturing IAM control-plane events; correlation over a short time window in the SIEM

## Query: Sigma

```yaml
title: AWS IAM Identity Manufacture
id: rc-sigma-aws-002
status: production
description: |
  Detects IAM identity-creation and permission-granting calls used to build a
  backdoor principal. Most effective when correlated by actor over a short
  window so a burst of distinct create verbs stands out from single events.
author: Ridgeline Cyber Detection Engineering
date: 2026/06/20
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1136.003
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - 'CreateUser'
      - 'CreateAccessKey'
      - 'CreateLoginProfile'
      - 'AttachUserPolicy'
      - 'PutUserPolicy'
      - 'CreatePolicyVersion'
  condition: selection
falsepositives:
  - Onboarding automation provisioning a user with key, login, and policy
  - Infrastructure-as-code creating identities in a batch
  - Genuine bulk administration during a maintenance window
level: high
```

## What Triggers This

One actor building an identity:

- Creating a user, then minting an access key for it
- Adding a console login profile to a new or existing principal
- Attaching or inlining a policy to give the new identity reach

## False Positives

1. **Onboarding automation.** Provisioning that creates a full identity in one run. Allowlist the provisioning role.
2. **IaC apply.** Infrastructure-as-code creating identities in a batch. Confirm naming and tagging standards.
3. **Bulk admin.** A genuine administrative batch. Correlate with change records.

## Tuning Notes

- **Correlate by actor.** In the SIEM, group these events by actor over a short window and alert on two or more distinct verbs; single events are noisy.
- **Weight the sharp signals.** Raise severity for `CreateLoginProfile` on a normally programmatic principal and for external sources.
- **Conversion.** `sigma convert -t microsoft365defender` is not applicable here; convert to your AWS SIEM backend. The Athena equivalent ships under `athena/persistence/`.

## Validation

1. With a test admin role, create a throwaway user, attach a policy, and create an access key within a short window.
2. Confirm the events fire and correlate to one actor, then delete the test principal.

## Learn More

- [AWS Incident Detection and Response: Privilege Escalation and Persistence](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). identity manufacture and distinct create-verb correlation
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). burst-of-verbs detection design
