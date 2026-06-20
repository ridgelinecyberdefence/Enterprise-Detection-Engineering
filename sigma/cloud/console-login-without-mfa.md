# AWS Console Login Without MFA — Single-Factor Access

Detects a successful AWS Management Console sign-in where MFA was not used. Single-factor console access is the foothold a phished or leaked password buys, and on the root user or an administrator it is the difference between a stolen password and a full account compromise.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts, T1556 — Modify Authentication Process
- **Tactic:** Initial Access, Defense Evasion

## Severity

**High.** A console login without MFA means a password alone reached the account. It is Critical on the root user or an administrator.

## Data Sources

- AWS CloudTrail management events (`ConsoleLogin`)
- Requires: CloudTrail capturing console sign-in events with `additionalEventData`

## Query — Sigma

```yaml
title: AWS Console Login Without MFA
id: rc-sigma-aws-003
status: production
description: |
  Detects successful AWS console sign-ins where MFA was not satisfied.
  Federated sign-ins record MFA at the identity provider and may need
  separate handling.
author: Ridgeline Cyber Detection Engineering
date: 2026/06/20
tags:
  - attack.initial_access
  - attack.defense_evasion
  - attack.t1078.004
  - attack.t1556
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'ConsoleLogin'
    responseElements.ConsoleLogin: 'Success'
    additionalEventData.MFAUsed: 'No'
  condition: selection
falsepositives:
  - Federated or SSO sign-ins that record MFA at the identity provider
  - Documented break-glass emergency accounts
level: high
```

## What Triggers This

A console sign-in that bypassed a second factor:

- `MFAUsed` recorded as `No` on a successful `ConsoleLogin`
- The root user signing in at all, which should be rare and always MFA-backed
- An administrator authenticating single-factor

## False Positives

1. **Federated sign-in.** SSO records MFA upstream and can show `No` here. Handle federated principals separately.
2. **Break-glass accounts.** A documented emergency account may log in single-factor. Allowlist and monitor it separately.
3. **Service consoles.** Rare automated console flows. Confirm the principal.

## Tuning Notes

- **Escalate root and admins.** Treat any root `ConsoleLogin` and privileged single-factor login as Critical.
- **Account for federation.** Exclude or separately handle federated principals whose MFA is enforced upstream.
- **Conversion.** Convert to your AWS SIEM backend; the Athena equivalent ships under `athena/initial-access/`.

## Validation

1. In a test account, sign in to the console with an IAM user that has no MFA device.
2. Confirm the rule fires on the successful single-factor login.

## Learn More

- [AWS Incident Detection and Response — Detecting Credential Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — console sign-in analysis and the MFA signal
- [Detection Engineering — Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — authentication-strength detections
