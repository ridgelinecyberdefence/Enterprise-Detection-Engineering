# AWS RunInstances Resource Hijacking: Unexpected Compute Launch

Detects EC2 instance launches that fit the resource-hijacking pattern: initiated by an IAM user (rather than an auto-scaling service), at unusual scale, or with compute types associated with mining. Stolen credentials are routinely used to spin up compute for cryptomining, billed to the victim.

## ATT&CK

- **Technique:** T1496. Resource Hijacking, T1578.002, Modify Cloud Compute Infrastructure: Create Cloud Instance
- **Tactic:** Impact, Defense Evasion

## Severity

**High.** Unexpected launches run up cost and give the attacker infrastructure inside the account. A burst of large or GPU instances launched directly by a user is the mining signature.

## Data Sources

- AWS CloudTrail management events (`RunInstances`)
- Requires: CloudTrail capturing EC2 management events; enrichment to baseline expected instance types

## Query: Sigma

```yaml
title: AWS RunInstances Resource Hijacking
id: rc-sigma-aws-004
status: production
description: |
  Detects EC2 RunInstances calls made directly by an IAM user, which is
  unusual where launches normally come from auto-scaling or IaC service
  principals. Tune the instance-type list to your environment.
author: Ridgeline Cyber Detection Engineering
date: 2026/06/20
tags:
  - attack.impact
  - attack.defense_evasion
  - attack.t1496
  - attack.t1578.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'RunInstances'
    userIdentity.type: 'IAMUser'
  condition: selection
falsepositives:
  - Auto-scaling and infrastructure-as-code launches (usually AssumedRole or service principals)
  - Build farms and batch jobs launching at scale
  - Legitimate GPU or compute-optimised workloads
level: high
```

## What Triggers This

Compute launched in a way that does not fit normal operations:

- A `RunInstances` call made directly by an IAM user rather than scaling automation
- Large instance counts or GPU and compute-optimised types associated with mining
- Launches in an unused region or from an unfamiliar AMI

## False Positives

1. **Auto-scaling and IaC.** These launch by design, usually as service principals or assumed roles. The IAM-user filter removes most; allowlist any user-driven exceptions.
2. **Batch and CI.** Build farms launch at scale. Confirm the principal and instance profile.
3. **GPU workloads.** ML training uses GPU types. Confirm against known workloads.

## Tuning Notes

- **Baseline instance types.** Maintain a list of expected types so GPU and compute-optimised launches stand out; add a `requestParameters.instanceType` selection for those.
- **Combine signals.** Direct IAM-user launch plus an unused region plus an unusual type is high confidence.
- **Conversion.** Convert to your AWS SIEM backend; the Athena equivalent ships under `athena/impact/`.

## Validation

1. In a test account, launch a small instance directly as an IAM user.
2. Confirm the rule fires with the principal and instance details.

## Learn More

- [AWS Incident Detection and Response: Compute Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). resource hijacking and cryptomining launch patterns
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). multi-signal launch detection
