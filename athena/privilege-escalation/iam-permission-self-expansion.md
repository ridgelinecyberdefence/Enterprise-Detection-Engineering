# IAM Permission Expansion — Policy Attach and Version Pivot

Detects a principal granting itself or another identity wider permissions by attaching a managed or inline policy or by publishing and defaulting a new policy version. `CreatePolicyVersion` with `setAsDefault` is a favoured path because it widens permissions without an obvious attach call.

## ATT&CK

- **Technique:** T1098 — Account Manipulation
- **Tactic:** Privilege Escalation, Persistence

## Severity

**High.** Attaching a broad managed policy or publishing a new default policy version is how a foothold becomes administrative access. The strongest cases are an actor modifying its own permissions and any `AdministratorAccess` attachment.

## Data Sources

- AWS CloudTrail management events — `cloudtrail_logs` table (IAM)
- Requires: CloudTrail capturing IAM control-plane events

## Query

```sql
SELECT
    eventtime,
    useridentity.arn AS actor,
    sourceipaddress  AS source_ip,
    eventname,
    json_extract_scalar(requestparameters, '$.policyArn')    AS policy_arn,
    json_extract_scalar(requestparameters, '$.userName')     AS target_user,
    json_extract_scalar(requestparameters, '$.setAsDefault') AS set_as_default
FROM cloudtrail_logs
WHERE eventname IN ('AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy',
                    'PutRolePolicy', 'CreatePolicyVersion', 'SetDefaultPolicyVersion')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
```

## What Triggers This

A principal widening permissions on itself or another identity:

- Attaching a managed or inline policy, especially `AdministratorAccess`
- Publishing a new policy version and setting it as default to widen access quietly
- Self-escalation, where the actor ARN equals the target user

## False Positives

1. **Platform and IaC roles.** Infrastructure-as-code and platform automation manage policy routinely. Allowlist them by ARN.
2. **Approved changes.** Permission grants that match an approved baseline or ticket. Correlate with change records.
3. **Onboarding.** New-hire provisioning attaches policy by design. Confirm against the provisioning role.

## Tuning Notes

- **Allowlist by ARN.** Exclude administration and IaC principals.
- **Escalate the sharp cases.** Raise severity when `policyArn` ends in `AdministratorAccess`, when `set_as_default` is true, or when `target_user` equals the actor.
- **Self-escalation check.** Compare `useridentity.arn` against the `userName` request parameter to surface actors modifying their own permissions.

## Validation

1. In a test account, attach a scoped policy to a throwaway user and publish a new default policy version.
2. Confirm both events surface with the expected `policy_arn` and `set_as_default` values.

## Learn More

- [AWS Incident Detection and Response — Privilege Escalation and Persistence](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) — policy-version pivots and self-escalation detection
- [Detection Engineering — Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — modelling privilege-change events
