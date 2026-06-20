# IAM Permission Expansion and Policy Version Pivot

**ATT&CK:** T1098 Account Manipulation. Tactics: Privilege Escalation, Persistence.

**Severity:** High. Attaching a broad managed policy or publishing a new default policy version is how a foothold becomes administrative access. `CreatePolicyVersion` with `setAsDefault` is especially favoured because it widens permissions without an obvious `AttachPolicy` call.

**Data Sources:** AWS CloudTrail management events over `cloudtrail_logs` (IAM).

**Query:**

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

**What Triggers This:** A principal granting itself or another identity wider permissions, by attaching a managed or inline policy or by publishing and defaulting a new policy version. The interesting cases are an actor modifying its own permissions and any `AdministratorAccess` attachment.

**False Positives:** Platform and IaC roles legitimately manage policy. Distinguish by whether the actor is a known administration or IaC principal and whether the change matches an approved baseline.

**Tuning Notes:** Allowlist administration and IaC roles by ARN. Raise severity automatically when `policyArn` ends in `AdministratorAccess`, when `target_user` equals the actor (self-escalation), or when `set_as_default` is true. For self-escalation specifically, compare `useridentity.arn` against the `userName` request parameter.

**Validation:** In a test account, attach a scoped policy to a throwaway user and publish a new default policy version; confirm both surface with the expected `policy_arn` and `set_as_default` values.

**Learn More:** [AWS Incident Detection and Response: Privilege Escalation and Persistence](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers policy-version pivots and self-escalation detection.
