# IAM Identity Manufacture: Burst of Create Verbs

Detects one actor performing several distinct identity-creation or permission-granting actions in a short window. An attacker who has compromised a principal often manufactures a fresh identity to hold durable access that survives the original key being rotated.

## ATT&CK

- **Technique:** T1136.003. Create Account: Cloud Account, T1098, Account Manipulation
- **Tactic:** Persistence, Privilege Escalation

## Severity

**High.** A single actor performing several distinct identity-creation actions quickly is the manufacture signature: create a user, mint a key, add a console login, attach a policy. Done together it is the construction of a backdoor, not the slow cadence of normal administration.

## Data Sources

- AWS CloudTrail management events, `cloudtrail_logs` table (IAM)
- Requires: CloudTrail capturing IAM control-plane events

## Query

```sql
SELECT
    useridentity.arn                     AS actor,
    sourceipaddress                      AS source_ip,
    COUNT(DISTINCT eventname)            AS distinct_create_verbs,
    COUNT(*)                             AS calls,
    array_distinct(array_agg(eventname)) AS actions,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventname IN ('CreateUser', 'CreateAccessKey', 'CreateLoginProfile',
                    'AttachUserPolicy', 'PutUserPolicy', 'CreatePolicyVersion')
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(DISTINCT eventname) >= 2
ORDER BY distinct_create_verbs DESC;
```

## What Triggers This

One actor performing two or more distinct create verbs in a short window:

- Creating a user, then minting an access key for it
- Adding a console login profile to a new or existing principal
- Attaching or inlining a policy to grant the new identity reach

Done together and quickly, this is backdoor-identity construction rather than routine admin.

## False Positives

1. **Onboarding automation.** Provisioning that creates a user with key, login, and policy in one run will match. Allowlist the provisioning role by ARN.
2. **IaC apply.** Infrastructure-as-code creating identities in a batch. Confirm the actor and that new principals follow naming and tagging standards.
3. **Bulk admin.** A genuine administrative batch during a maintenance window. Correlate with change records.

## Tuning Notes

- **Allowlist by ARN.** Exclude provisioning and IaC roles.
- **Keep the floor low.** The `>= 2 distinct verbs` floor earns fidelity through breadth; tighten the window before raising it.
- **Weight the sharp signals.** Raise severity for `CreateLoginProfile` on a normally programmatic principal and for external `sourceipaddress`.

## Validation

1. With a test admin role, create a throwaway user, attach a policy, and create an access key within the window.
2. Confirm the actor surfaces with `distinct_create_verbs >= 2`, then delete the test principal.

## Learn More

- [AWS Incident Detection and Response: Privilege Escalation and Persistence](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). identity manufacture and counting distinct create verbs
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). distinct-verb burst detection
