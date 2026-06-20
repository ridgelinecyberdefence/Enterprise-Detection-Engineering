# IAM Identity Manufacture Burst

**ATT&CK:** T1136.003 Create Account: Cloud Account; T1098 Account Manipulation. Tactics: Persistence, Privilege Escalation.

**Severity:** High. An attacker who has compromised one principal often manufactures a fresh identity to hold durable access that survives the original key being rotated. A single actor performing several distinct identity-creation actions in a short span is the manufacture signature.

**Data Sources:** AWS CloudTrail management events over `cloudtrail_logs` (IAM).

**Query:**

```sql
SELECT
    useridentity.arn                  AS actor,
    sourceipaddress                   AS source_ip,
    COUNT(DISTINCT eventname)         AS distinct_create_verbs,
    COUNT(*)                          AS calls,
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

**What Triggers This:** One actor performing two or more distinct identity-creation or permission-granting actions in a short window: creating a user, minting an access key, adding a console login, then attaching policy. Done together and quickly, this is the construction of a backdoor identity, not the slow cadence of normal administration.

**False Positives:** Onboarding automation and IaC that provisions a new user with key, login, and policy in one run will match. Distinguish by whether the actor is the known provisioning role and whether the new principal follows naming and tagging standards.

**Tuning Notes:** Allowlist provisioning and IaC roles by ARN. The `>= 2 distinct verbs` floor is deliberately low for fidelity through breadth; tighten the window before raising it. For higher confidence, weight `CreateLoginProfile` (programmatic principal gaining interactive console access) and external `sourceipaddress` upward.

**Validation:** With a test admin role, create a throwaway user, attach a policy, and create an access key within the window; confirm the actor surfaces with `distinct_create_verbs >= 2`. Delete the test principal afterward.

**Learn More:** [AWS Incident Detection and Response: Privilege Escalation and Persistence](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers identity manufacture and counting distinct create verbs as the detection.
