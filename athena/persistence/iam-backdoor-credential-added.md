# Backdoor Credential Added to an Existing Principal

**ATT&CK:** T1098.001 Account Manipulation: Additional Cloud Credentials. Tactic: Persistence.

**Severity:** High. Adding a second access key or a console login profile to an existing principal is quiet, durable persistence: it survives rotation of the original credential and rarely looks out of place in isolation.

**Data Sources:** AWS CloudTrail management events over `cloudtrail_logs` (IAM).

**Query:**

```sql
SELECT
    eventtime,
    useridentity.arn AS actor,
    sourceipaddress  AS source_ip,
    eventname,
    json_extract_scalar(requestparameters, '$.userName') AS target_user
FROM cloudtrail_logs
WHERE eventname IN ('CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile')
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
  AND ( json_extract_scalar(requestparameters, '$.userName') IS NULL
        OR json_extract_scalar(requestparameters, '$.userName') <> useridentity.username )
ORDER BY eventtime;
```

**What Triggers This:** A principal adding an access key or console login to a user other than itself, or adding interactive console access to an account that previously had none. The cross-principal case (actor != target) is the strongest, because users normally manage only their own credentials.

**False Positives:** Help-desk and IAM-administration roles legitimately create credentials for others. Service-account key rotation creates new keys by design. Distinguish by whether the actor is a known administration role and whether the target follows expected patterns.

**Tuning Notes:** Allowlist help-desk and IAM-admin roles by ARN. Treat `CreateLoginProfile` on a principal that is normally programmatic (no prior console use) as higher severity. For service accounts, alert when a second active key exists rather than on each `CreateAccessKey`.

**Validation:** With a test admin role, create an access key for a different throwaway user; confirm the event surfaces with `actor` != `target_user`. Remove the key afterward.

**Learn More:** [AWS Incident Detection and Response: Privilege Escalation and Persistence](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers credential-based persistence on existing principals.
