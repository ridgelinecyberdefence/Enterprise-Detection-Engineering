# IAM Backdoor Credential: Key or Login Added to a Principal

Detects a principal adding an access key or console login to a user other than itself, or adding interactive console access to an account that had none. This is quiet, durable persistence: it survives rotation of the original credential and rarely looks out of place in isolation.

## ATT&CK

- **Technique:** T1098.001. Account Manipulation: Additional Cloud Credentials
- **Tactic:** Persistence

## Severity

**High.** A second access key or a console login profile on an existing principal is a foothold that outlives credential rotation. The cross-principal case, where the actor and target differ, is the strongest, because users normally manage only their own credentials.

## Data Sources

- AWS CloudTrail management events, `cloudtrail_logs` table (IAM)
- Requires: CloudTrail capturing IAM control-plane events

## Query

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

## What Triggers This

A principal adding a credential to another identity:

- An access key minted for a user other than the actor
- A console login profile added to a programmatic account that never had one
- An existing login profile updated to reset access

## False Positives

1. **Help-desk and IAM admins.** These roles legitimately create credentials for others. Allowlist them by ARN.
2. **Service-account rotation.** Rotation creates new keys by design. Alert when a second active key exists rather than on each create.
3. **Self-service tooling.** Some platforms add credentials on a user's behalf. Confirm the calling role.

## Tuning Notes

- **Allowlist by ARN.** Exclude help-desk and IAM-admin roles.
- **Weight console-on-programmatic.** Treat `CreateLoginProfile` on a principal with no prior console use as higher severity.
- **Service accounts.** For these, alert on the existence of a second active key rather than each `CreateAccessKey`.

## Validation

1. With a test admin role, create an access key for a different throwaway user.
2. Confirm the event surfaces with `actor` not equal to `target_user`, then remove the key.

## Learn More

- [AWS Incident Detection and Response: Privilege Escalation and Persistence](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). credential-based persistence on existing principals
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). modelling cross-principal credential events
