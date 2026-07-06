# Console Login Without MFA: Single-Factor Access

Detects a successful AWS Management Console sign-in where MFA was not used. Single-factor console access is the foothold a phished or leaked password buys, and on a privileged or root identity it is the difference between a stolen password and a full account compromise.

## ATT&CK

- **Technique:** T1078.004. Valid Accounts: Cloud Accounts, T1556, Modify Authentication Process
- **Tactic:** Initial Access, Defense Evasion

## Severity

**High.** A console login without MFA means a password alone reached the account. It is Critical on the root user or an administrator, where the blast radius is the whole account.

## Data Sources

- AWS CloudTrail management events, `cloudtrail_logs` table (`ConsoleLogin`)
- Requires: CloudTrail capturing console sign-in events with `additionaleventdata`

## Query

```sql
SELECT
    eventtime,
    useridentity.arn AS principal,
    useridentity.type AS principal_type,
    sourceipaddress  AS source_ip,
    json_extract_scalar(additionaleventdata, '$.MFAUsed')        AS mfa_used,
    json_extract_scalar(responseelements, '$.ConsoleLogin')      AS result
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success'
  AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
ORDER BY eventtime;
```

## What Triggers This

A successful console sign-in that bypassed a second factor:

- `MFAUsed` recorded as `No` on a successful `ConsoleLogin`
- The root user signing in at all, which should be rare and always MFA-backed
- An administrator or privileged role authenticating single-factor

## False Positives

1. **Federated sign-in.** SSO and federated logins record MFA at the identity provider, not in CloudTrail, and can show `No` here. Confirm whether the principal is federated.
2. **Break-glass accounts.** A documented emergency account may log in single-factor by design. Allowlist it and alert on its use separately.
3. **Service consoles.** Rare automated console flows. Confirm the principal.

## Tuning Notes

- **Escalate root and admins.** Treat any root `ConsoleLogin` and any privileged identity as Critical regardless of MFA, and single-factor admin as immediate.
- **Account for federation.** Exclude or separately handle federated principals whose MFA is enforced upstream.
- **Allowlist break-glass.** Exclude the documented emergency identity and monitor it on its own.

## Validation

1. In a test account, sign in to the console with an IAM user that has no MFA device.
2. Confirm the event surfaces with `mfa_used = No` and `result = Success`.

## Learn More

- [AWS Incident Detection and Response: Detecting Credential Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). console sign-in analysis and the MFA signal
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). authentication-strength detections
