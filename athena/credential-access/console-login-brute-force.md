# Console Login Brute Force: Failures Then Success

Detects a burst of failed console sign-ins followed by a success from the same source, the console-surface equivalent of a brute force or spray that landed. A run of failures resolving into a success is the moment a guessing attack found the password.

## ATT&CK

- **Technique:** T1110, Brute Force
- **Tactic:** Credential Access

## Severity

**High.** Failures alone are noise; failures resolving to a success from the same source is a credential that was guessed and is now in use. Escalate to Critical when the successful principal is privileged.

## Data Sources

- AWS CloudTrail management events, `cloudtrail_logs` table (`ConsoleLogin`)
- Requires: CloudTrail capturing both failed and successful console sign-ins

## Query

```sql
SELECT
    sourceipaddress AS source_ip,
    COUNT_IF(json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Failure') AS failures,
    COUNT_IF(json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success') AS successes,
    array_distinct(array_agg(useridentity.arn)) AS principals,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY sourceipaddress
HAVING COUNT_IF(json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Failure') >= 10
   AND COUNT_IF(json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success') >= 1
ORDER BY failures DESC;
```

## What Triggers This

A source that failed repeatedly then got in:

- Ten or more failed `ConsoleLogin` events from one source in the window
- At least one success from that same source
- A spread of target principals, which leans toward spray rather than a single forgotten password

## False Positives

1. **Forgotten password.** A user fat-fingering their password several times then succeeding. The signal is weak when failures and the success share one principal and a known source.
2. **Shared egress.** Several users behind one NAT producing combined failures. Exclude known corporate egress.
3. **Password reset churn.** Post-reset confusion. Correlate with reset events.

## Tuning Notes

- **Weight breadth.** Many distinct target principals from one source shifts this from forgotten-password to spray; raise severity accordingly.
- **Allowlist egress.** Exclude corporate NAT and VPN ranges to remove the dominant false positive.
- **Escalate privileged success.** If the succeeding principal is an admin or root, treat as Critical.

## Validation

1. In a test account, attempt ten or more failed console logins from one host, then one success, within the window.
2. Confirm the source surfaces with `failures >= 10` and `successes >= 1`.

## Learn More

- [AWS Incident Detection and Response: Detecting Credential Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). console sign-in failure-to-success analysis
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). brute-force and spray detection on cloud consoles
