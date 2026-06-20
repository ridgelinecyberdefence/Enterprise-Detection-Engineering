# External Read-Only Reconnaissance: Describe and List Burst

Detects a principal making many distinct read-only API calls from an external source. After landing on a credential, an attacker maps the account with `Describe*`, `List*`, and `Get*` calls before acting, so breadth of distinct read verbs from outside the environment is the recon signature.

## ATT&CK

- **Technique:** T1526. Cloud Service Discovery, T1580, Cloud Infrastructure Discovery
- **Tactic:** Discovery

## Severity

**Medium.** Reconnaissance is the orientation step, not yet impact, so it sits at Medium. It rises when the same principal then performs a write or when the source is external and previously unseen.

## Data Sources

- AWS CloudTrail management events. `cloudtrail_logs` table (`readonly = 'true'`)
- Requires: CloudTrail with the `readonly` field populated

## Query

```sql
SELECT
    useridentity.arn AS principal,
    sourceipaddress  AS source_ip,
    COUNT(DISTINCT eventname) AS distinct_reads,
    COUNT(*)         AS total_reads,
    array_distinct(array_agg(eventsource)) AS services,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE readonly = 'true'
  AND NOT regexp_like(sourceipaddress, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND sourceipaddress NOT LIKE '%.amazonaws.com'
  AND eventtime >= to_iso8601(current_timestamp - interval '1' hour)
GROUP BY useridentity.arn, sourceipaddress
HAVING COUNT(DISTINCT eventname) > 8
ORDER BY distinct_reads DESC;
```

## What Triggers This

A principal orienting itself across the account from outside:

- More than eight distinct read-only verbs in a short window
- Reads spanning several services (IAM, EC2, S3, STS), measuring what exists
- An external source, since recon from inside is far more likely benign

## False Positives

1. **Posture and inventory tools.** These read broadly across services by design. Allowlist their roles by ARN.
2. **Cost and audit tooling.** Billing and compliance scans enumerate widely. Exclude known scanners.
3. **Developer exploration.** An engineer exploring via the CLI. The external-source filter removes most of this.

## Tuning Notes

- **Allowlist scanners by ARN.** Posture, inventory, and audit roles are the dominant false positives; exclude them first.
- **Internal variant.** Drop the external filter and raise the distinct-read threshold to hunt internal recon at lower fidelity.
- **Escalate read-then-write.** Correlate with a subsequent write by the same principal to promote recon into an active intrusion.

## Validation

1. With a test role from an external host, run nine or more distinct `describe`/`list` calls across services within the window.
2. Confirm the principal surfaces with `distinct_reads > 8`.

## Learn More

- [AWS Incident Detection and Response: Detecting Credential Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). read-only reconnaissance and the read-then-write pivot
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). distinct-verb recon detection
