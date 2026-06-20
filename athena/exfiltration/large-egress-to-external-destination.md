# Large Data Egress: Sustained Outbound to an External Destination

Detects an internal workload sending a large accepted volume to a single external address. After collection comes the transfer out, and sustained accepted flows carrying large byte volumes are the exfiltration leg, visible in VPC Flow Logs even when the application layer is opaque.

## ATT&CK

- **Technique:** T1048. Exfiltration Over Alternative Protocol, T1041, Exfiltration Over C2 Channel
- **Tactic:** Exfiltration

## Severity

**High.** The pairing of a non-internal destination with sustained byte volume is the egress signature; an unusual destination port strengthens it. It is the visible end of a data-theft chain.

## Data Sources

- VPC Flow Logs, `vpc_flow_logs` table in Athena
- Requires: flow logs enabled on the relevant VPCs or subnets and delivered to S3

## Query

```sql
SELECT
    srcaddr,
    dstaddr,
    dstport,
    COUNT(*)   AS flows,
    SUM(bytes) AS total_bytes
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND NOT regexp_like(dstaddr, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND "start" >= to_unixtime(current_timestamp - interval '1' hour)
GROUP BY srcaddr, dstaddr, dstport
HAVING SUM(bytes) >= 524288000
ORDER BY total_bytes DESC;
```

## What Triggers This

A workload moving a large volume outbound:

- 500 MB or more accepted to a single external address in the window
- A destination outside internal ranges, often on an unusual port
- Sustained flows rather than a single transient connection

## False Positives

1. **Backups and updates.** Cloud backups, software updates, and image pulls move large volumes outbound. Allowlist known provider destinations.
2. **Log shipping and SaaS.** Telemetry and SaaS integrations egress steadily. Confirm the destination resolves to a known service.
3. **Replication.** Cross-region or cross-account replication carries volume by design. Map the source workload.

## Tuning Notes

- **Threshold to baseline.** Set the byte floor to your normal outbound profile.
- **Allowlist destinations.** Maintain provider, partner, and update-endpoint ranges so only unexpected egress surfaces.
- **Resolve the source.** Flow logs show the VPC-internal source address; correlate `srcaddr` to the instance and its role. Add a time-partition predicate to bound the scan.

## Validation

1. From a test instance, transfer a large file to an external test endpoint.
2. Confirm the `srcaddr` / `dstaddr` pair surfaces above the byte threshold.

## Learn More

- [AWS Incident Detection and Response: S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/). reading exfiltration from flow logs and weighting on bytes
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). egress-volume detection design
