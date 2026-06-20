# Large Data Egress to an External Destination

**ATT&CK:** T1048 Exfiltration Over Alternative Protocol; T1041 Exfiltration Over C2 Channel. Tactic: Exfiltration.

**Severity:** High. After collection comes the transfer out. Sustained accepted flows carrying large byte volumes from a workload to an external address are the exfiltration leg, visible in VPC Flow Logs even when the application layer is opaque.

**Data Sources:** VPC Flow Logs (`vpc_flow_logs` Athena table).

**Query:**

```sql
SELECT
    srcaddr,
    dstaddr,
    dstport,
    COUNT(*)    AS flows,
    SUM(bytes)  AS total_bytes
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND NOT regexp_like(dstaddr, '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')
  AND "start" >= to_unixtime(current_timestamp - interval '1' hour)
GROUP BY srcaddr, dstaddr, dstport
HAVING SUM(bytes) >= 524288000
ORDER BY total_bytes DESC;
```

**What Triggers This:** An internal workload sending a large accepted volume (here, 500 MB or more in the window) to a single external address. The pairing of a non-RFC1918 destination with sustained byte volume is the egress signature; an unusual destination port strengthens it.

**False Positives:** Legitimate cloud backups, software updates, container image pulls, log shipping, and SaaS integrations move large volumes outbound. Distinguish by whether the destination resolves to a known provider or partner and whether the source workload is expected to egress.

**Tuning Notes:** Set the byte threshold to your environment's normal outbound profile. Allowlist known external destinations (provider CIDRs, partner ranges, update endpoints) so the alert surfaces only unexpected egress. Note that VPC Flow Logs show the VPC-internal source address; correlate `srcaddr` to the instance and its role. Add a time-partition predicate to bound the scan.

**Validation:** From a test instance, transfer a large file to an external test endpoint and confirm the `srcaddr`/`dstaddr` pair surfaces above the byte threshold.

**Learn More:** [AWS Incident Detection and Response: S3 and Data Exfiltration](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers reading exfiltration from flow logs and weighting on bytes to the attacker.
