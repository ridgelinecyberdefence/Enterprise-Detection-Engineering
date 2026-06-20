# IAM Access Key Used Concurrently from Internal and External Sources

**ATT&CK:** T1078.004 Valid Accounts: Cloud Accounts. Tactics: Initial Access, Persistence, Privilege Escalation, Defense Evasion.

**Severity:** High. A long-term access key operated from two locations at once is close to conclusive evidence of credential theft, because a single key cannot legitimately be in two places. It is not Critical on its own only because a small number of architectures (split egress paths, shared CI keys) reproduce the pattern benignly; confirm against those before escalating.

**Data Sources:** AWS CloudTrail management events, queried with Athena over the standard `cloudtrail_logs` table. The same logic ports to CloudTrail Lake or Security Lake (OCSF) by mapping `useridentity.accesskeyid`, `sourceipaddress`, and `eventtime` to their equivalents.

**Query:**

```sql
SELECT
    useridentity.accesskeyid AS access_key,
    useridentity.arn         AS principal,
    COUNT_IF(regexp_like(sourceipaddress,
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))     AS internal_calls,
    COUNT_IF(NOT regexp_like(sourceipaddress,
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))     AS external_calls,
    array_distinct(filter(array_agg(sourceipaddress),
        ip -> NOT regexp_like(ip,'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'))) AS external_sources,
    min(eventtime) AS first_seen,
    max(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE useridentity.type = 'IAMUser'
  AND useridentity.accesskeyid LIKE 'AKIA%'
  AND eventtime >= to_iso8601(current_timestamp - interval '24' hour)
GROUP BY useridentity.accesskeyid, useridentity.arn
HAVING COUNT_IF(regexp_like(sourceipaddress,
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')) > 0
   AND COUNT_IF(NOT regexp_like(sourceipaddress,
        '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)')) > 0
ORDER BY external_calls DESC;
```

**What Triggers This:** A single long-term IAM access key (the `AKIA` prefix) making API calls from both an internal/known source range and an external address inside the same window. The key's own history is the baseline: the internal calls are the owner working normally, and the external calls are the same credential in someone else's hands. Concurrency is what makes it strong. Unlike one odd login, simultaneous use cannot be explained away as the owner travelling, because the owner is demonstrably still active internally.

**False Positives:** A workload that reaches some APIs over a VPC endpoint (private source) and others over an internet path (public source) can split across the internal/external boundary. CI/CD that legitimately drives a key from an external runner while a developer uses the same key internally will also match; the real problem there is the shared key, not an intrusion. A corporate VPN moving between split-tunnel and full-tunnel can change the observed source. Distinguish by whether the external sources resolve to known org egress, VPC endpoint, or CI provider ranges.

**Tuning Notes:** Replace the RFC1918 regex with your organisation's known-good source CIDRs, corporate egress, VPC endpoint ranges, and CI/CD provider ranges, maintained as an allowlist rather than hard-coded. Add a partition predicate (for example a `date` or `region` partition column) to bound the Athena scan and control cost. Widen the window for low-and-slow keys that operate over days. Exclude service-linked and automation roles whose source legitimately varies, and consider restricting to keys older than a few hours so freshly rotated keys mid-propagation do not flag.

**Validation:** From an out-of-band host on a different public IP, run a single benign permitted call such as `aws sts get-caller-identity` using a test key that is also exercised internally in the same window. Confirm the key surfaces with both `internal_calls` and `external_calls` greater than zero and the external IP listed in `external_sources`.

**Learn More:** [AWS Incident Detection and Response: Detecting Credential Compromise](https://ridgelinecyber.com/training/courses/aws-detection-and-response/) covers the per-principal source baseline and the cloud form of impossible travel in depth.
