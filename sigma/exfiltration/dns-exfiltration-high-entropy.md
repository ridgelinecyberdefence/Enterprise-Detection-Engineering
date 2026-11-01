# DNS Exfiltration: High-Entropy Subdomain Queries

Detects DNS-based data exfiltration by identifying queries with unusually long, high-entropy subdomains encoding stolen data.

## ATT&CK

- **Technique:** T1048.003. Exfiltration Over Alternative Protocol, T1071.004, Application Layer Protocol: DNS
- **Tactic:** Exfiltration, Command and Control

## Severity

**Medium.** DNS exfiltration is slow but nearly impossible to block without breaking DNS. The statistical profile of encoded subdomains is distinguishable from legitimate DNS.

## Data Sources

- DNS query logs: Sysmon Event ID 22, Zeek dns.log, Windows DNS analytical log

## Query: Sigma

```yaml
title: DNS Exfiltration, High-Entropy Subdomain Queries
id: rc-sigma-023
status: production
description: |
  Detects DNS queries with long subdomain labels containing
  high-entropy data characteristic of encoded exfiltration.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.exfiltration
  - attack.t1048.003
  - attack.command_and_control
  - attack.t1071.004
logsource:
  category: dns
  product: windows
detection:
  selection_long:
    query|re: '^[a-zA-Z0-9+/=-]{30,}\.'
  selection_tools:
    query|contains|any:
      - 'dnscat'
      - '.onion.'
  selection_txt:
    QueryType: 'TXT'
    query|re: '^[a-zA-Z0-9]{20,}\.'
  condition: selection_long or selection_tools or selection_txt
falsepositives:
  - CDN hostnames with long generated subdomains
  - DKIM and SPF DNS records
level: medium
```

## What Triggers This

Data leaving inside DNS queries, from Windows DNS client telemetry. The rule matches long query labels, queries naming known tunnelling tools including `dnscat`, and TXT record queries, which carry more payload per response than any other type.

Encoding data into a subdomain and reading the answer back is a route out of almost every network, because DNS is permitted where nothing else is.

## False Positives

1. **Endpoint security agents.** Reputation and hash lookups encode data into subdomains as their normal function, and they are the largest producer of long-label queries on any managed estate.
2. **Cloud service hostnames,** particularly storage endpoints with generated names, which legitimately exceed any reasonable length threshold.
3. **Email authentication.** DKIM, DMARC and SPF lookups are TXT queries, so any mail flow trips the TXT selection.
4. **The tool-name selection catches only defaults.** `dnscat` in a query means an operator who changed nothing, and `.onion.` resolution attempts are usually a curious user rather than exfiltration.
5. **Content delivery and analytics** encode identifiers into hostnames routinely.

## Tuning Notes

- Supplement with volumetric rule: >100 unique subdomain queries to same parent domain in 10 minutes
- Network-level DNS logs (Zeek, DNS server) provide better coverage than endpoint-level (Sysmon Event ID 22)

## Tuning Notes

- **Exclude the security agent and the mail path first.** Those two removals take most of the volume and neither weakens the rule, because exfiltration does not originate from them.
- **Entropy discriminates better than length.** A long CDN hostname and an encoded payload are the same length and look nothing alike statistically. If your platform can score label entropy or character distribution, that is where the detection should live.
- **Volume per parent domain is the strongest single signal.** Tunnelling generates many unique subdomains under one registered domain, which almost nothing legitimate does at the same rate. Aggregating by registered domain rather than alerting per query changes this rule's usefulness substantially.
- **Review or drop the tool-name list.** It costs nothing and proves nothing when quiet, so keep it if you like, but do not count it toward coverage.
- **Conversion:** `sigma convert -t splunk -p windows sigma/exfiltration/dns-exfiltration-high-entropy.yml`

## Learn More

- [Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/). statistical detection for protocol abuse
