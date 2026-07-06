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
title: DNS Exfiltration — High-Entropy Subdomain Queries
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

## Tuning Notes

- Supplement with volumetric rule: >100 unique subdomain queries to same parent domain in 10 minutes
- Network-level DNS logs (Zeek, DNS server) provide better coverage than endpoint-level (Sysmon Event ID 22)

## Learn More

- [Network Detection and Forensics](https://ridgelinecyber.com/training/courses/network-detection-forensics/). DNS analysis and tunneling detection
- [Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/). statistical detection for protocol abuse
