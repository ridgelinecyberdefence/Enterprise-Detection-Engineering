# C2 over DNS — Encoded Subdomain Queries

Detects DNS-based command and control by identifying processes making DNS queries with high-entropy subdomain labels characteristic of DNS tunneling tools (iodine, dnscat2, DNSTT, Cobalt Strike DNS beacon). The encoded data in the subdomain distinguishes C2 traffic from legitimate DNS resolution.

## ATT&CK

- **Technique:** T1071.004 — Application Layer Protocol: DNS
- **Tactic:** Command and Control

## Severity

**High.** DNS tunneling is a deliberate evasion technique that bypasses most web proxies and firewalls. Any confirmed DNS C2 channel indicates an active compromise with a sophisticated adversary.

## Data Sources

- Sysmon Event ID 22 (DNSEvent)
- Windows DNS Client ETW logs
- DNS server query logs

## Detection

```yaml
title: DNS C2 — High-Entropy Subdomain Queries from Non-Browser Process
id: 8c7e3a41-bf29-4d82-a5f1-c3e9d7812fab
status: experimental
description: >
  Detects DNS queries with high-entropy subdomain labels from non-browser
  processes, indicating DNS tunneling for C2 communication.
references:
  - https://attack.mitre.org/techniques/T1071/004/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.command_and_control
  - attack.t1071.004
logsource:
  category: dns_query
  product: windows
detection:
  selection:
    EventID: 22
  filter_browsers:
    Image|endswith:
      - '\chrome.exe'
      - '\msedge.exe'
      - '\firefox.exe'
      - '\brave.exe'
      - '\iexplore.exe'
  filter_system:
    Image|endswith:
      - '\svchost.exe'
      - '\OneDrive.exe'
      - '\Teams.exe'
  filter_domains:
    QueryName|contains:
      - 'microsoft.com'
      - 'windows.com'
      - 'office.com'
      - 'azure.com'
      - 'google.com'
      - 'cloudflare.com'
      - 'amazonaws.com'
      - 'akamai.com'
  condition: selection and not filter_browsers and not filter_system and not filter_domains
  # Post-processing note: filter results where the first subdomain label
  # exceeds 30 characters or contains Base32/Base64 character patterns.
  # Most SIEM platforms support regex post-filtering on QueryName.
falsepositives:
  - CDN and cloud services with long subdomain labels
  - DKIM and SPF validation queries with encoded selectors
  - Certificate validation (OCSP) queries
level: high
```

## What Triggers This

A non-browser process resolves DNS names where the subdomain label is unusually long (30+ characters) or contains character patterns consistent with Base32/Base64 encoding. DNS tunneling encodes C2 commands and responses in subdomain labels and TXT records, producing queries like:

```
aGVsbG8gd29ybGQ.tunnel.attacker-domain.com
```

## False Positives

1. **DKIM selectors.** Email authentication queries contain long encoded selectors. Filter by `_domainkey` in the query name.
2. **OCSP and CRL.** Certificate validation queries can have long subdomains. Filter by known OCSP responder domains.
3. **CDN routing.** Some CDNs use long hashed subdomains for routing. Exclude known CDN base domains.

## Tuning Notes

- The Sigma rule captures the process-level signal. Post-filter in your SIEM for subdomain length > 30 characters using regex on `QueryName`
- Combine with query volume: legitimate long subdomains are one-off lookups, DNS tunneling produces dozens per minute
- Exclude `_dmarc`, `_spf`, `_domainkey`, `_mta-sts` prefixes

## Learn More

- [Threat Hunting — DNS-Based Hunting](https://ridgelinecyber.com/training/courses/threat-hunting-m365/) — DNS anomaly detection and tunneling identification
- [Network Detection and Forensics — DNS Analysis](https://ridgelinecyber.com/training/courses/network-detection-forensics/) — DNS traffic analysis techniques
