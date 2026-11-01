# DNS Tunneling Detection

Suricata rules detecting DNS-based C2 and data exfiltration by identifying high-frequency DNS queries, unusually long subdomain labels, TXT record abuse, and queries to known DNS tunneling tool domains.

## ATT&CK

- **Technique:** T1071.004, Application Layer Protocol: DNS
- **Tactic:** Command and Control, Exfiltration

## Severity

**High.** DNS tunneling bypasses most web proxies and firewalls. Detection at the network layer is often the only opportunity to catch it.

## Data Sources

Suricata or Suricata-compatible IDS with the relevant protocol parsers enabled, positioned where it can see the traffic. These rules assume `$HOME_NET` and `$EXTERNAL_NET` are set correctly for your estate, which is the single most common reason a network rule appears to do nothing.

Rules matching on payload content need unencrypted traffic. Where TLS terminates upstream of the sensor, place it after termination or accept that only the metadata rules will fire.

## Query: Sigma
```
# DNS query with very long subdomain (tunneling indicator)
alert dns $HOME_NET any -> any any (
    msg:"RCY - DNS Query with Long Subdomain - Possible Tunneling";
    dns.query; pcre:"/^[a-zA-Z0-9\-]{40,}\./";
    threshold:type both, track by_src, count 5, seconds 60;
    classtype:trojan-activity;
    sid:2025010; rev:1;
    metadata:mitre_attack T1071.004, severity high, author Ridgeline_Cyber;
)

# High-frequency DNS TXT queries to same domain
alert dns $HOME_NET any -> any any (
    msg:"RCY - High-Frequency DNS TXT Queries - Possible DNS C2";
    dns.query; content:"|00 10|"; content:!".microsoft.com"; content:!".windows.com";
    content:!".office.com"; content:!"_dmarc"; content:!"_domainkey";
    threshold:type both, track by_src, count 20, seconds 120;
    classtype:trojan-activity;
    sid:2025011; rev:1;
    metadata:mitre_attack T1071.004, severity high, author Ridgeline_Cyber;
)

# DNS query for known tunneling tool domains
alert dns $HOME_NET any -> any any (
    msg:"RCY - DNS Query for Known Tunneling Tool Domain";
    dns.query; content:".dnscat2."; nocase;
    classtype:trojan-activity;
    sid:2025012; rev:1;
    metadata:mitre_attack T1071.004, severity critical, author Ridgeline_Cyber;
)

# Excessive DNS queries from single host (data exfil)
alert dns $HOME_NET any -> any any (
    msg:"RCY - Excessive DNS Query Volume from Single Host";
    threshold:type both, track by_src, count 500, seconds 300;
    classtype:trojan-activity;
    sid:2025013; rev:1;
    metadata:mitre_attack T1048.003, severity medium, author Ridgeline_Cyber;
)

# NULL or CNAME queries with encoded data
alert dns $HOME_NET any -> any any (
    msg:"RCY - DNS Query with Base32/Base64 Encoded Subdomain";
    dns.query; pcre:"/^[2-7A-Z]{16,}\./i";
    threshold:type both, track by_src, count 3, seconds 60;
    classtype:trojan-activity;
    sid:2025014; rev:1;
    metadata:mitre_attack T1071.004, severity high, author Ridgeline_Cyber;
)
```

## What Triggers This

Four separate signals, each with its own threshold. A DNS query whose first label runs to 40 or more characters, matched by `pcre`, thresholded at five per source per minute. High-frequency TXT queries, matched on the `00 10` query-type bytes, at twenty per source in two minutes. Queries for domains belonging to published tunnelling tools including `dnscat2`. And raw query volume from one host, at 500 in five minutes.

Long labels and TXT frequency are the behavioural signals; the tool-domain list is a name check that only catches an operator who left the default.

## False Positives

1. **Antivirus and reputation lookups.** Endpoint agents encode hashes and URLs into subdomains and query them constantly. This is the dominant producer of both the long-label and the volume rules, and on a large estate it will exceed 500 queries in five minutes from a single proxy or resolver.
2. **CDN and cloud service names.** AWS, Azure and CDN hostnames legitimately run past 40 characters, particularly S3 and storage endpoints with generated names.
3. **DNS-based service discovery.** Kubernetes and Consul generate high query volumes with long generated labels as normal operation.
4. **Email authentication.** DKIM and DMARC lookups are TXT queries by definition, so any mail gateway will trip the TXT frequency rule.
5. **A forwarding resolver in the path.** If the sensor sees traffic after a central resolver, every query appears to come from that one address and every by-source threshold becomes meaningless.

## Tuning Notes

- **Fix the sensor position before tuning the thresholds.** If queries reach the sensor from a forwarding resolver, `track by_src` collapses your whole estate into one host and the counts are worthless. These rules want visibility of client-to-resolver traffic.
- **Exclude your mail gateway from the TXT rule and your endpoint agent from the volume rule.** Those two exclusions remove most of the noise, and neither weakens the rule against tunnelling, which does not come from those hosts.
- **The thresholds are starting points and will need raising.** 500 queries in five minutes is low for a busy resolver and high for a workstation. Set it from a week of your own percentiles rather than from this file.
- **The tool-domain list needs review or removal.** `dnscat2` in a query name means an operator who changed nothing. Keep it for the cost, but do not count it as coverage.
- **Entropy beats length.** A 40-character label catches encoding but so does a long CDN name. If your platform can score label entropy, that discriminates far better than length alone.

## Learn More

- [Threat Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/)
- [Threat Hunting: DNS-Based Hunting](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). statistical DNS anomaly detection
