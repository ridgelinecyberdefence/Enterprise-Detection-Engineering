# DNS Tunneling Detection

Suricata rules detecting DNS-based C2 and data exfiltration by identifying high-frequency DNS queries, unusually long subdomain labels, TXT record abuse, and queries to known DNS tunneling tool domains.

## ATT&CK

- **Technique:** T1071.004 — Application Layer Protocol: DNS
- **Tactic:** Command and Control, Exfiltration

## Severity

**High.** DNS tunneling bypasses most web proxies and firewalls. Detection at the network layer is often the only opportunity to catch it.

## Rules

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

## Learn More

- [Network Detection and Forensics — DNS Traffic Analysis](https://training.ridgelinecyber.com/courses/network-detection-forensics/) — DNS protocol analysis and tunneling detection
- [Threat Hunting — DNS-Based Hunting](https://training.ridgelinecyber.com/courses/threat-hunting/) — statistical DNS anomaly detection
