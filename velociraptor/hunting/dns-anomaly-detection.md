# DNS Anomaly Fleet Hunt

Hunts for DNS-based C2 and data exfiltration by analyzing the DNS client cache and ETW DNS query logs for anomalous patterns: high-entropy subdomain queries (DNS tunneling), queries to recently registered domains, unusually long domain names, and high query volumes to single domains.

## ATT&CK Coverage

- T1071.004 — Application Layer Protocol: DNS
- T1048.003 — Exfiltration Over Alternative Protocol (DNS tunneling)
- T1568.002 — Dynamic Resolution: Domain Generation Algorithms

## Artifact

```yaml
name: Custom.Windows.Hunting.DNSAnomalies
description: |
  Hunt for DNS-based C2 and exfiltration by analyzing DNS cache
  and query logs for tunneling indicators, DGA domains, and
  high-volume query patterns.

type: CLIENT

parameters:
  - name: MinSubdomainLength
    description: Flag subdomains longer than this (DNS tunneling indicator)
    type: int
    default: 40
  - name: MinDomainEntropy
    description: Minimum Shannon entropy to flag (DGA indicator, 0-4.5)
    default: "3.5"

sources:
  - name: DNSCache
    description: Current DNS client cache entries
    query: |
      SELECT Name, Type, TTL, DataLength, Data, Section
      FROM Artifact.Windows.System.DNSCache()

  - name: LongSubdomains
    description: DNS queries with unusually long subdomains (tunneling indicator)
    query: |
      SELECT Name, Type, Data,
             len(list=split(string=Name, sep=".")[0]) AS SubdomainLength,
             "Long Subdomain" AS Indicator
      FROM Artifact.Windows.System.DNSCache()
      WHERE len(list=split(string=Name, sep=".")[0]) > MinSubdomainLength

  - name: HighEntropyDomains
    description: Domains with high character entropy (DGA indicator)
    query: |
      LET Entries = SELECT Name, Type, Data FROM Artifact.Windows.System.DNSCache()

      SELECT Name, Type, Data,
             entropy(string=split(string=Name, sep=".")[0]) AS Entropy,
             "High Entropy" AS Indicator
      FROM Entries
      WHERE entropy(string=split(string=Name, sep=".")[0]) > atof(string=MinDomainEntropy)
        AND NOT Name =~ "(?i)\\.(microsoft|windows|office|azure|cloudflare|akamai|amazonaws|google)\\."

  - name: TXTRecordQueries
    description: TXT record queries (common DNS tunneling channel)
    query: |
      SELECT Name, Type, Data,
             "TXT Query" AS Indicator
      FROM Artifact.Windows.System.DNSCache()
      WHERE Type = "TXT"
        AND NOT Name =~ "(?i)(_dmarc|_spf|_domainkey|_mta-sts)"

  - name: SuspiciousTLDs
    description: Queries to commonly abused TLDs
    query: |
      SELECT Name, Type, Data,
             "Suspicious TLD" AS Indicator
      FROM Artifact.Windows.System.DNSCache()
      WHERE Name =~ "\\.(top|xyz|tk|ml|ga|cf|gq|buzz|club|wang|loan|racing|win|bid|stream|download)$"
```

## Hunting Logic

DNS tunneling leaves a distinct statistical fingerprint:
- Subdomains are long (encoding data in the query itself)
- Character distribution has high entropy (Base32/Base64 encoded data)
- Query volume to a single domain is high
- TXT record queries carry the response payload

## Learn More

- [Threat Hunting — DNS-Based Hunting](https://training.ridgelinecyber.com/courses/threat-hunting/) — DNS anomaly detection and tunneling identification
- [Network Detection and Forensics](https://training.ridgelinecyber.com/courses/network-detection-forensics/) — DNS traffic analysis
- [Detection Engineering — Network Detection Rules](https://training.ridgelinecyber.com/courses/detection-engineering/)
