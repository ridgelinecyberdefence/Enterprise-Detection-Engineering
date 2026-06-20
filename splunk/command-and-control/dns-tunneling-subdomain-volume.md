# DNS Tunnelling — High Subdomain Volume per Parent Domain

Detects a source generating an unusually high number of distinct subdomains under one parent domain, the signature of data or commands smuggled through DNS queries. Tunnelling encodes payload into the query name, so a single client producing hundreds of unique long subdomains under one domain is exfiltration or C2 over DNS.

## ATT&CK

- **Technique:** T1071.004 — Application Layer Protocol: DNS
- **Tactic:** Command and Control

## Severity

**High.** DNS tunnelling slips past controls that ignore DNS and provides a covert bidirectional channel. High distinct-name volume under one parent from one source is a strong indicator.

## Data Sources

- DNS query logs — `sourcetype="stream:dns"`
- Requires: query-name logging; a `threatintel` lookup for parent-domain promotion

## Query

```spl
sourcetype="stream:dns"
| rex field=query "(?<parent>[^.]+\.[^.]+)$"
| eval qlen = len(query)
| stats count, dc(query) AS distinct_names, avg(qlen) AS avg_len, max(qlen) AS max_len by src, parent
| where distinct_names > 50 AND avg_len > 30
| lookup threatintel indicator AS parent OUTPUT threat_category
| sort - distinct_names
```

## What Triggers This

A source smuggling data through query names:

- More than fifty distinct subdomains under a single parent domain from one source
- Long average query length, consistent with encoded payload
- A threat-intel hit on the parent domain, which confirms it

## False Positives

1. **CDNs and analytics.** Content delivery and telemetry generate many distinct subdomains legitimately. Allowlist known high-cardinality parents.
2. **Anti-spam and reputation lookups.** Some security tools query many encoded subdomains. Exclude known tools.
3. **Cloud service endpoints.** Large providers use many subdomains. Confirm the parent is not a sanctioned service.

## Tuning Notes

- **Allowlist high-cardinality parents.** Exclude CDNs, analytics, and provider domains, the dominant false positives.
- **Tune length and count together.** Long names plus high distinct-name volume is far stronger than either alone.
- **Add entropy.** Where available, score query-name entropy to separate encoded payload from human-readable subdomains.

## Validation

1. From a test host, run a benign tunnelling tool against a lab domain you control.
2. Confirm the source and parent surface with `distinct_names > 50` and elevated `avg_len`.

## Learn More

- [Splunk Detection and Incident Response — Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — DNS tunnelling detection by subdomain volume and length
- [Detection Engineering — Network Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — covert-channel detection design
