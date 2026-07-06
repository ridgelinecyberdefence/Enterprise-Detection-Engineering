# Threat-Intel Match: Proxy and DNS Destinations

Detects web-proxy or DNS traffic to a destination or parent domain that matches current threat intelligence. A confirmed connection to known-bad infrastructure at the network layer is near-zero-false-positive when the intelligence is curated, and it catches C2 that endpoint telemetry alone may miss.

## ATT&CK

- **Technique:** T1071, Application Layer Protocol
- **Tactic:** Command and Control

## Severity

**High.** A proxy or DNS hit on a curated indicator is direct evidence of contact with attacker infrastructure. High-confidence matches are treated as active C2.

## Data Sources

- Web proxy access logs (`sourcetype="squid:access"`) and DNS query logs (`sourcetype="stream:dns"`)
- Requires: a maintained `threatintel` lookup with category, confidence, and expiry

## Query

```spl
sourcetype="squid:access"
| lookup threatintel indicator AS dest_ip OUTPUT threat_category, confidence, associated_incident
| where isnotnull(threat_category)
| stats count AS hits, values(url) AS sample_urls, min(_time) AS first_seen, max(_time) AS last_seen
    by src, dest_ip, threat_category, associated_incident
| sort - hits
```

A parallel query catches DNS resolution of flagged parent domains, which fires even when the connection is later blocked:

```spl
sourcetype="stream:dns"
| rex field=query "(?<parent>[^.]+\.[^.]+)$"
| lookup threatintel indicator AS parent OUTPUT threat_category, associated_incident
| where isnotnull(threat_category)
| stats count AS lookups, dc(query) AS names by src, parent, threat_category, associated_incident
| sort - lookups
```

## What Triggers This

Network contact with flagged infrastructure:

- A proxy connection whose destination matches an indicator
- A DNS query for a flagged parent domain, even if the connection is later blocked
- The associated incident context attached for triage

## False Positives

1. **Stale intelligence.** Aged indicators on recycled addresses. Filter on confidence and expiry.
2. **Shared hosting and CDNs.** A flagged neighbour on shared infrastructure. Prefer domain and URL indicators over bare IPs.
3. **Sinkholes and research.** Security research traffic to flagged hosts. Exclude known research sources.

## Tuning Notes

- **Curate the lookup.** The control is the intelligence; maintain category, confidence, and expiry.
- **Run both layers.** DNS catches intent even when egress is blocked; proxy confirms connection. Keep both.
- **Route by confidence.** High-confidence matches to alert, lower-confidence to a hunt queue.

## Validation

1. Add a benign test IP and domain to the `threatintel` lookup and generate a proxy hit and a DNS query for them from a test host.
2. Confirm both queries fire, then remove the test indicators.

## Learn More

- [Splunk Detection and Incident Response: Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). network-layer indicator matching across proxy and DNS
- [Detection Engineering: Network Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). operationalising intelligence at the network layer
