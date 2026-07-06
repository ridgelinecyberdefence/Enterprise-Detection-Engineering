# Threat-Intel Match: Outbound Connection to a Known Indicator

Detects any outbound connection whose destination matches a current threat-intelligence indicator. A confirmed connection from an internal host to a known-bad destination is one of the few near-zero-false-positive detections available, provided the intelligence is current and curated.

## ATT&CK

- **Technique:** T1071, Application Layer Protocol
- **Tactic:** Command and Control

## Severity

**High.** The match carries its own context (category, confidence, associated incident), so the analyst starts with attribution rather than a bare IP. High-confidence matches are treated as active C2.

## Data Sources

- Sysmon Event ID 3 (or CIM Network_Traffic / Web). `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Requires: a maintained `threatintel` indicator lookup with confidence and expiry fields

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| lookup threatintel indicator AS dest_ip OUTPUT threat_category, confidence, associated_incident
| where isnotnull(threat_category)
| stats count, values(process_name) AS processes, min(_time) AS first_seen, max(_time) AS last_seen
    by host, dest_ip, threat_category, confidence, associated_incident
| sort - count
```

## What Triggers This

An outbound connection to a flagged destination:

- A destination matching a current threat-intelligence indicator
- Match context attached: category, confidence, and any associated incident
- The connecting process and host, for immediate triage

## False Positives

1. **Stale intelligence.** Aged indicators on recycled IPs produce false matches. Filter on confidence and an expiry so old indicators drop out.
2. **Shared infrastructure.** CDNs and shared hosting can carry a flagged IP alongside benign services. Prefer domain and URL indicators over bare IPs.
3. **Low-quality feeds.** Unvetted feeds generate noise. Curate sources.

## Tuning Notes

- **Curate the lookup ruthlessly.** The `threatintel` lookup is the actual control; the query is only as good as it. Maintain confidence and expiry.
- **Prefer richer indicators.** Use domain and URL indicators over bare IPs where the data source supports them.
- **Route by confidence.** Send high-confidence matches straight to alert and lower-confidence ones to a hunt queue.

## Validation

1. Add a benign test IP to the `threatintel` lookup and connect to it from a test host.
2. Confirm the detection fires, then remove the test indicator.

## Learn More

- [Splunk Detection and Incident Response: Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). indicator enrichment and feed curation
- [Detection Engineering: Network Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). operationalising threat intelligence in detections
