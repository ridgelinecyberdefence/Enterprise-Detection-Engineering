# Outbound Connection to a Threat-Intel Indicator

**ATT&CK:** T1071 Application Layer Protocol. Tactic: Command and Control.

**Severity:** High. A confirmed connection from an internal host to a known-bad destination is one of the few near-zero-false-positive detections available, provided the intelligence is current and curated.

**Data Sources:** Sysmon Event ID 3 (or CIM Network_Traffic / Web), enriched with a maintained `threatintel` indicator lookup.

**Query:**

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| lookup threatintel indicator AS dest_ip OUTPUT threat_category, confidence, associated_incident
| where isnotnull(threat_category)
| stats count, values(process_name) AS processes, min(_time) AS first_seen, max(_time) AS last_seen
    by host, dest_ip, threat_category, confidence, associated_incident
| sort - count
```

**What Triggers This:** Any outbound connection whose destination matches a current threat-intelligence indicator. The match carries its own context (category, confidence, associated incident), so the analyst starts with attribution rather than a bare IP.

**False Positives:** Stale or low-quality intelligence is the only meaningful source of error: shared hosting, CDNs, and recycled IPs produce false matches when the feed is not curated. Distinguish by indicator confidence and recency.

**Tuning Notes:** Curate the `threatintel` lookup ruthlessly; filter on `confidence` and an expiry so aged indicators drop out, and prefer domain and URL indicators over bare IPs where the data source supports them. Maintain the feed as the actual control, since the query is only as good as it. Route high-confidence matches straight to alert and lower-confidence ones to a hunt queue.

**Validation:** Add a benign test IP to the `threatintel` lookup, connect to it from a test host, confirm the detection fires, then remove the test indicator.

**Learn More:** [Splunk Detection and Incident Response: Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers indicator enrichment and feed curation.
