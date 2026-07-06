# Proxy Beaconing: Statistical Outlier on Hits per Destination

Detects a source-destination pair through the web proxy whose request count is a statistical outlier against the population. Rather than a fixed threshold, this scores every pair by how far its volume sits above the mean, surfacing the steady, high-count callbacks of C2 without hard-coding what normal looks like.

## ATT&CK

- **Technique:** T1071. Application Layer Protocol, T1571, Non-Standard Port
- **Tactic:** Command and Control

## Severity

**High.** A destination a single source hits far more than any peer, with few distinct URLs, is the beaconing shape. A threat-intel match promotes it to immediate.

## Data Sources

- Web proxy access logs, `sourcetype="squid:access"`
- Requires: proxy logging with bytes and URL fields; a `threatintel` lookup for promotion

## Query

```spl
sourcetype="squid:access"
| stats count, dc(url) AS distinct_urls, sum(bytes_out) AS bytes_out by src, dest_ip
| eventstats avg(count) AS avg_hits, stdev(count) AS sd_hits
| eval z = round((count - avg_hits) / sd_hits, 1)
| where z > 3 AND distinct_urls <= 5
| lookup threatintel indicator AS dest_ip OUTPUT threat_category
| sort - z
```

## What Triggers This

A destination one source hammers far more than its peers:

- A request count more than three standard deviations above the population mean
- A small number of distinct URLs, the repetitive single-callback path of an implant
- A threat-intel hit on the destination, which makes it conclusive

## False Positives

1. **Update and telemetry endpoints.** High-volume legitimate services score as outliers. Allowlist known service destinations.
2. **API integrations.** A single client hammering one API. Confirm the destination is a sanctioned integration.
3. **Sync and collaboration.** Constant polling to a SaaS endpoint. Exclude known SaaS.

## Tuning Notes

- **Triage on jitter and URL diversity.** Low URL diversity plus regular timing distinguishes C2 from a busy legitimate client; add an interval calculation for confirmation.
- **Allowlist service destinations.** Exclude update, telemetry, and SaaS endpoints, the main outliers.
- **Promote on intel.** A `threatintel` hit on the destination routes straight to alert.

## Validation

1. From a test host, generate a high, repetitive request volume to a single lab endpoint.
2. Confirm the pair surfaces with `z > 3` and low `distinct_urls`.

## Learn More

- [Splunk Detection and Incident Response: Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). statistical beaconing detection over proxy logs
- [Detection Engineering: Network Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). outlier-based detection design
