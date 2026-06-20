# Web Upload Exfiltration: Large Outbound POST to One Destination

Detects large outbound data transfers through the web proxy: high upload volume to a single destination, or repeated octet-stream POSTs. After staging, data leaves over HTTP to file-sharing services or attacker infrastructure, and the upload volume is the signal.

## ATT&CK

- **Technique:** T1048. Exfiltration Over Alternative Protocol, T1567, Exfiltration Over Web Service
- **Tactic:** Exfiltration

## Severity

**High.** Sustained large uploads to one destination, especially as octet-stream POSTs, are the exfiltration leg visible at the proxy. A statistical outlier on outbound bytes is high-fidelity.

## Data Sources

- Web proxy access logs, `sourcetype="squid:access"`
- Requires: proxy logging with `bytes_out`, `http_method`, and `http_content_type`

## Query

```spl
sourcetype="squid:access"
| stats sum(bytes_out) AS out_bytes, count, dc(url) AS urls,
        values(http_method) AS methods, values(http_content_type) AS ctypes by src, dest_ip
| eventstats avg(out_bytes) AS avg_out, stdev(out_bytes) AS sd_out
| eval z = round((out_bytes - avg_out) / sd_out, 1)
| where z > 5 OR (out_bytes > 104857600 AND urls <= 5)
| sort - out_bytes
```

## What Triggers This

A source pushing data out to one destination:

- Outbound bytes more than five standard deviations above the population
- Large volume (over 100 MB here) concentrated on few URLs
- Repeated `POST` with `application/octet-stream`, the raw-upload content type

## False Positives

1. **Cloud backup and sync.** Backup and file-sync clients upload large volumes by design. Allowlist their destinations.
2. **Software and log shipping.** Telemetry and log uploads egress steadily. Confirm the destination is a known service.
3. **Legitimate file sharing.** Sanctioned file-transfer services. Exclude approved destinations.

## Tuning Notes

- **Allowlist sanctioned destinations.** Exclude backup, sync, and approved sharing endpoints so only unexpected uploads surface.
- **Combine volume and shape.** Outbound volume plus low URL diversity plus octet-stream is stronger than volume alone.
- **Baseline per source.** Where upload profiles vary widely, baseline per source rather than across the whole population.

## Validation

1. From a test host, upload a large file via POST to a lab endpoint.
2. Confirm the source-destination pair surfaces above the volume threshold or `z > 5`.

## Learn More

- [Splunk Detection and Incident Response: Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). web-upload exfiltration and outbound-volume outliers
- [Detection Engineering: Network Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). egress-volume detection design
