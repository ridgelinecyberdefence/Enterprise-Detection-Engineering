# Network Beaconing: Regular-Interval Callbacks

Detects a host making many outbound connections to one destination over a sustained window at a consistent interval. C2 implants call home on a near-fixed cadence, so a steady beat to a single destination, especially from an unusual process, is the beaconing signature.

## ATT&CK

- **Technique:** T1071. Application Layer Protocol, T1571, Non-Standard Port
- **Tactic:** Command and Control

## Severity

**High.** Regular-cadence callbacks from a process that has no business making sustained outbound connections, such as `rundll32.exe`, are a strong C2 indicator. A threat-intel match on the destination promotes it immediately.

## Data Sources

- Sysmon Event ID 3. `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`; also expressible over the CIM Network_Traffic data model
- Requires: outbound connection logging with process attribution

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-24h
| stats count AS beacons, min(_time) AS first_ep, max(_time) AS last_ep,
        values(process_name) AS processes by host, dest_ip
| where beacons >= 20
| eval window_min = round((last_ep - first_ep)/60, 1)
| eval avg_interval_s = round((last_ep - first_ep)/(beacons-1), 0)
| where avg_interval_s > 0 AND window_min >= 30
| sort - beacons
```

## What Triggers This

A host-to-destination pair calling home on a beat:

- Many connections to one destination over a sustained window
- A steady average interval, the cadence of an implant rather than a person
- An unusual connecting process such as `rundll32.exe` or `regsvr32.exe`

Triage the `avg_interval_s` and the connecting process to separate machine-regular C2 from human traffic.

## False Positives

1. **Update and telemetry agents.** Software update checks, telemetry, and CRL fetches beacon on a cadence. Allowlist known service destinations.
2. **Sync and chat clients.** These poll on intervals. Confirm the destination is a known service endpoint.
3. **Monitoring probes.** Health checks connect regularly. Exclude known probes.

## Tuning Notes

- **This is a triage surface.** Compute jitter (the standard deviation of inter-arrival gaps) to separate machine-regular C2 from human traffic.
- **Allowlist destinations.** Exclude known update and telemetry endpoints; weight unusual connecting processes upward.
- **Enrich on intel.** A `threatintel` match on `dest_ip` promotes the pair straight to alert.

## Validation

1. From a test host, run a benign script that connects to a lab endpoint every 60 seconds for an hour.
2. Confirm the pair surfaces with `avg_interval_s` near 60.

## Learn More

- [Splunk Detection and Incident Response: Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). beacon-cadence analysis and jitter
- [Detection Engineering: Network Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). interval and jitter detection design
