# Regular-Interval Network Beaconing

**ATT&CK:** T1071 Application Layer Protocol; T1571 Non-Standard Port. Tactic: Command and Control.

**Severity:** High. C2 implants call home on a near-fixed cadence. A host making many outbound connections to one destination at a consistent interval, especially from an unusual process such as `rundll32.exe`, is the beaconing signature.

**Data Sources:** Sysmon Event ID 3 (network connection), `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`. Also expressible over the CIM Network_Traffic data model.

**Query:**

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 earliest=-24h
| eval ep=_time
| stats count AS beacons, min(ep) AS first_ep, max(ep) AS last_ep,
        values(process_name) AS processes by host, dest_ip
| where beacons >= 20
| eval window_min = round((last_ep - first_ep)/60, 1)
| eval avg_interval_s = round((last_ep - first_ep)/(beacons-1), 0)
| eval beacons_per_hour = round(beacons / (window_min/60), 1)
| where avg_interval_s > 0 AND window_min >= 30
| sort - beacons
```

**What Triggers This:** A host-to-destination pair with many connections over a sustained window at a steady average interval. Triage the `avg_interval_s` and the connecting process: a regular cadence from `rundll32.exe`, `regsvr32.exe`, or another process that has no business making sustained outbound connections is the strong case.

**False Positives:** Software update checks, telemetry agents, certificate and CRL fetches, and chat or sync clients all beacon legitimately on a cadence. Distinguish by the destination reputation, the process, and whether the destination is a known service endpoint.

**Tuning Notes:** This is a triage surface, not a fire-and-forget alert. Compute jitter (the standard deviation of inter-arrival gaps) to separate machine-regular C2 from human traffic, allowlist known update and telemetry destinations, and weight unusual connecting processes upward. Enrich `dest_ip` against threat intelligence to promote known-bad destinations straight to alert.

**Validation:** From a test host, run a benign script that connects to a lab endpoint every 60 seconds for an hour; confirm the pair surfaces with `avg_interval_s` near 60.

**Learn More:** [Splunk Detection and Incident Response: Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers beacon-cadence analysis and jitter.
