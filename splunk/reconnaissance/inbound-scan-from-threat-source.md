# Inbound Scan from a Threat Source: Perimeter Probing

Detects a burst of firewall-denied inbound connections from a single source, separating known-bad scanners (threat-intel match) from unattributed ones. Perimeter scanning is the reconnaissance that precedes exploitation, and a source generating many denies against varied ports and hosts is mapping the attack surface.

## ATT&CK

- **Technique:** T1595, Active Scanning
- **Tactic:** Reconnaissance

## Severity

**Low.** Internet background scanning is constant, so this is Low by default and best used to enrich and prioritise rather than to page. It rises when the source matches threat intelligence or when denies turn into an accepted connection.

## Data Sources

- Firewall traffic logs, `sourcetype="pan:traffic"`
- Requires: deny logging with source, destination, and port; a `threatintel` lookup

## Query

```spl
sourcetype="pan:traffic" action="deny"
| lookup threatintel indicator AS src_ip OUTPUT threat_category
| stats count AS denies, dc(dest_port) AS ports_probed, dc(dest_ip) AS hosts_probed,
        values(threat_category) AS threat by src_ip
| eval attribution = if(isnotnull(threat_category), "known-bad", "unattributed")
| where denies >= 50 AND (ports_probed >= 10 OR attribution="known-bad")
| sort - denies
```

## What Triggers This

A source probing the perimeter:

- Fifty or more denied inbound attempts from one source
- Many distinct ports or hosts probed, the breadth of a scan
- A threat-intel match, which promotes an otherwise routine scanner

## False Positives

1. **Internet background noise.** Constant opportunistic scanning. This is expected; use the detection to enrich, not to page, unless attributed.
2. **Security scanners.** Authorized external assessment. Allowlist the assessment source during engagements.
3. **Misconfigured partners.** A partner system retrying to a wrong port. Confirm and exclude.

## Tuning Notes

- **Use it to prioritise.** Feed attribution into risk scoring rather than alerting on every scanner.
- **Watch deny-to-accept.** The high-value pivot is a scanning source that later gets an accepted connection; correlate for that.
- **Allowlist assessments.** Exclude authorized external testing sources during their windows.

## Validation

1. From a test source, generate denied connection attempts across many ports to the perimeter.
2. Confirm the source surfaces with `denies >= 50` and the ports counted.

## Learn More

- [Splunk Detection and Incident Response: Network, Web, and DNS Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). perimeter-scan detection and attribution
- [Detection Engineering: Network Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). turning scan noise into prioritised signal
