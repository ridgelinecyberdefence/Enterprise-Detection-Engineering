# Ingress Tool Transfer — Download Cradle via Script or LOLBin

Detects download cradles that pull a payload from the internet using PowerShell, certutil, or bitsadmin. After initial execution, the next move is to fetch the real tooling, and these built-in download primitives are the most common way attackers stage the second stage.

## ATT&CK

- **Technique:** T1105 — Ingress Tool Transfer
- **Tactic:** Command and Control

## Severity

**High.** A download cradle is the bridge between a lightweight initial foothold and full attacker tooling on the host. The signal is strong when the parent is an interpreter or Office app.

## Data Sources

- Sysmon Event ID 1 — `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Requires: command-line logging; a `threatintel` lookup for destination enrichment

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    ((process_name="powershell.exe" (CommandLine="*Invoke-WebRequest*" OR CommandLine="*DownloadString*"
        OR CommandLine="*DownloadFile*" OR CommandLine="*Start-BitsTransfer*"))
     OR (process_name="certutil.exe" CommandLine="*-urlcache*")
     OR (process_name="bitsadmin.exe" CommandLine="*/transfer*"))
| rex field=CommandLine "(?i)https?://(?<download_host>[^/\s\"']+)"
| lookup threatintel indicator AS download_host OUTPUT threat_category
| stats values(CommandLine) AS command_lines, values(download_host) AS hosts,
        values(threat_category) AS threat, min(_time) AS first_seen by host, user, parent_process_name
| sort - first_seen
```

## What Triggers This

A built-in tool fetching a remote payload:

- PowerShell `Invoke-WebRequest`, `DownloadString`, `DownloadFile`, or BITS transfer
- `certutil -urlcache` or `bitsadmin /transfer`, the classic LOLBin download cradles
- An interpreter or Office parent, and a threat-intel hit on the download host

## False Positives

1. **Legitimate scripted downloads.** Admin and deployment scripts fetch files this way. Allowlist by parent, command pattern, or signed publisher.
2. **Software updaters.** Some updaters use BITS. Exclude known updater processes.
3. **certutil for certificates.** certutil has legitimate certificate uses; the `-urlcache` download form is the suspicious one. Scope to it.

## Tuning Notes

- **Scope certutil tightly.** Only the `-urlcache` download form is interesting; do not flag normal certificate operations.
- **Allowlist deployment scripts.** Exclude sanctioned download patterns by parent and signature.
- **Enrich the destination.** A `threatintel` hit on the download host promotes the event straight to alert.

## Validation

1. On a test host, run `certutil -urlcache -f http://<test-host>/file.txt out.txt` against a benign endpoint.
2. Confirm the host surfaces with the download host extracted.

## Learn More

- [Splunk Detection and Incident Response — Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — download-cradle detection and destination enrichment
- [Detection Engineering — Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/) — staging and tool-transfer detection
