# Recovery Inhibition: Shadow Copy Deletion

Detects the standard recovery-destruction commands: `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit` disabling recovery, and `wbadmin delete`. Deleting volume shadow copies and disabling recovery is the immediate pre-encryption step of nearly every ransomware operation.

## ATT&CK

- **Technique:** T1490, Inhibit System Recovery
- **Tactic:** Impact

## Severity

**Critical.** These commands have essentially no benign interactive use on endpoints and should be treated as an active incident. Detecting them buys the only window in which recovery options can still be protected.

## Data Sources

- Sysmon Event ID 1, `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Requires: command-line logging

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    ((process_name="vssadmin.exe" CommandLine="*delete*shadows*")
     OR (process_name="wmic.exe" CommandLine="*shadowcopy*delete*")
     OR (process_name="bcdedit.exe" (CommandLine="*recoveryenabled*no*" OR CommandLine="*bootstatuspolicy*ignoreallfailures*"))
     OR (process_name="wbadmin.exe" CommandLine="*delete*"))
| stats values(process_name) AS tools, values(CommandLine) AS command_lines, min(_time) AS first_seen by host, user
| sort - first_seen
```

## What Triggers This

A command that destroys recovery options:

- `vssadmin delete shadows` or `wmic shadowcopy delete`
- `bcdedit` disabling recovery or ignoring boot failures
- `wbadmin delete` removing backups

## False Positives

1. **Backup and imaging products.** A narrow set manage shadow copies legitimately. Allowlist them by signed publisher only.
2. **Maintenance windows.** Sanctioned cleanup during imaging. Confirm the host is in a maintenance window.
3. **Disk tooling.** Some disk utilities touch shadow storage. Exclude by signature.

## Tuning Notes

- **Allowlist by publisher only.** Exclude sanctioned backup and imaging software by signature; keep the command patterns un-suppressed.
- **Low volume, high priority.** Route straight to alert.
- **Pair with isolation.** Wire this into response automation that isolates the host, since it precedes encryption by minutes.

## Validation

1. On an isolated test host, run `vssadmin delete shadows /for=C: /quiet` against a disposable system.
2. Confirm it surfaces immediately.

## Learn More

- [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). pre-encryption recovery inhibition as a ransomware tripwire
- [Detection Engineering: Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/). high-priority low-volume detection design
