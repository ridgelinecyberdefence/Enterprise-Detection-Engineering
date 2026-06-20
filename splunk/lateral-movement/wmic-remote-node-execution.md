# WMIC Remote Execution: /node Process Creation

Detects a `wmic` invocation with `/node:` targeting one or more remote hosts. This is a standard lateral-movement primitive and is rare in modern administration, which mostly uses PowerShell remoting or management agents.

## ATT&CK

- **Technique:** T1047, Windows Management Instrumentation
- **Tactic:** Lateral Movement, Execution

## Severity

**High.** One source fanning out to several distinct targets over WMI is the lateral-movement signature, especially when paired with `process call create`.

## Data Sources

- Sysmon Event ID 1, `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Requires: command-line logging; a destination-side remote-process-creation detection enables two-sided confirmation

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    process_name="wmic.exe" CommandLine="*/node:*"
| rex field=CommandLine "(?i)/node:\"?(?<remote_host>[^\s\"]+)"
| stats values(CommandLine) AS command_lines, values(remote_host) AS targets,
        dc(remote_host) AS distinct_targets, min(_time) AS first_seen by host, user
| sort - distinct_targets
```

## What Triggers This

A WMIC invocation reaching across the network:

- `/node:` targeting one or more remote hosts
- `process call create` launching a process on the target
- One source fanning out to several distinct targets

## False Positives

1. **Legacy admin scripts.** A few maintenance scripts still use WMIC remotely. Allowlist the admin jump host and the command-line pattern.
2. **Inventory tooling.** Older inventory tools query remote nodes. Confirm the targets match a known scope.
3. **Vendor utilities.** Some products invoke remote WMI. Exclude by source and signature.

## Tuning Notes

- **Allowlist jump hosts.** Exclude administration jump hosts and known inventory scripts by source host and command pattern.
- **Weight the sharp cases.** Raise severity for `process call create` and fan-out to many distinct targets.
- **Pair with the destination.** Combine with a target-side remote-process-creation detection (WMI parent) for two-sided confirmation.

## Validation

1. From a test host, run `wmic /node:<test-target> process call create "cmd /c whoami"` against a lab machine.
2. Confirm the source surfaces with the target extracted into `targets`.

## Learn More

- [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). WMI lateral movement and two-sided correlation
- [Detection Engineering: Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/). lateral-movement primitive detection
