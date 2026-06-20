# LOLBin Cluster — Multiple Signed Binaries from cmd.exe

Detects two or more distinct living-off-the-land binaries spawned from the same `cmd.exe` in a short span. Any one signed Windows binary running is unremarkable; a cluster of distinct ones under an interactive shell is the texture of an operator working a host by hand.

## ATT&CK

- **Technique:** T1218 — System Binary Proxy Execution
- **Tactic:** Defense Evasion, Execution

## Severity

**High.** The fidelity comes from breadth: a single LOLBin is common, but several distinct ones from one shell session indicate hands-on-keyboard activity rather than a routine script.

## Data Sources

- Sysmon Event ID 1 — `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Requires: parent process and command-line logging

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    (process_name="rundll32.exe" OR process_name="wmic.exe" OR process_name="schtasks.exe"
     OR process_name="regsvr32.exe" OR process_name="mshta.exe" OR process_name="certutil.exe"
     OR process_name="vssadmin.exe" OR process_name="wbadmin.exe" OR process_name="bcdedit.exe"
     OR process_name="bitsadmin.exe")
    parent_process_name="cmd.exe"
| stats dc(process_name) AS distinct_lolbins, values(process_name) AS lolbins,
        values(CommandLine) AS command_lines, min(_time) AS first_seen by host, user
| where distinct_lolbins >= 2
| sort - distinct_lolbins
```

## What Triggers This

A cluster of distinct LOLBins under one shell:

- Two or more distinct signed binaries from the list, all parented by `cmd.exe`
- On a single host in a short span, indicating interactive work
- Destructive binaries (vssadmin, wbadmin, bcdedit) in the mix, which shift intent toward impact

## False Positives

1. **Administrative scripts.** Maintenance and imaging scripts chain several of these legitimately. Allowlist by command-line pattern or signed parent.
2. **Installers.** Software installers invoke multiple LOLBins. Confirm against a maintenance window.
3. **Imaging tooling.** Build and provisioning runs use these binaries. Exclude known tooling.

## Tuning Notes

- **Allowlist known scripts.** Exclude administrative and imaging scripts by command-line pattern or signed parent.
- **Raise the floor where needed.** In estates with heavy scripted administration, increase `distinct_lolbins`.
- **Weight destructive binaries.** Their presence shifts the finding toward impact and warrants higher severity.

## Validation

1. On a test host, run two or more of the listed binaries from a single `cmd.exe` session.
2. Confirm the host surfaces with `distinct_lolbins >= 2`.

## Learn More

- [Splunk Detection and Incident Response — Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — LOLBin clustering and breadth-based fidelity
- [Detection Engineering — Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/) — clustering signals into a single detection
