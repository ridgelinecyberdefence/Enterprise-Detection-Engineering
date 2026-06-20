# WMIC Remote Node Execution

**ATT&CK:** T1047 Windows Management Instrumentation. Tactics: Lateral Movement, Execution.

**Severity:** High. `wmic /node:` invokes a process on a remote host over WMI. It is a standard lateral-movement primitive and is rare in modern administration, which mostly uses PowerShell remoting or management agents.

**Data Sources:** Sysmon Event ID 1, `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`.

**Query:**

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    process_name="wmic.exe" CommandLine="*/node:*"
| rex field=CommandLine "(?i)/node:\"?(?<remote_host>[^\s\"]+)"
| stats values(CommandLine) AS command_lines, values(remote_host) AS targets,
        dc(remote_host) AS distinct_targets, min(_time) AS first_seen by host, user
| sort - distinct_targets
```

**What Triggers This:** A `wmic` invocation with `/node:` targeting one or more remote hosts, especially when paired with `process call create`. One source fanning out to several distinct targets is the lateral-movement signature.

**False Positives:** A few legacy administration scripts and inventory tools still use WMIC remotely. Distinguish by whether the source is an administration jump host and whether the targets match a known maintenance scope.

**Tuning Notes:** Allowlist administration jump hosts and known inventory scripts by source host and command-line pattern. Weight `process call create` and fan-out to many distinct targets upward. Pair with a destination-side detection (remote process creation with a WMI parent) for two-sided confirmation.

**Validation:** From a test host, run `wmic /node:<test-target> process call create "cmd /c whoami"` against a lab machine; confirm the source surfaces with the target extracted.

**Learn More:** [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers WMI lateral movement and two-sided correlation.
