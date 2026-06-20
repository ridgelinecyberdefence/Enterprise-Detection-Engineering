# Shadow Copy Deletion and Recovery Inhibition

**ATT&CK:** T1490 Inhibit System Recovery. Tactic: Impact.

**Severity:** Critical. Deleting volume shadow copies and disabling recovery is the immediate pre-encryption step of nearly every ransomware operation. Detecting it buys the only window in which recovery options can still be protected.

**Data Sources:** Sysmon Event ID 1, `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`.

**Query:**

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    ((process_name="vssadmin.exe" CommandLine="*delete*shadows*")
     OR (process_name="wmic.exe" CommandLine="*shadowcopy*delete*")
     OR (process_name="bcdedit.exe" (CommandLine="*recoveryenabled*no*" OR CommandLine="*bootstatuspolicy*ignoreallfailures*"))
     OR (process_name="wbadmin.exe" CommandLine="*delete*"))
| stats values(process_name) AS tools, values(CommandLine) AS command_lines, min(_time) AS first_seen by host, user
| sort - first_seen
```

**What Triggers This:** Any of the standard recovery-destruction commands: `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit` disabling recovery, or `wbadmin delete`. These have essentially no benign interactive use on endpoints and should be treated as an active incident.

**False Positives:** A narrow set of backup and imaging products manage shadow copies legitimately. Distinguish by whether the actor is a sanctioned backup process and whether the host is in a maintenance window.

**Tuning Notes:** Allowlist sanctioned backup and imaging software by signed publisher only; keep the command patterns themselves un-suppressed. This is a high-priority, low-volume detection, so route it straight to alert and pair it with host isolation in your response automation.

**Validation:** On an isolated test host, run `vssadmin delete shadows /for=C: /quiet` against a disposable system; confirm it surfaces immediately.

**Learn More:** [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers pre-encryption recovery inhibition as a ransomware tripwire.
