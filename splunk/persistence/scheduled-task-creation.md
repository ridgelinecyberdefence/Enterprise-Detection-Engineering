# Scheduled Task Creation for Persistence

**ATT&CK:** T1053.005 Scheduled Task/Job: Scheduled Task. Tactics: Persistence, Privilege Escalation, Execution.

**Severity:** Medium. Scheduled tasks are a durable, reboot-surviving foothold and a common SYSTEM-level execution path. The volume of legitimate task creation keeps this Medium until enriched, but the malicious cases are high impact.

**Data Sources:** Sysmon Event ID 1 (`schtasks.exe` with `/create`) or Windows Security Event ID 4698 (a scheduled task was created).

**Query:**

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    process_name="schtasks.exe" CommandLine="*/create*"
| stats values(CommandLine) AS command_lines, min(_time) AS first_seen by host, user, parent_process_name
| sort - first_seen
```

**What Triggers This:** Creation of a scheduled task from the command line. The interesting cases run an interpreter or a binary from a user-writable or temp path, run as SYSTEM, or are created by an unusual parent such as an Office app or a script host.

**False Positives:** Software installers, management agents, and update mechanisms create tasks routinely, so raw volume is high. Distinguish by the task action (what it runs and from where), the creating parent, and whether it runs with elevated rights.

**Tuning Notes:** Enrich with the task action path and flag tasks whose action lives in `\Users\`, `\ProgramData\`, `\Temp\`, or `\AppData\`, or that launch an interpreter. Allowlist installer and agent parents. Where Event ID 4698 is available it carries the task XML, which lets you alert on the action rather than just the create.

**Validation:** On a test host, create a benign task with `schtasks /create`; confirm it surfaces, then refine with the action-path enrichment.

**Learn More:** [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers scheduled-task persistence and enriching on the task action.
