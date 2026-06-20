# Scheduled Task Creation — Command-Line Persistence

Detects creation of a scheduled task from the command line. Scheduled tasks are a durable, reboot-surviving foothold and a common SYSTEM-level execution path; the malicious cases run an interpreter or a binary from a user-writable path, run as SYSTEM, or are created by an unusual parent.

## ATT&CK

- **Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task
- **Tactic:** Persistence, Privilege Escalation, Execution

## Severity

**Medium.** The volume of legitimate task creation keeps this Medium until enriched, but the malicious cases are high impact. Severity rises sharply when the task action lives in a temp or user path or launches an interpreter.

## Data Sources

- Sysmon Event ID 1 (`schtasks.exe` with `/create`) — `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`
- Requires: command-line logging; Windows Security Event ID 4698 carries the task XML where available

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    process_name="schtasks.exe" CommandLine="*/create*"
| stats values(CommandLine) AS command_lines, min(_time) AS first_seen by host, user, parent_process_name
| sort - first_seen
```

## What Triggers This

A scheduled task created from the command line:

- A task whose action runs from `\Users\`, `\ProgramData\`, `\Temp\`, or `\AppData\`
- A task that launches an interpreter such as PowerShell or cmd
- An unusual creating parent, such as an Office app or a script host

## False Positives

1. **Software installers.** Installers create tasks routinely. Allowlist installer parents by signed publisher.
2. **Management agents.** Monitoring and patch agents create maintenance tasks. Confirm the agent and host.
3. **Update mechanisms.** Updater frameworks schedule check tasks. Exclude known updaters.

## Tuning Notes

- **Enrich on the action.** Flag tasks whose action path is user-writable or that launch an interpreter; this is where the signal lives.
- **Allowlist by parent.** Exclude installer and agent parents rather than the whole event.
- **Prefer 4698 where present.** Event ID 4698 carries the task XML, letting you alert on the action rather than the create.

## Validation

1. On a test host, create a benign task with `schtasks /create`.
2. Confirm it surfaces, then refine with the action-path enrichment.

## Learn More

- [Splunk Detection and Incident Response — Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — scheduled-task persistence and enriching on the task action
- [Detection Engineering — Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/) — turning a noisy primitive into a tuned detection
