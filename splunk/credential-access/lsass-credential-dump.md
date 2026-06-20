# LSASS Credential Dump: comsvcs MiniDump and Dump Files

Detects credential dumping from LSASS, the `rundll32 comsvcs.dll MiniDump` living-off-the-land path, procdump or tools targeting `lsass`, and `.dmp` files being written. Dumping LSASS yields plaintext and hashed credentials for everyone logged on, which is the pivot from one host to the domain.

## ATT&CK

- **Technique:** T1003.001. OS Credential Dumping: LSASS Memory
- **Tactic:** Credential Access

## Severity

**Critical.** A successful LSASS dump hands the attacker credentials for every active session, enabling immediate lateral movement and privilege escalation. The strongest case correlates the dumping command with a dropped `.dmp` on the same host.

## Data Sources

- Sysmon process creation and file create. `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` (Event ID 1 and 11)
- Requires: command-line logging and file-create events

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    ((EventCode=1 process_name="rundll32.exe" CommandLine="*comsvcs*" CommandLine="*MiniDump*")
     OR (EventCode=1 CommandLine="*lsass*" (CommandLine="*MiniDump*" OR CommandLine="*procdump*"))
     OR (EventCode=11 file_name="*.dmp"))
| stats values(EventCode) AS events, values(CommandLine) AS dump_command,
        values(file_name) AS dropped_file, min(_time) AS first_seen by host, user
| sort - first_seen
```

## What Triggers This

An attempt to capture LSASS memory:

- `rundll32 comsvcs.dll MiniDump` against the LSASS process ID
- procdump or another tool naming `lsass` with a dump verb
- A `.dmp` file written, strongest when correlated with the dumping command on the same host

## False Positives

1. **Crash-dump tooling.** Diagnostic and EDR self-tests write `.dmp` files. Keep the `.dmp` clause correlated rather than standalone, and allowlist sanctioned tools by signed publisher.
2. **Legitimate diagnostics.** Rare admin troubleshooting may dump process memory. Distinguish by whether `lsass` is the target.
3. **EDR memory scans.** Some agents touch LSASS legitimately. Exclude by signed process.

## Tuning Notes

- **Scope the dump-file clause.** Dump files alone are noisier than the targeted commands; correlate them with the command on the same host.
- **Treat lsass+dump as immediate.** Any command line naming both `lsass` and a dump verb is high-confidence regardless of correlation.
- **Allowlist by publisher.** Exclude sanctioned crash-dump and EDR processes by signature, not by name.

## Validation

1. On an isolated test host, run the `rundll32 comsvcs.dll MiniDump` pattern against a benign process (not lsass) to fire the command-line detection without touching real credentials.
2. Confirm the host surfaces with the command captured.

## Learn More

- [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). LSASS dump detection and correlating the command with the dropped file
- [Detection Engineering: Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/). behavioral detection design for credential access
