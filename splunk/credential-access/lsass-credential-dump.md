# LSASS Credential Dump via comsvcs or Dump File

**ATT&CK:** T1003.001 OS Credential Dumping: LSASS Memory. Tactic: Credential Access.

**Severity:** Critical. Dumping LSASS yields plaintext and hashed credentials for everyone logged on, which is the pivot from one host to the domain. The `comsvcs.dll MiniDump` technique is a common living-off-the-land path.

**Data Sources:** Sysmon Event ID 1 (process creation) and Event ID 11 (file create), `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`.

**Query:**

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    ((EventCode=1 process_name="rundll32.exe" CommandLine="*comsvcs*" CommandLine="*MiniDump*")
     OR (EventCode=1 CommandLine="*lsass*" (CommandLine="*MiniDump*" OR CommandLine="*procdump*"))
     OR (EventCode=11 file_name="*.dmp"))
| stats values(EventCode) AS events, values(CommandLine) AS dump_command,
        values(file_name) AS dropped_file, min(_time) AS first_seen by host, user
| sort - first_seen
```

**What Triggers This:** A `rundll32 comsvcs.dll MiniDump` invocation, a procdump or other tool targeting `lsass`, or a `.dmp` file being written. The strongest case correlates the dumping command and a dropped `.dmp` on the same host.

**False Positives:** Crash-dump tooling and some EDR self-tests write `.dmp` files; legitimate diagnostics occasionally dump process memory. Distinguish by whether `lsass` is the target and whether the actor is a sanctioned diagnostic process.

**Tuning Notes:** Keep the `.dmp` clause scoped or correlated, since dump files alone are noisier than the targeted commands. Allowlist sanctioned crash-dump and EDR processes by signed publisher. Treat any command line naming both `lsass` and a dump verb as immediate regardless of correlation.

**Validation:** On an isolated test host, run the `rundll32 comsvcs.dll MiniDump` pattern against a benign process (not lsass) to confirm the command-line detection fires without touching real credentials.

**Learn More:** [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers LSASS dump detection and correlating the command with the dropped file.
