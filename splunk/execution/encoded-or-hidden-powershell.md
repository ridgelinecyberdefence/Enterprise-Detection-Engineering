# Encoded or Hidden-Window PowerShell

**ATT&CK:** T1059.001 Command and Scripting Interpreter: PowerShell; T1027 Obfuscated Files or Information. Tactics: Execution, Defense Evasion.

**Severity:** High. Encoded command payloads and hidden windows are how PowerShell is driven by malware and frameworks, not by administrators. The flags themselves are the signal.

**Data Sources:** Sysmon Event ID 1 (`sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`) or any process telemetry carrying the full command line.

**Query:**

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process_name="powershell.exe"
    (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
     OR CommandLine="*-w hidden*" OR CommandLine="*-WindowStyle Hidden*"
     OR CommandLine="*FromBase64String*" OR CommandLine="*-nop*")
| stats count, values(CommandLine) AS command_lines, min(_time) AS first_seen, max(_time) AS last_seen
    by host, user, parent_process_name
| sort - count
```

**What Triggers This:** PowerShell invoked with an encoded command, a hidden window, no-profile execution, or in-line Base64 decoding. Each flag has legitimate uses in isolation, but together and outside sanctioned automation they characterise malicious invocation.

**False Positives:** Some management agents, installers, and scheduled jobs run encoded or hidden PowerShell. Distinguish by the parent process, the signing of the launching agent, and whether the host runs known automation.

**Tuning Notes:** Allowlist sanctioned automation by parent process and signed publisher rather than removing the flags. Decode `-enc` payloads at triage to read intent; for detection, the presence of encoding plus hidden window is enough. If PowerShell Script Block Logging (Event ID 4104) is available, correlate to capture the decoded body.

**Validation:** On a test host, run `powershell.exe -nop -w hidden -enc <benign-base64>`; confirm it surfaces with the command line captured.

**Learn More:** [Splunk Detection and Incident Response: Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers command-line obfuscation indicators and decoding at triage.
