# PowerShell — Encoded or Hidden-Window Execution

Detects PowerShell invoked with an encoded command, a hidden window, no-profile execution, or in-line Base64 decoding. Each flag has legitimate uses in isolation, but together and outside sanctioned automation they characterise malicious invocation.

## ATT&CK

- **Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell, T1027 — Obfuscated Files or Information
- **Tactic:** Execution, Defense Evasion

## Severity

**High.** Encoded payloads and hidden windows are how PowerShell is driven by malware and offensive frameworks, not by administrators. The flags themselves are the signal.

## Data Sources

- Sysmon Event ID 1 — `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`, or any process telemetry carrying the full command line
- Requires: command-line capture; PowerShell Script Block Logging (Event ID 4104) strengthens triage

## Query

```spl
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 process_name="powershell.exe"
    (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
     OR CommandLine="*-w hidden*" OR CommandLine="*-WindowStyle Hidden*"
     OR CommandLine="*FromBase64String*" OR CommandLine="*-nop*")
| stats count, values(CommandLine) AS command_lines, min(_time) AS first_seen, max(_time) AS last_seen
    by host, user, parent_process_name
| sort - count
```

## What Triggers This

PowerShell invoked the way malware invokes it:

- An encoded command (`-enc`, `-EncodedCommand`) or in-line `FromBase64String`
- A hidden window (`-w hidden`, `-WindowStyle Hidden`) or no-profile (`-nop`) execution
- These flags appearing outside sanctioned automation, especially under an unusual parent

## False Positives

1. **Management agents.** Some agents and installers run encoded or hidden PowerShell. Allowlist by parent process and signed publisher.
2. **Scheduled jobs.** Sanctioned jobs may use these flags. Distinguish by the launching parent and host.
3. **Vendor tooling.** Product installers occasionally encode commands. Exclude by signature.

## Tuning Notes

- **Allowlist by parent and publisher.** Exclude sanctioned automation rather than removing the flags.
- **Decode at triage.** Decode `-enc` payloads to read intent; for detection, encoding plus a hidden window is enough.
- **Correlate script blocks.** Where Event ID 4104 is available, join it to capture the decoded body.

## Validation

1. On a test host, run `powershell.exe -nop -w hidden -enc <benign-base64>`.
2. Confirm it surfaces with the command line captured.

## Learn More

- [Splunk Detection and Incident Response — Endpoint Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — command-line obfuscation indicators and decoding at triage
- [Detection Engineering — Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/) — designing detections for obfuscated execution
