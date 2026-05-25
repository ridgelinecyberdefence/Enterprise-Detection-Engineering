# Office Application Spawning Suspicious Child Process

Detects Microsoft Office applications (Word, Excel, Outlook, PowerPoint, OneNote) launching command interpreters or scripting engines. This is the canonical initial access pattern for macro-based and exploit-based document attacks — the document opens, executes embedded code, and spawns a shell to download or execute the payload.

## ATT&CK

- **Technique:** T1059.001 — PowerShell, T1059.003 — Windows Command Shell, T1204.002 — User Execution: Malicious File
- **Tactic:** Execution, Initial Access

## Severity

**High.** Office applications have no legitimate reason to spawn PowerShell, cmd, wscript, or mshta in normal business use. Macro-enabled documents and exploits that achieve code execution produce this parent-child pattern as the first observable step. CrowdStrike 2025: 62% of initial access that involved Office documents produced an Office → shell parent-child relationship.

## Data Sources

- Defender for Endpoint — `DeviceProcessEvents` table
- Alternative: Sysmon Event ID 1 (Process Creation) via `Event` or `SecurityEvent` table
- Requires: Command line logging enabled

## Query — KQL (Defender XDR / Sentinel)

```kql
let lookback = 24h;
let officeProcesses = dynamic([
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "onenote.exe", "msaccess.exe",
    "mspub.exe", "visio.exe"
]);
let suspiciousChildren = dynamic([
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe",
    "bash.exe", "wsl.exe"
]);
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ (officeProcesses)
| where FileName in~ (suspiciousChildren)
| extend CommandLineLength = strlen(ProcessCommandLine)
| extend HasEncodedCmd = ProcessCommandLine has_any (
    "-enc", "-EncodedCommand", "frombase64", "ToBase64String"
)
| extend HasDownload = ProcessCommandLine has_any (
    "Net.WebClient", "DownloadString", "DownloadFile",
    "Invoke-WebRequest", "wget", "curl", "bitsadmin",
    "certutil -urlcache"
)
| extend HasEvasion = ProcessCommandLine has_any (
    "-WindowStyle Hidden", "-W Hidden", "-NonInteractive",
    "bypass", "AmsiUtils", "amsiInitFailed"
)
| extend RiskScore = toint(HasEncodedCmd) * 3
    + toint(HasDownload) * 3
    + toint(HasEvasion) * 2
    + toint(CommandLineLength > 500) * 2
| project
    Timestamp,
    DeviceName,
    AccountName,
    ParentProcess = InitiatingProcessFileName,
    ChildProcess = FileName,
    ProcessCommandLine,
    CommandLineLength,
    RiskScore,
    HasEncodedCmd,
    HasDownload,
    HasEvasion,
    InitiatingProcessCommandLine,
    FolderPath
| sort by RiskScore desc, Timestamp desc
```

## Why This Detection Is Effective

The Office-to-shell parent-child relationship is a behavioral constant across almost every macro-based and many exploit-based attacks. The specific payload changes with every campaign. The delivery mechanism (phishing, web download) varies. But the moment embedded code executes, it spawns a shell — and Office is the parent process.

The risk scoring adds analytical depth:
- **Encoded commands (score +3)** — almost always malicious in this context. Legitimate Office macros don't base64-encode PowerShell.
- **Download cradles (score +3)** — the macro is fetching a second-stage payload. This is the weaponized part of the kill chain.
- **Evasion techniques (score +2)** — hidden windows, AMSI bypass, execution policy bypass. Defense-aware malware.
- **Long command lines (score +2)** — encoded payloads produce command lines > 500 characters. Legitimate shell commands from Office are short (10-50 characters).

A RiskScore of 0 means Office spawned a shell with a simple command (rare but occasionally legitimate — e.g., a macro opening a folder with `cmd /c explorer`). A RiskScore of 6+ is almost certainly an attack.

## What Triggers This

1. User opens a malicious document (email attachment, web download, shared file)
2. The document contains a macro (VBA), DDE link, or triggers an exploit
3. The embedded code calls `Shell()`, `WScript.Shell`, or `CreateProcess` to launch a shell
4. The shell executes a command — typically a download cradle or encoded payload
5. The detection captures the Office → shell parent-child chain with the full command line

## False Positives

1. **Legitimate macros that shell out.** Some business macros launch command-line tools for data processing, file operations, or system queries. These should use specific, short command lines — not download cradles or encoded commands. Validate the macro and exclude by the specific command line pattern.
2. **COM add-ins.** Some Excel/Word add-ins spawn helper processes. These are typically signed executables from known vendors, not interpreters like PowerShell or cmd.
3. **IT automation triggered by Outlook rules.** Outlook rules that launch scripts on email arrival produce an `outlook.exe` → `powershell.exe` chain. These should use specific, signed scripts from known paths.
4. **OneNote embedded files.** OneNote allows embedding files that users can double-click to execute. This produces a `onenote.exe` → `<anything>` chain. Since OneNote has been weaponized extensively since 2023, treat OneNote child processes with extra scrutiny.

## Tuning Notes

- **Start with RiskScore > 0.** In the first week, review all alerts. Move to RiskScore >= 3 after baseline if score-0 alerts are all false positives.
- **Outlook special handling.** Outlook spawning processes is more common than Word/Excel due to preview pane rendering, link handling, and attachment opening. Consider a separate, higher-threshold rule for Outlook.
- **Command line allowlist.** If you identify legitimate macros that must shell out, exclude by the exact command line string (not by process name — that's too broad).
- **Sentinel deployment:** NRT rule for RiskScore >= 3. Scheduled rule (15 min) for RiskScore 0-2. Entity mapping: `DeviceName` as Host, `AccountName` as Account.

## Validation

1. Create a Word document with a VBA macro: `Sub Test(): Shell "cmd.exe /c echo test", vbHide: End Sub`
2. Enable macros and run the macro on a test endpoint
3. Verify the detection fires with Word as the parent and cmd.exe as the child
4. Delete the test document after validation

## References

- CrowdStrike 2025 Global Threat Report: Office-based initial access statistics
- MITRE ATT&CK: [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/)

## Learn More

- [SOC Operations — Endpoint Detection](https://training.ridgelinecyber.com/courses/m365-security-operations/) — process chain analysis and endpoint alert triage
- [Detection Engineering](https://training.ridgelinecyber.com/courses/detection-engineering/) — building behavioral detections for execution techniques
- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — macro attack development and the telemetry it produces
