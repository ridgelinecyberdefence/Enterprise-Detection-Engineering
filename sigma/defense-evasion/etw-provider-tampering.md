# ETW Provider Tampering — Disabling Event Tracing

Detects attempts to disable Event Tracing for Windows (ETW) providers used by security tools. ETW is the telemetry backbone for Defender for Endpoint, Sysmon, .NET logging, and PowerShell Script Block Logging. Disabling an ETW provider blinds the security tools that depend on it — no events, no detections.

## ATT&CK

- **Technique:** T1562.006 — Impair Defenses: Indicator Blocking
- **Tactic:** Defense Evasion

## Severity

**Critical.** ETW tampering disables the detection pipeline itself. Unlike AMSI bypass (which affects one inspection layer), ETW tampering can blind entire security products. If the Microsoft-Windows-Threat-Intelligence ETW provider is disabled, Defender for Endpoint loses kernel-level visibility.

## Data Sources

- Process creation with command line: Sysmon Event ID 1 or Windows Security 4688
- Registry modification: Sysmon Event ID 13 (for ETW provider registry keys)
- .NET CLR ETW events: Event ID 4104 (PowerShell attempting ETW manipulation)

## Query — Sigma

```yaml
title: ETW Provider Tampering or Disabling
id: rc-sigma-016
status: production
description: |
  Detects attempts to disable ETW providers via logman, wevtutil,
  registry modification, or PowerShell/.NET reflection. ETW
  providers feed telemetry to Defender, Sysmon, and AMSI.
  Disabling them blinds security products at the kernel level.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.defense_evasion
  - attack.t1562.006
  - attack.t1562.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_logman:
    Image|endswith: '\logman.exe'
    CommandLine|contains|any:
      - 'stop'
      - 'delete'
      - 'update'
    CommandLine|contains|any:
      - 'EventLog-'
      - 'Microsoft-Windows-Threat-Intelligence'
      - 'Microsoft-Antimalware'
      - 'SysmonDrv'
      - 'Microsoft-Windows-PowerShell'
      - 'Microsoft-Windows-WMI-Activity'
      - '.NET Common Language Runtime'
  selection_wevtutil:
    Image|endswith: '\wevtutil.exe'
    CommandLine|contains|any:
      - 'sl'
      - 'set-log'
    CommandLine|contains: '/e:false'
  selection_powershell_etw:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|any:
      - 'EtwEventWrite'
      - 'NtTraceEvent'
      - 'EventRegister'
      - 'Reflection'
    CommandLine|contains|any:
      - 'Patch'
      - 'VirtualProtect'
      - 'WriteProcessMemory'
  selection_registry:
    Image|endswith:
      - '\reg.exe'
      - '\powershell.exe'
    CommandLine|contains|all:
      - 'HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger'
      - 'Enabled'
      - '0'
  condition: selection_logman or selection_wevtutil or selection_powershell_etw or selection_registry
falsepositives:
  - Legitimate ETW session management by system administrators
  - Performance troubleshooting that temporarily disables verbose logging
level: critical
```

## What Triggers This

1. **logman stop/delete:** `logman stop "EventLog-Security"` — stops the security event log ETW session
2. **wevtutil disable:** `wevtutil sl Security /e:false` — disables a log channel
3. **PowerShell ETW patching:** Reflection-based patching of EtwEventWrite to prevent event emission
4. **Registry tampering:** Setting `Enabled=0` under ETW Autologger keys to prevent providers from starting at boot

## False Positives

1. **Performance diagnostics.** System administrators disabling verbose ETW providers during performance troubleshooting. Should be rare, documented, and temporary.
2. **ETW session management.** Custom ETW consumers starting/stopping sessions for diagnostic purposes. These typically use dedicated session names, not security provider sessions.

## Tuning Notes

- **Alert on every instance.** ETW tampering targeting security providers should never happen in normal operations. Every alert warrants immediate investigation.
- **Provider priority.** The most critical providers to monitor: Microsoft-Windows-Threat-Intelligence (kernel telemetry), SysmonDrv (Sysmon), Microsoft-Windows-PowerShell (Script Block Logging), Microsoft-Antimalware (Defender).

## Validation

1. On a test endpoint: `logman query "EventLog-Security"` (query only — does not modify)
2. For actual tamper testing (lab only): `logman stop "EventLog-Security"` then immediately `logman start "EventLog-Security"`
3. Verify detection fires on the stop command

## Learn More

- [Detection Engineering — Detection Architecture](https://training.ridgelinecyber.com/courses/detection-engineering/) — ETW architecture and detection pipeline security
- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — defense evasion techniques targeting security tooling
