# WMIC Remote Process Creation and Reconnaissance

Detects WMIC (Windows Management Instrumentation Command-line) used for remote process creation, system reconnaissance, and lateral movement. WMIC is a signed Microsoft tool present on every Windows system — it provides remote code execution over DCOM without deploying any agent or tool on the target.

## ATT&CK

- **Technique:** T1047 — Windows Management Instrumentation, T1059.001 — PowerShell
- **Tactic:** Execution, Lateral Movement, Discovery

## Severity

**Medium.** WMIC is used legitimately by IT operations teams, but the specific subcommands for remote process creation and system enumeration are strongly correlated with attack activity. Severity escalates to High when targeting is to a non-standard host or from a non-admin workstation.

## Data Sources

- Process creation logs: Sysmon Event ID 1, Windows Security Event ID 4688, EDR telemetry
- Requires: Command line logging enabled

## Query — Sigma

```yaml
title: WMIC Abuse — Remote Execution and Reconnaissance
id: rc-sigma-009
status: production
description: |
  Detects WMIC used for remote process creation (process call create),
  lateral movement, and aggressive system enumeration. WMIC provides
  remote code execution over DCOM without deploying tools. Microsoft
  deprecated WMIC in Windows 11 — any usage on modern systems is
  increasingly suspicious.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.execution
  - attack.t1047
  - attack.lateral_movement
  - attack.discovery
  - attack.t1018
logsource:
  category: process_creation
  product: windows
detection:
  selection_wmic:
    Image|endswith: '\wmic.exe'
  # Remote process creation — lateral movement
  remote_exec:
    CommandLine|contains|all:
      - '/node:'
      - 'process'
      - 'call'
      - 'create'
  # Reconnaissance commands
  recon_product:
    CommandLine|contains:
      - 'product get'
      - 'product list'
  recon_process:
    CommandLine|contains|all:
      - 'process'
      - 'get'
    CommandLine|contains:
      - 'commandline'
      - 'executablepath'
      - 'parentprocessid'
  recon_service:
    CommandLine|contains:
      - 'service get'
      - 'service list'
  recon_shadow:
    CommandLine|contains|all:
      - 'shadowcopy'
      - 'delete'
  recon_useraccount:
    CommandLine|contains:
      - 'useraccount get'
      - 'useraccount list'
  recon_qfe:
    CommandLine|contains:
      - 'qfe get'
      - 'qfe list'
  recon_av:
    CommandLine|contains:
      - 'AntiVirusProduct'
      - '/namespace:\\\\root\\SecurityCenter2'
  condition: selection_wmic and (remote_exec or recon_product or recon_process or recon_service or recon_shadow or recon_useraccount or recon_qfe or recon_av)
falsepositives:
  - IT asset inventory scripts using WMIC for hardware/software enumeration
  - SCCM/Intune management operations
  - Legacy deployment scripts
level: medium
```

## What Triggers This

- **Remote execution:** `wmic /node:TARGET process call create "cmd.exe /c payload"` — creates a process on a remote host over DCOM. No agent deployment needed.
- **Software inventory:** `wmic product get name,version` — enumerates installed software to find vulnerable applications or security tools to disable
- **Process reconnaissance:** `wmic process get commandline,executablepath` — finds running processes, looks for security tools, identifies other users' sessions
- **AV detection:** `wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get` — identifies which AV is installed before launching malware
- **Patch level:** `wmic qfe get` — enumerates installed patches to identify exploitable vulnerabilities
- **Shadow copy deletion:** `wmic shadowcopy delete` — ransomware preparation (covered in the ransomware pre-encryption detection but also caught here)

## False Positives

1. **IT asset management scripts.** Scripts that use WMIC for software inventory and hardware auditing. These typically run from known management servers on a schedule. Exclude by parent process (e.g., `sccm_client.exe`, specific script paths).
2. **SCCM client operations.** Configuration Manager uses WMIC internally for some operations. These run as SYSTEM from known SCCM paths.
3. **Legacy deployment scripts.** Older deployment tools use `wmic product` for application management. Migration to PowerShell eliminates this false positive source.

## Tuning Notes

- **Prioritize `/node:` remote execution.** `wmic /node:TARGET process call create` is the highest-risk subcommand. Consider a separate High severity rule for just this pattern.
- **WMIC deprecation.** Microsoft deprecated WMIC in Windows 11 (21H2+). On modern systems, any WMIC usage is increasingly unusual. Consider elevating severity for Windows 11 endpoints.
- **Parent process context.** WMIC spawned by `explorer.exe` (user double-clicked or typed in Run) is more suspicious than WMIC spawned by a scheduled task from a known management tool.

## Validation

1. On a test endpoint: `wmic process get name,processid,commandline`
2. Verify detection fires for the process reconnaissance pattern
3. For remote execution testing (lab only): `wmic /node:TEST-PC process call create "calc.exe"`

## Learn More

- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — WMIC in attack chains and the telemetry it generates
- [SOC Operations](https://training.ridgelinecyber.com/courses/m365-security-operations/) — endpoint process chain analysis
