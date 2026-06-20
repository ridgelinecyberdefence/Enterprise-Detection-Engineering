# PowerShell with Multiple Evasion Indicators

Detects PowerShell execution combining two or more evasion techniques: encoded commands, download cradles, AMSI bypass attempts, or hidden windows. Targets the behavior pattern, not individual commands.

## ATT&CK

- **Technique:** T1059.001. Command and Scripting Interpreter: PowerShell, T1562.001, Impair Defenses: Disable or Modify Tools
- **Tactic:** Execution, Defense Evasion

## Severity

**High.** Multiple evasion indicators in a single PowerShell invocation strongly suggest adversary activity. Legitimate automation rarely combines encoded commands with AMSI bypass or hidden windows.

## Data Sources

- Process creation logs: Sysmon Event ID 1, Windows Security Event ID 4688, or Defender for Endpoint `DeviceProcessEvents`
- Command line logging must be enabled
- ScriptBlock logging (Event ID 4104) provides additional context

## Query: Sigma

```yaml
title: PowerShell with Multiple Evasion Indicators
id: det-soc-021
status: production
description: |
  Detects PowerShell execution with 2+ evasion indicators:
  encoded commands, download cradles, AMSI bypass, or hidden
  windows. CrowdStrike 2025: PowerShell in 71% of LOTL attacks.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/17
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  encoded:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc '
  download:
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'Invoke-WebRequest'
  amsi:
    CommandLine|contains:
      - 'amsiInitFailed'
      - 'AmsiUtils'
  condition: selection and (encoded or download or amsi)
falsepositives:
  - Legitimate automation scripts using encoded commands
  - SCCM/Intune deployment scripts with execution policy bypass
level: high
```

## What Triggers This

An attacker launches PowerShell with multiple evasion techniques in the same command line:

- **Encoded commands** (`-enc`, `-EncodedCommand`). hides the payload from command line logging tools that don't decode Base64
- **Download cradles** (`Net.WebClient`, `Invoke-WebRequest`, `DownloadString`, `DownloadFile`). fetches payloads from attacker infrastructure
- **AMSI bypass** (`AmsiUtils`, `amsiInitFailed`, `SetValue`). disables the Antimalware Scan Interface before executing malicious scripts
- **Hidden window** (`-WindowStyle Hidden`, `-W Hidden`, `-NonInteractive`). runs PowerShell without a visible console window

The detection requires 2+ indicators in the same execution. A single indicator (e.g., `-EncodedCommand` alone) generates too many false positives from legitimate IT automation.

## False Positives

1. **SCCM/Intune deployment scripts.** Configuration management tools sometimes use encoded commands for complex deployments. These typically run as SYSTEM from known deployment paths. Exclude by parent process path after validation.
2. **Monitoring agents.** Some agents use `-NonInteractive -WindowStyle Hidden` for background operations. Validate the agent and exclude by the signed executable path.
3. **Developer tools.** IDE extensions and build scripts may invoke PowerShell with parameters that match. Correlate with the user account. Developer accounts in known dev groups are lower risk.

## Tuning Notes

- **Threshold adjustment.** The rule fires on 2+ indicators. In high-automation environments, consider raising to 3+ indicators for the first week to establish baseline.
- **Parent process context.** `explorer.exe` → `powershell.exe` with evasion indicators is almost always suspicious. `svchost.exe` → `powershell.exe` may be legitimate scheduled tasks.
- **Sentinel deployment:** Scheduled rule, 15-minute frequency. Map `CommandLine` as Process entity and `Computer`/`DeviceName` as Host entity.

## Validation

1. Open a command prompt on a test endpoint
2. Run: `powershell -EncodedCommand dABlAHMAdAA= -WindowStyle Hidden`
3. Verify the detection fires (the encoded payload is just "test")
4. Confirm the alert captures both evasion indicators

## Learn More

- [SOC Operations: Endpoint Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/). PowerShell attack detection and investigation
- [Detection Engineering: Threat Modeling](https://ridgelinecyber.com/training/courses/detection-engineering/). building behavioral detection for execution techniques
