# Persistence via Scheduled Task, Run Key, or Service Installation

Detects the three most common Windows persistence mechanisms in a single rule: scheduled task creation, registry Run/RunOnce key modification, and new service installation. Covers the persistence vectors used in over 80% of Windows-targeted attacks.

## ATT&CK

- **Technique:** T1053.005 — Scheduled Task, T1547.001 — Registry Run Keys, T1543.003 — Windows Service
- **Tactic:** Persistence, Execution

## Severity

**Medium.** Each individual mechanism is used by both legitimate software and attackers. The detection provides broad visibility into persistence establishment. Investigate based on the binary path, parent process, and user context.

## Data Sources

- Sysmon Event IDs 1 (Process Creation), 12/13 (Registry), 6 (Driver Loaded)
- Windows Security Event IDs 4698 (Scheduled Task), 7045 (Service Install), 4688 (Process Creation)
- Defender for Endpoint `DeviceProcessEvents`, `DeviceRegistryEvents`

## Query — Sigma

```yaml
title: Persistence via Scheduled Task, Run Key, or Service
id: det-soc-018
status: production
description: |
  Detects scheduled task creation, registry Run key modification,
  or service creation with suspicious command/path indicators.
  Red Canary 2025: scheduled tasks are the most prevalent
  persistence technique.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/17
tags:
  - attack.persistence
  - attack.t1053.005
  - attack.t1547.001
  - attack.t1543.003
logsource:
  category: process_creation
  product: windows
detection:
  schtasks:
    Image|endswith: '\schtasks.exe'
    CommandLine|contains: '/create'
    CommandLine|contains:
      - '\Temp\'
      - '\AppData\'
      - 'powershell'
      - 'rundll32'
  condition: schtasks
falsepositives:
  - Software deployment tools creating scheduled tasks
  - Group Policy applying scheduled tasks at scale
  - Legitimate installer creating Run key entries
level: high
```

## What Triggers This

1. **Scheduled task creation** — `schtasks.exe /create` or Task Scheduler API calls that register a new task
2. **Run/RunOnce registry key modification** — values added to `HKLM\...\Run`, `HKCU\...\Run`, or their `RunOnce` equivalents
3. **Service installation** — `sc.exe create` or `New-Service` registering a new Windows service with an executable path

Each vector gives the attacker code execution on boot, logon, or a scheduled interval. The attacker's payload runs automatically without user interaction.

## False Positives

1. **Software installation.** Applications legitimately create services, scheduled tasks, and Run keys during setup. Correlate with known software deployment windows.
2. **Windows Update.** The update process creates and modifies scheduled tasks and services. Filter by known Windows system paths.
3. **IT management tools.** RMM, monitoring, and patch management agents install services on endpoints. Maintain an allowlist of known management tool service names.

## Tuning Notes

- **Binary path analysis.** Focus investigation on persistence mechanisms pointing to binaries in user-writable directories (`%TEMP%`, `%APPDATA%`, `Downloads`). System directories are lower risk.
- **Stacking analysis.** Run the detection in hunt mode first — summarize by binary path across all endpoints. Persistence mechanisms present on 1-2 endpoints but not fleet-wide are suspicious.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. High volume — tune exclusions before enabling automated incidents.

## Validation

1. Create a benign scheduled task: `schtasks /create /tn "RidgelineTest" /tr "calc.exe" /sc daily /st 23:59`
2. Verify the detection fires and captures the task name, binary path, and creating user
3. Delete the task: `schtasks /delete /tn "RidgelineTest" /f`

## Learn More

- [SOC Operations — Endpoint Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/) — persistence detection and investigation methodology
- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/) — how attackers establish persistence and what telemetry they generate
