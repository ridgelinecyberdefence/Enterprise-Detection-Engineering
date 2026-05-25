# DLL Search Order Hijacking

Detects DLL search order hijacking by identifying suspicious DLL loads from writable directories that precede the legitimate DLL location in the Windows search order. The attacker places a malicious DLL in a directory that Windows checks before the system directory — the target application loads the attacker's DLL instead of the legitimate one.

## ATT&CK

- **Technique:** T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking
- **Tactic:** Persistence, Privilege Escalation, Defense Evasion

## Severity

**High.** DLL hijacking executes attacker code in the context of the hijacked process. If the process runs as SYSTEM or with elevated privileges, the attacker inherits those privileges. The malicious DLL is loaded by a legitimate, signed binary — most security tools don't flag the load because the parent process is trusted.

## Data Sources

- Sysmon Event ID 7 (Image Loaded) — DLL load events with hash and signature info
- EDR telemetry: DLL/module load events
- Requires: Sysmon configured with ImageLoad logging

## Query — Sigma

```yaml
title: DLL Search Order Hijacking — Suspicious Load Path
id: rc-sigma-017
status: production
description: |
  Detects DLLs loaded from user-writable directories by system
  binaries or privileged applications. Windows searches the
  application directory before System32 — placing a DLL in
  the application's directory hijacks the load order.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.persistence
  - attack.t1574.001
  - attack.privilege_escalation
  - attack.defense_evasion
logsource:
  category: image_load
  product: windows
detection:
  selection_trusted_process:
    Image|contains:
      - '\Windows\System32\'
      - '\Windows\SysWOW64\'
      - '\Program Files\'
      - '\Program Files (x86)\'
  selection_suspicious_dll_path:
    ImageLoaded|contains:
      - '\Users\'
      - '\AppData\'
      - '\Temp\'
      - '\Downloads\'
      - '\Desktop\'
      - '\ProgramData\'
      - '\Windows\Temp\'
  filter_known_patterns:
    ImageLoaded|contains:
      - '\AppData\Local\Microsoft\'
      - '\AppData\Local\Google\Chrome\'
      - '\AppData\Local\Programs\'
  filter_signed:
    Signed: 'true'
    SignatureStatus: 'Valid'
  condition: selection_trusted_process and selection_suspicious_dll_path and not filter_known_patterns and not filter_signed
falsepositives:
  - Portable applications that load DLLs from user directories
  - Development environments with DLLs in project folders
  - Unsigned but legitimate third-party plugins
level: high
```

## What Triggers This

1. Attacker identifies a system binary that loads a DLL without specifying a full path
2. Attacker places their malicious DLL (named identically to the expected DLL) in a directory that precedes System32 in the search order
3. The target process starts and loads the attacker's DLL first
4. The malicious DLL executes in the context of the trusted process

Common targets: `comctl32.dll`, `version.dll`, `dbghelp.dll`, `wer.dll` loaded by system services.

## False Positives

1. **Chrome/Edge updates.** Browsers load DLLs from AppData during updates. Filtered by `filter_known_patterns`.
2. **Signed third-party DLLs.** Legitimate software with valid signatures loading from user directories. Filtered by `filter_signed`.
3. **Development environments.** IDEs loading project DLLs from user directories. Exclude known IDE paths.

## Tuning Notes

- **Unsigned DLL focus.** The `filter_signed` exclusion is critical. Signed, valid DLLs from user directories are almost always legitimate. Unsigned DLLs from user directories loaded by system processes are the attack pattern.
- **High-value process focus.** Create a higher-severity variant that only fires when the loading process runs as SYSTEM or is a known hijack target (services, scheduled tasks).
- **Combine with process creation.** DLL hijacking + subsequent suspicious child process from the hijacked application is a strong compound detection.

## Validation

1. In a lab, create a benign DLL named `version.dll` in a user-writable directory
2. Place a legitimate application that loads `version.dll` in the same directory
3. Verify Sysmon Event ID 7 fires with the suspicious load path

## Learn More

- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — DLL hijacking mechanics and privilege escalation chains
- [Purple Team Operations](https://training.ridgelinecyber.com/courses/purple-teaming-for-blue-teams/) — persistence technique validation
