# SAM Database Dump — Local Credential Extraction

Detects attempts to extract the Security Account Manager (SAM) database or SYSTEM registry hive, which contain local account password hashes. Dumping the SAM allows the attacker to crack local admin passwords offline or use pass-the-hash for lateral movement to every machine with the same local admin password.

## ATT&CK

- **Technique:** T1003.002 — OS Credential Dumping: Security Account Manager
- **Tactic:** Credential Access

## Severity

**High.** SAM dumps provide NTLM hashes for every local account on the system. In environments without LAPS, the local admin password is often identical across all workstations — one SAM dump provides lateral movement credentials for the entire fleet.

## Data Sources

- Process creation: Sysmon Event ID 1, Windows Security 4688, EDR
- Registry access: Sysmon Event ID 1 (reg.exe commands), Windows Security 4663

## Query — Sigma

```yaml
title: SAM Database or SYSTEM Hive Extraction
id: rc-sigma-020
status: production
description: |
  Detects reg.exe, esentutl, and other tools saving the SAM,
  SYSTEM, or SECURITY registry hives. These hives contain NTLM
  hashes for local accounts. Also detects Volume Shadow Copy
  access to extract offline copies of the hives.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.credential_access
  - attack.t1003.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_reg:
    Image|endswith: '\reg.exe'
    CommandLine|contains|any:
      - 'save'
      - 'export'
    CommandLine|contains|any:
      - 'hklm\sam'
      - 'hklm\system'
      - 'hklm\security'
      - 'HKLM\SAM'
      - 'HKLM\SYSTEM'
      - 'HKLM\SECURITY'
  selection_esentutl:
    Image|endswith: '\esentutl.exe'
    CommandLine|contains|any:
      - '\SAM'
      - '\SYSTEM'
      - '\SECURITY'
    CommandLine|contains|any:
      - '/y'
      - '/vss'
      - 'copy'
  selection_vss:
    CommandLine|contains|any:
      - '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy'
      - 'HarddiskVolumeShadowCopy'
    CommandLine|contains|any:
      - 'SAM'
      - 'SYSTEM'
      - 'SECURITY'
  selection_ps:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|any:
      - 'HiveNightmare'
      - 'SeriousSam'
      - 'SaveSubKey'
  selection_tools:
    CommandLine|contains|any:
      - 'secretsdump'
      - 'hashdump'
      - 'samdump'
  condition: selection_reg or selection_esentutl or selection_vss or selection_ps or selection_tools
falsepositives:
  - System backup tools that export registry hives
  - Forensic collection tools used by IR teams
  - SCCM task sequences during OS deployment
level: high
```

## What Triggers This

- `reg save hklm\sam C:\temp\sam.save`
- `esentutl /y /vss C:\Windows\System32\config\SAM /d C:\temp\sam.copy`
- Volume Shadow Copy access to SAM hive
- Impacket secretsdump remote SAM extraction

## False Positives

1. **Backup tools** exporting registry hives as part of system state backups
2. **IR/forensic tools** during authorized investigations
3. **OS deployment** task sequences accessing registry hives

## Tuning Notes

- Prioritize reg.exe detection — it's the simplest and most common technique
- Deploy LAPS to reduce SAM dump impact (unique local admin passwords per machine)

## Learn More

- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — credential dumping techniques
- [Incident Response](https://training.ridgelinecyber.com/courses/practical-ir/) — credential compromise assessment
