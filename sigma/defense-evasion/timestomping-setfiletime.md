# Timestomping: File Time Attribute Manipulation

Detects tools and techniques that modify file timestamps to blend malicious files with legitimate system files. Timestomping breaks timeline analysis. The attacker's files appear to have been created during the OS installation instead of during the intrusion.

## ATT&CK

- **Technique:** T1070.006, Indicator Removal: Timestomp
- **Tactic:** Defense Evasion

## Severity

**Medium.** Timestomping is an anti-forensics technique that indicates the attacker is operationally mature and actively trying to evade investigation. The timestomping itself doesn't cause harm, but it signals that the attacker is covering tracks. Which means there are tracks to cover.

## Data Sources

- Process creation with command line: Sysmon Event ID 1
- File creation time changed: Sysmon Event ID 2 (only source for actual timestamp modification)
- Requires: Sysmon with FileCreateTime change logging enabled

## Query: Sigma

```yaml
title: Timestomping — File Creation Time Modification
id: rc-sigma-019
status: production
description: |
  Detects timestomping via Sysmon FileCreateTime events and
  command-line tools that modify file timestamps. Covers
  PowerShell Set-ItemProperty, NtSetInformationFile via
  compiled tools, and common timestomping utilities.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.defense_evasion
  - attack.t1070.006
logsource:
  category: process_creation
  product: windows
detection:
  selection_powershell:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|any:
      - 'CreationTime'
      - 'LastWriteTime'
      - 'LastAccessTime'
      - 'Set-ItemProperty'
      - 'SetCreationTime'
      - 'SetLastWriteTime'
  selection_tools:
    CommandLine|contains|any:
      - 'timestomp'
      - 'SetMACE'
      - 'NtSetInformationFile'
      - 'FileBasicInformation'
  condition: selection_powershell or selection_tools
falsepositives:
  - Build systems that set consistent file timestamps for reproducible builds
  - Backup/restore tools that preserve original file timestamps
  - Archive extraction tools (7-Zip, WinRAR) restoring archived timestamps
level: medium
```

## Sysmon Rule: File Creation Time Changed

```yaml
title: Suspicious File Creation Time Changed
id: rc-sigma-019b
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 2  # FileCreateTime changed
  filter_legitimate:
    Image|contains:
      - '\Windows\System32\'
      - '\Program Files\'
      - '\7-Zip\'
      - '\WinRAR\'
  suspicious_target:
    TargetFilename|contains:
      - '\Windows\System32\'
      - '\Windows\SysWOW64\'
      - '\Windows\Temp\'
  condition: selection and suspicious_target and not filter_legitimate
```

## What Triggers This

The attacker drops a malicious DLL or executable in `C:\Windows\System32` and changes its creation timestamp to match `kernel32.dll` (the OS installation date). During forensic analysis, sorting files by creation time no longer reveals the attacker's files.

## False Positives

1. **Archive extraction.** 7-Zip, WinRAR, and Windows built-in extraction restore the original file timestamps from the archive. Filtered by `filter_legitimate`.
2. **Backup restoration.** Backup tools preserve timestamps when restoring files.
3. **Reproducible builds.** Some build systems set timestamps to epoch or a fixed date for build reproducibility.

## Tuning Notes

- **Sysmon Event ID 2 is essential.** The process creation rule catches tool usage. Sysmon Event ID 2 catches the actual timestamp modification regardless of how it was done.
- **Focus on system directories.** Timestomping in user directories is lower priority. Timestomping in System32 or SysWOW64 is almost always malicious.

## Validation

1. In a test environment: `(Get-Item C:\Temp\test.txt).CreationTime = '2020-01-15 08:30:00'`
2. Verify the PowerShell rule fires on the command line and Sysmon Event ID 2 fires on the timestamp change

## Learn More

- [Windows Forensics](https://ridgelinecyber.com/training/courses/windows-endpoint-investigation/). filesystem timestamp analysis and timestomping detection in NTFS
- [Incident Response](https://ridgelinecyber.com/training/courses/practical-ir/). timeline construction and anti-forensics awareness
