# MSBuild Inline Task Code Execution

Detects MSBuild.exe executing inline tasks from XML project files, a technique that compiles and runs arbitrary C# code without dropping a standalone executable. MSBuild is signed by Microsoft, present on systems with .NET or Visual Studio, and frequently allowed by application control policies.

## ATT&CK

- **Technique:** T1127.001 — Trusted Developer Utilities Proxy Execution: MSBuild
- **Tactic:** Defense Evasion, Execution

## Severity

**High.** MSBuild inline task execution compiles and runs arbitrary code in memory. No PE file is written to disk. No executable needs to bypass application control. The build file is XML — it passes email filters, web proxies, and most content inspection systems.

## Data Sources

- Process creation logs: Sysmon Event ID 1, Windows Security Event ID 4688, EDR telemetry
- File creation logs: Sysmon Event ID 11 for .csproj/.vbproj/.xml delivery

## Query — Sigma

```yaml
title: MSBuild Inline Task Code Execution
id: rc-sigma-010
status: production
description: |
  Detects MSBuild executing project files from unusual locations
  or with inline task compilation. MSBuild compiles and runs C#
  in memory — no PE on disk, signed by Microsoft, often allowed
  by AppLocker/WDAC. Used by APTs and red teams for defense
  evasion since 2017.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.defense_evasion
  - attack.t1127.001
  - attack.execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\MSBuild.exe'
      - '\msbuild.exe'
  filter_legitimate_paths:
    CommandLine|contains:
      - '\Visual Studio\'
      - '\MSBuild\Current\'
      - '\dotnet\sdk\'
      - '.sln'
  suspicious_paths:
    CommandLine|contains:
      - '\Temp\'
      - '\Downloads\'
      - '\AppData\'
      - '\ProgramData\'
      - '\Users\Public\'
      - 'C:\Windows\Temp\'
  suspicious_extensions:
    CommandLine|endswith:
      - '.xml'
      - '.csproj'
      - '.vbproj'
      - '.txt'
  condition: selection and (suspicious_paths or suspicious_extensions) and not filter_legitimate_paths
falsepositives:
  - Developer builds from non-standard directories
  - CI/CD build agents running in temp directories
level: high
```

## What Triggers This

An attacker delivers an XML project file containing an inline C# task. When MSBuild processes the file, it compiles the C# code in memory and executes it. The entire attack runs through a signed Microsoft binary processing a text file.

Example malicious project file:
```xml
<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <Task TaskName="Execute" TaskFactory="CodeTaskFactory"
          AssemblyFile="Microsoft.Build.Tasks.v4.0.dll">
      <Code Type="Fragment" Language="cs">
        // Arbitrary C# code executes here
      </Code>
    </Task>
  </Target>
</Project>
```

## False Positives

1. **Developer builds.** Developers running MSBuild from project directories. Filtered by the `filter_legitimate_paths` condition.
2. **CI/CD agents.** Build servers running in temp directories. Exclude by the CI/CD agent's service account.

## Tuning Notes

- **Developer workstations.** If developers are common, add a workstation group exclusion. MSBuild from non-developer machines is high confidence.
- **Application control.** If you control MSBuild via AppLocker/WDAC, this detection catches the cases that bypass those policies.

## Validation

1. Create a benign project file with an inline task that writes to a temp file
2. Execute: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\temp\test.xml`
3. Verify detection fires

## Learn More

- [Offensive Security for Defenders](https://training.ridgelinecyber.com/courses/offensive-security-for-defenders/) — LOLBin execution and application control bypass
- [Detection Engineering](https://training.ridgelinecyber.com/courses/detection-engineering/) — detection for trusted binary abuse
