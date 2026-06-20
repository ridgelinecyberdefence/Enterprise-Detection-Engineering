# Macro-Enabled Document Spawning Suspicious Process

Detects macro-enabled Office documents (DOCM, XLSM, DOTM, PPTM) spawning command interpreters, scripting engines, or living-off-the-land binaries. Vendor-agnostic Sigma rule covering the most reliable initial access indicator for document-based attacks.

## ATT&CK

- **Technique:** T1204.002 — User Execution: Malicious File, T1059 — Command and Scripting Interpreter
- **Tactic:** Execution, Initial Access

## Severity

**High.** Macro-enabled documents spawning shells have almost no legitimate business use. This is the initial execution step in phishing-to-C2 attack chains.

## Data Sources

- Process creation logs: Sysmon Event ID 1, Windows Security Event ID 4688, Defender for Endpoint, CrowdStrike, Carbon Black
- Requires: Parent process and command line logging

## Query — Sigma

```yaml
title: Macro-Enabled Document Spawning Suspicious Child Process
id: rc-sigma-008
status: production
description: |
  Detects macro-enabled Office applications spawning command interpreters
  or LOLBins. Covers the execution step after a user enables macros in a
  malicious document. The parent-child relationship is the behavioral
  constant — the payload changes but the spawn pattern doesn't.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.execution
  - attack.t1204.002
  - attack.t1059.001
  - attack.t1059.003
  - attack.initial_access
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\msaccess.exe'
      - '\mspub.exe'
      - '\visio.exe'
      - '\onenote.exe'
      - '\outlook.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\msbuild.exe'
      - '\installutil.exe'
      - '\bash.exe'
      - '\wsl.exe'
      - '\forfiles.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Legitimate macros that launch command-line tools for data processing
  - COM add-ins spawning helper processes
  - Outlook rules executing scripts on email arrival
level: high
```

## What Triggers This

A user opens a document, enables macros, and the VBA/DDE code calls `Shell()`, `WScript.Shell.Run()`, or `CreateProcess()` to launch a command interpreter. The child process typically executes a download cradle, encoded payload, or LOLBin command to establish the next stage of the attack.

## False Positives

1. **Business automation macros.** Macros that automate data processing by shelling out to command-line tools. Validate the macro and exclude by specific parent-child-commandline combination.
2. **COM add-ins.** Some Word/Excel add-ins spawn helper processes during document operations. These produce consistent, low-volume patterns from signed executables.
3. **Outlook script rules.** Rules that launch scripts on email arrival create outlook.exe → powershell.exe chains. These should be replaced with Power Automate workflows.

## Tuning Notes

- **Outlook handling.** Outlook generates more child processes than other Office apps due to preview pane rendering, link handling, and attachment operations. Consider a separate, higher-threshold rule for Outlook or add command line conditions.
- **SIEM conversion:** `sigma convert -t splunk -p windows sigma/execution/macro-child-process.yml`
- **Sentinel conversion:** `sigma convert -t microsoft365defender -p windows sigma/execution/macro-child-process.yml`

## Validation

1. Create a DOCM with VBA: `Sub AutoOpen(): Shell "cmd.exe /c echo test > %TEMP%\test.txt": End Sub`
2. Open the document and enable macros on a test endpoint
3. Verify detection fires with winword.exe as parent and cmd.exe as child

## Learn More

- [SOC Operations — Endpoint Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/) — process chain analysis for document-based attacks
- [Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/) — building behavioral detections for execution techniques
