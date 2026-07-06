# AMSI Bypass: Reflection-Based Memory Patching

Detects attempts to disable the Antimalware Scan Interface by patching the AmsiScanBuffer function in memory. AMSI is the last inspection layer before PowerShell, VBScript, JScript, and .NET code executes. Disabling it allows the attacker to run malicious scripts that would otherwise be blocked.

## ATT&CK

- **Technique:** T1562.001. Impair Defenses: Disable or Modify Tools
- **Tactic:** Defense Evasion

## Severity

**High.** AMSI bypass is a prerequisite for running most offensive PowerShell toolkits (Mimikatz, PowerView, Rubeus). The bypass itself is the precursor. What follows is the actual attack. If AMSI is bypassed, every subsequent PowerShell-based detection that relies on script content inspection is blind.

## Data Sources

- PowerShell Script Block Logging: Event ID 4104 (captures the bypass script content)
- Process creation with command line logging
- .NET ETW tracing (for advanced reflection-based bypasses)

## Query: Sigma

```yaml
title: AMSI Bypass via Reflection or Memory Patching
id: rc-sigma-015
status: production
description: |
  Detects AMSI bypass techniques that use .NET reflection to
  access AmsiUtils internals, or directly reference AMSI
  function names and patching primitives. Covers Matt Graeber's
  original bypass, the amsiInitFailed technique, and memory
  patching variants.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/25
tags:
  - attack.defense_evasion
  - attack.t1562.001
logsource:
  category: ps_script
  product: windows
detection:
  selection_reflection:
    ScriptBlockText|contains|any:
      - 'System.Management.Automation.AmsiUtils'
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
      - 'amsi.dll'
      - 'AmsiContext'
  selection_patch_primitives:
    ScriptBlockText|contains|any:
      - 'GetField'
      - 'SetValue'
      - 'NonPublic'
      - 'VirtualProtect'
      - 'Marshal.Copy'
      - 'GetProcAddress'
  selection_combined:
    ScriptBlockText|contains|all:
      - 'Reflection'
      - 'Assembly'
  condition: selection_reflection or (selection_patch_primitives and selection_combined)
falsepositives:
  - Security testing tools that intentionally test AMSI (authorized pen testing)
  - Anti-malware research environments
  - PowerShell development that legitimately references AMSI internals
level: high
```

## Alternative: Process Creation Rule

```yaml
title: AMSI Bypass via Command Line
id: rc-sigma-015b
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|any:
      - 'AmsiUtils'
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
      - 'Disable-Amsi'
      - 'Set-MpPreference -DisableScriptScanning'
  condition: selection
```

## What Triggers This

The attacker runs a PowerShell one-liner or script that disables AMSI before executing their payload. Common techniques:

**amsiInitFailed bypass:**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**AmsiScanBuffer memory patch:**
```powershell
$Win32 = @"
using System; using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
# Patches AmsiScanBuffer to return E_INVALIDARG
```

After the bypass, AMSI no longer scans script content. The attacker can then run Invoke-Mimikatz, PowerView, or any other blocked script without triggering AMSI-based detections.

## False Positives

1. **Authorized penetration testing.** Red team and pen test tools bypass AMSI as part of their methodology. Coordinate with testing teams and time-bound exclusions.
2. **Security research.** Malware analysts and security researchers testing AMSI in lab environments.
3. **Obfuscated matches.** Some legitimate PowerShell modules reference `Reflection.Assembly` for non-malicious purposes. The combined condition (`Reflection` + `Assembly` + patch primitives) reduces these.

## Tuning Notes

- **Script Block Logging is essential.** Without Event ID 4104, this detection only works via command line (which misses file-based and obfuscated bypasses). Enable ScriptBlockLogging via GPO.
- **Obfuscation variants.** Attackers encode, split strings, and use variable substitution to evade string-based detection. Supplement with a rule that detects PowerShell obfuscation patterns (string concatenation, `[char]` arrays, backtick insertion).
- **Combine with post-bypass activity.** An AMSI bypass followed by Mimikatz/PowerView/Rubeus keywords in subsequent script blocks is the complete attack pattern.

## Validation

1. On a test endpoint with Script Block Logging enabled:
   ```powershell
   # Safe test — this string triggers detection without actually bypassing AMSI
   Write-Output "Testing detection for AmsiUtils amsiInitFailed"
   ```
2. Verify Event ID 4104 fires and the Sigma rule matches

## Learn More

- [Offensive Security for Defenders](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/). AMSI architecture, bypass techniques, and detection engineering
- [Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/). building detections for defense evasion techniques
