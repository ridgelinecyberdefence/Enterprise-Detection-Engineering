# LOLBin Execution with Download or Decode Arguments

Detects abuse of legitimate Windows binaries (Living Off the Land Binaries) for payload download, decoding, or proxy execution. These binaries are signed by Microsoft and present on every Windows system, making them the primary tool for malware-free attacks.

## ATT&CK

- **Technique:** T1218. System Binary Proxy Execution, T1105, Ingress Tool Transfer
- **Tactic:** Defense Evasion, Execution

## Severity

**Medium.** LOLBin usage is common in both attacks and legitimate IT operations. The combination of a LOLBin with download/decode arguments significantly increases confidence. Investigate every alert. But expect some legitimate IT automation.

## Data Sources

- Process creation logs: Sysmon Event ID 1, Windows Security Event ID 4688 (with command line), or Defender for Endpoint `DeviceProcessEvents`
- Command line logging must be enabled

## Query: Sigma

```yaml
title: LOLBin Execution with Download or Decode Arguments
id: det-soc-015
status: production
description: |
  Detects abuse of legitimate Windows binaries for payload
  download, decode, or execution. Covers certutil, mshta,
  bitsadmin, rundll32, regsvr32. CrowdStrike 2025 report:
  79% of attacks are malware-free, using LOLBins instead.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/17
tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.execution
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection_certutil:
    Image|endswith: '\certutil.exe'
    CommandLine|contains|any:
      - '-urlcache'
      - '-decode'
      - '-encode'
      - '-decodehex'
      - 'http://'
      - 'https://'
  selection_mshta:
    Image|endswith: '\mshta.exe'
    CommandLine|contains|any:
      - 'http://'
      - 'https://'
      - 'javascript:'
      - 'vbscript:'
      - '.hta'
  selection_bitsadmin:
    Image|endswith: '\bitsadmin.exe'
    CommandLine|contains|any:
      - '/transfer'
      - '/create'
      - '/addfile'
      - 'http://'
      - 'https://'
  selection_rundll32:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|any:
      - 'javascript:'
      - 'http://'
      - 'shell32.dll,ShellExec_RunDLL'
      - ',DllRegisterServer'
  selection_regsvr32:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains|any:
      - '/s /n /u /i:http'
      - '/s /n /u /i:https'
      - 'scrobj.dll'
  condition: 1 of selection_*
falsepositives:
  - IT automation scripts using certutil for certificate management
  - Software deployment tools using bitsadmin for downloads
  - Legacy applications using mshta for HTML Application interfaces
level: medium
```

## What Triggers This

An attacker uses a signed Windows binary to download a payload, decode an encoded file, or execute code through a proxy mechanism:

- **certutil**. Downloads files with `-urlcache -f` or decodes Base64-encoded payloads with `-decode`. Present on every Windows system as a certificate management tool.
- **mshta**. Executes HTML Applications (.hta) or inline JavaScript/VBScript. Used for initial payload execution from phishing links.
- **bitsadmin**. Downloads files using the Background Intelligent Transfer Service. Survives reboots and runs as a system service.
- **rundll32**. Executes DLL exports or JavaScript via `javascript:` protocol handler. Used for DLL side-loading and proxy execution.
- **regsvr32**. Registers COM objects, but the `/i` parameter accepts URLs for remote scriptlet execution (Squiblydoo technique).

## False Positives

1. **certutil for certificate operations.** IT teams use `certutil -addstore`, `-viewstore`, and `-verify` routinely. The detection filters for download/decode arguments specifically, which should not appear in normal certificate management.
2. **bitsadmin for SCCM/WSUS.** Software deployment systems use BITS for file transfers. These typically run as SYSTEM from known deployment directories. Exclude by parent process path if your deployment tool is identified.
3. **mshta for legacy applications.** Some older LOB applications use HTA interfaces. Identify these applications and exclude by the specific HTA file path, never exclude `mshta.exe` globally.

## Tuning Notes

- **Start with certutil and mshta.** These two generate the fewest false positives and cover the most common attack vectors. Add bitsadmin, rundll32, and regsvr32 after your baseline is clean.
- **Parent process context.** Adding parent process analysis dramatically reduces false positives. A `certutil` spawned by `cmd.exe` from a user's Downloads folder is suspicious. The same `certutil` spawned by `svchost.exe` from System32 is likely legitimate.
- **SIEM conversion.** Convert with pySigma: `sigma convert -t microsoft365defender -p windows sigma/defense-evasion/lolbin-download-decode.yml`
- **Sentinel deployment:** Scheduled rule, 15-minute frequency. Map `Image` (process path) as Process entity and `Computer`/`DeviceName` as Host entity.

## Validation

1. Open a command prompt on a test endpoint
2. Run: `certutil -urlcache -f https://example.com/test.txt C:\temp\test.txt`
3. Verify the detection fires with the correct process, command line, and arguments
4. Clean up: `del C:\temp\test.txt`

## Learn More

- [SOC Operations: Endpoint & Lateral Movement Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/). LOLBin detection strategies and tuning methodology
- [Detection Engineering: Threat Modeling](https://ridgelinecyber.com/training/courses/detection-engineering/). building detection coverage for malware-free attack techniques
