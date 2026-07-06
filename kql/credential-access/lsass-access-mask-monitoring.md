# LSASS Access Mask Monitoring

Detects processes accessing LSASS memory using access masks associated with credential dumping tools. Behavioral detection. Works regardless of the tool name or process path the attacker uses.

## ATT&CK

- **Technique:** T1003.001. OS Credential Dumping: LSASS Memory
- **Tactic:** Credential Access

## Severity

**High.** LSASS memory access with these masks has very few legitimate uses outside Windows system processes. A true positive here means credential material is being read from memory.

## Data Sources

- Microsoft Defender for Endpoint, `DeviceEvents` table
- Requires: `OpenProcessApiCall` action type enabled in advanced features
- Alternative: Sysmon Event ID 10 (ProcessAccess) with `TargetImage` containing `lsass.exe`

## Query: KQL (Defender XDR / Sentinel)

```kql
DeviceEvents
| where TimeGenerated > ago(1d)
| where ActionType == "OpenProcessApiCall"
| extend TargetProcess = tostring(AdditionalFields.TargetImageFile)
| extend GrantedAccess = tostring(AdditionalFields.GrantedAccess)
| where TargetProcess endswith "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a", "0x1f0fff")
| where not (
    InitiatingProcessFolderPath startswith @"c:\windows\system32\"
    or InitiatingProcessFolderPath startswith @"c:\program files\"
    or InitiatingProcessFolderPath startswith @"c:\program files (x86)\"
    or InitiatingProcessFileName in~ ("MsMpEng.exe", "csrss.exe", "svchost.exe")
)
| project
    TimeGenerated,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    TargetProcess,
    GrantedAccess,
    InitiatingProcessAccountName
```

## What Triggers This

An attacker (or their tool) calls `OpenProcess` against `lsass.exe` with access masks that grant memory read capability:

| Mask | Meaning | Common Tool |
|---|---|---|
| `0x1010` | PROCESS_VM_READ + PROCESS_QUERY_LIMITED_INFORMATION | Mimikatz (default) |
| `0x1410` | PROCESS_VM_READ + PROCESS_QUERY_INFORMATION | Procdump |
| `0x1438` | VM_READ + QUERY_INFO + VM_WRITE + VM_OPERATION | Mimikatz (sekurlsa) |
| `0x143a` | As above + CREATE_THREAD | Advanced credential tools |
| `0x1f0fff` | PROCESS_ALL_ACCESS | Crude tools, some post-exploitation frameworks |

The detection uses `endswith "lsass.exe"` instead of exact path matching because the LSASS process path is consistent, but the key behavioral signal is the access mask, not the process name of the initiator.

## False Positives

1. **Antivirus/EDR scanning.** MsMpEng.exe, CrowdStrike Falcon sensor, and similar security tools legitimately access LSASS. Excluded by the `InitiatingProcessFileName` filter. Add your EDR process name if not already listed.
2. **Windows system processes.** `csrss.exe` and `svchost.exe` access LSASS during normal session management. Excluded by the system path and process name filters.
3. **IT management tools.** Some RMM and monitoring agents access LSASS for authentication. Validate the process and add to exclusions only after confirming the tool legitimately requires LSASS access.

## Tuning Notes

- **Exclusion approach:** Exclude by `InitiatingProcessFolderPath` (signed, known location) rather than by process name alone. Attackers rename binaries. They rarely install them in `C:\Program Files\`.
- **Access mask scope:** The five masks listed cover the most common credential dumping tools observed in production. If you see alerts on a mask not listed here, investigate before excluding. It may be a tool variant.
- **Volume:** In a 500-endpoint environment with proper exclusions, expect 0-2 alerts per day. Higher volume indicates either missing exclusions or active credential access attempts.
- **Sentinel deployment:** Deploy as a Scheduled analytics rule with 1-hour frequency and 1-day lookback. Map `DeviceName` as Host entity and `InitiatingProcessAccountName` as Account entity.

## Validation

1. Use a non-privileged account on a test endpoint
2. Run: `procdump -ma lsass.exe lsass.dmp` (requires local admin)
3. Verify the detection fires within the rule frequency window
4. Confirm the alert includes the correct device, account, and access mask
5. Delete the dump file immediately after testing

**Do not test with Mimikatz on production endpoints.** Use Procdump or the Sysinternals LiveKD tool for validation.

## Learn More

- [Detection Engineering: Custom Endpoint Detections](https://ridgelinecyber.com/training/courses/detection-engineering/). full walkthrough of behavioral detection design for credential access
- [Endpoint Security: LSASS and Credential Storage](https://ridgelinecyber.com/training/courses/endpoint-security/). deep dive on LSASS architecture and why these access masks matter
