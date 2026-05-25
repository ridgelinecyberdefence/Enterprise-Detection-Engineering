# Exfiltration via OneDrive Sync to Unmanaged Device

Detects OneDrive or SharePoint file sync initiated from an unmanaged or non-compliant device. An attacker or insider syncs an entire document library to a personal device, creating a complete offline copy of company data that persists after the account is remediated.

## ATT&CK

- **Technique:** T1530 — Data from Cloud Storage
- **Tactic:** Exfiltration, Collection

## Severity

**High.** A full library sync to an unmanaged device creates an offline copy of potentially thousands of files. Unlike file-by-file download, sync is silent and can include entire department drives.

## Data Sources

- Microsoft 365 Unified Audit Log — `OfficeActivity` (FileSyncDownloadedFull, FileSynced)
- Entra ID Sign-in Logs — device compliance state

## Detection

```yaml
title: OneDrive/SharePoint Sync from Non-Compliant or Unmanaged Device
id: 2e9b4a73-d158-4c92-8f61-a3d7e5b29c14
status: experimental
description: >
  Detects full file sync operations from devices that are not Intune-managed
  or not compliant. Indicates potential data exfiltration via offline sync
  to a personal device.
references:
  - https://attack.mitre.org/techniques/T1530/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.exfiltration
  - attack.collection
  - attack.t1530
logsource:
  product: m365
  service: audit
detection:
  selection:
    Operation:
      - 'FileSyncDownloadedFull'
      - 'FileSynced'
      - 'FileDownloaded'
    OfficeWorkload:
      - 'SharePoint'
      - 'OneDrive'
  condition: selection
  # Post-filter in SIEM: correlate with sign-in logs where
  # DeviceDetail.isCompliant == false or DeviceDetail.isManaged == false
falsepositives:
  - Employees syncing work files to approved personal devices (BYOD policy)
  - New device setup during legitimate onboarding
  - IT testing sync functionality
level: high
```

## KQL Supplement

```kql
let TimePeriod = 24h;
let SyncThreshold = 50;
OfficeActivity
| where TimeGenerated > ago(TimePeriod)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where Operation in ("FileSyncDownloadedFull", "FileSynced", "FileDownloaded")
| summarize
    SyncCount = count(),
    DistinctFiles = dcount(SourceFileName),
    Sites = make_set(Site_, 10),
    IPs = make_set(ClientIP, 5),
    FirstSync = min(TimeGenerated),
    LastSync = max(TimeGenerated)
    by UserId
| where SyncCount >= SyncThreshold
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(TimePeriod)
    | where ResultType == 0
    | extend IsCompliant = tostring(DeviceDetail.isCompliant),
             IsManaged = tostring(DeviceDetail.isManaged),
             DeviceOS = tostring(DeviceDetail.operatingSystem)
    | summarize
        ManagedSignIns = countif(IsManaged == "true"),
        UnmanagedSignIns = countif(IsManaged != "true"),
        DeviceOSList = make_set(DeviceOS, 5)
        by UserPrincipalName
) on $left.UserId == $right.UserPrincipalName
| where UnmanagedSignIns > 0
| project
    UserId,
    SyncCount,
    DistinctFiles,
    Sites,
    UnmanagedSignIns,
    DeviceOSList,
    FirstSync,
    LastSync
| sort by SyncCount desc
```

## Tuning Notes

- The sync threshold of 50 files in 24 hours catches bulk sync while ignoring normal single-file sync operations
- Correlate with device compliance from sign-in logs. If the syncing user has ONLY unmanaged device sign-ins, confidence is very high.
- Consider blocking OneDrive sync on unmanaged devices via Conditional Access session controls (`Use app enforced restrictions`)

## Learn More

- [M365 Security Architecture — Data Protection](https://training.ridgelinecyber.com/courses/m365-security-architecture/) — sync controls and session restrictions
- [SOC Operations — Cloud Exfiltration Investigation](https://training.ridgelinecyber.com/courses/m365-security-operations/) — investigating data theft via cloud storage
