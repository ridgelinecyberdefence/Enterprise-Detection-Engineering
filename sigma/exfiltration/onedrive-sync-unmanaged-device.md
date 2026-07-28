# Exfiltration via OneDrive Sync to Unmanaged Device

Detects OneDrive or SharePoint file sync initiated from an unmanaged or non-compliant device. An attacker or insider syncs an entire document library to a personal device, creating a complete offline copy of company data that persists after the account is remediated.

## ATT&CK

- **Technique:** T1530, Data from Cloud Storage
- **Tactic:** Exfiltration, Collection

## Severity

**High.** A full library sync to an unmanaged device creates an offline copy of potentially thousands of files. Unlike file-by-file download, sync is silent and can include entire department drives.

## Data Sources

- Microsoft 365 Unified Audit Log, `OfficeActivity` (FileSyncDownloadedFull, FileSynced)
- Entra ID Sign-in Logs, device compliance state

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

## What Triggers This

Bulk retrieval from SharePoint or OneDrive, from the Microsoft 365 audit log. The rule matches `FileSyncDownloadedFull`, `FileSynced` and `FileDownloaded` operations against SharePoint and OneDrive workloads.

`FileSyncDownloadedFull` is the interesting one. It indicates a sync client pulling an entire library, which is what happens when someone connects a new device and takes a copy of everything they can reach.

## False Positives

1. **A user setting up a new laptop.** The first sync of a genuine device produces exactly this event at high volume, and it is completely normal. Onboarding weeks will be your busiest period.
2. **Legitimate offline access.** Staff who work on the move sync entire libraries deliberately.
3. **Migration and backup tooling,** which downloads at scale by design.
4. **The rule does not know whether the device is managed.** The title says unmanaged, but the operation alone cannot tell you that; the device identity has to come from Conditional Access or Intune, and without that join the rule matches all sync activity equally.

## Tuning Notes

- The sync threshold of 50 files in 24 hours catches bulk sync while ignoring normal single-file sync operations
- Correlate with device compliance from sign-in logs. If the syncing user has ONLY unmanaged device sign-ins, confidence is very high.
- Consider blocking OneDrive sync on unmanaged devices via Conditional Access session controls (`Use app enforced restrictions`)

## Tuning Notes

- **Join to device compliance or it does not do what its name says.** Conditional Access sign-in data or Intune enrolment state is what turns this from bulk-download detection into unmanaged-device detection. Without that field the rule cannot distinguish the two cases it exists to separate.
- **Volume and breadth beat volume alone.** One library synced is a device setup. Several libraries the user has never opened before, synced within an hour, is collection. Counting distinct sites touched is a better discriminator than counting files.
- **Correlate with the leaver process.** The same pattern from an account with a notice period recorded against it is a different proposition, and that context sits in HR data rather than the audit log.
- **Expect a permanent baseline, not a clean state.** Sync is a product feature in daily use, so this rule reports on a busy surface and needs a threshold set from your own tenant.

## Learn More

- [M365 Security Architecture: Data Protection](https://ridgelinecyber.com/training/courses/m365-security-architecture/). sync controls and session restrictions
- [SOC Operations: Cloud Exfiltration Investigation](https://ridgelinecyber.com/training/courses/m365-security-operations/). investigating data theft via cloud storage
