# Bulk SharePoint and OneDrive Download: Volume Anomaly

Detects users or applications downloading an anomalous volume of files from SharePoint Online or OneDrive for Business within a short time window. This is the data collection phase of an attack. The attacker has access and is exfiltrating documents, intellectual property, or sensitive data before they lose access.

## ATT&CK

- **Technique:** T1213.002. Data from Information Repositories: SharePoint, T1530, Data from Cloud Storage Object
- **Tactic:** Collection

## Severity

**High.** Bulk file downloads from a compromised account indicate active data exfiltration. The window between download and data loss is minutes. If the account was compromised via AiTM or token theft, the attacker is racing to collect data before the token expires or sessions are revoked.

## Data Sources

- Microsoft 365 Unified Audit Log, `OfficeActivity` table in Sentinel
- Requires: SharePoint audit logging enabled (default in E3/E5)
- Enhanced: `CloudAppEvents` (Defender for Cloud Apps) for additional file operation context

## Query: KQL (Sentinel)

```kql
let lookback = 24h;
let baseline_days = 14;
let anomaly_multiplier = 10;
let min_file_count = 50;
// Stage 1: Current download activity per user
let currentActivity = OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")
| where OfficeWorkload in ("SharePoint", "OneDrive")
| summarize
    DownloadCount = count(),
    UniqueFiles = dcount(OfficeObjectId),
    UniqueSites = dcount(Site_Url),
    TotalSizeMB = round(sum(toreal(coalesce(OfficeObjectId_size, 0))) / 1048576, 1),
    SourceIPs = make_set(ClientIP, 5),
    SampleFiles = make_set(SourceFileName, 10),
    SampleSites = make_set(Site_Url, 5),
    FirstDownload = min(TimeGenerated),
    LastDownload = max(TimeGenerated)
    by UserId
| where DownloadCount >= min_file_count;
// Stage 2: Baseline — normal download volume per user
let userBaseline = OfficeActivity
| where TimeGenerated between(ago(baseline_days + 1d) .. ago(1d))
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| where OfficeWorkload in ("SharePoint", "OneDrive")
| summarize BaselineDaily = count() / toreal(baseline_days) by UserId;
// Stage 3: Identify anomalous users
currentActivity
| join kind=leftouter (userBaseline) on UserId
| extend BaselineDaily = coalesce(BaselineDaily, 0.0)
| extend Multiplier = iff(BaselineDaily > 0,
    round(toreal(DownloadCount) / BaselineDaily, 1), 999.0)
| where Multiplier >= anomaly_multiplier or BaselineDaily == 0
// Stage 4: Enrich with sign-in risk
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == 0
    | where RiskLevelDuringSignIn in ("medium", "high")
    | summarize HasRiskySignin = count() by UserPrincipalName
) on $left.UserId == $right.UserPrincipalName
| extend HasRiskySignin = coalesce(HasRiskySignin, 0)
| extend RiskContext = case(
    HasRiskySignin > 0, "ELEVATED — user has risky sign-ins today",
    BaselineDaily == 0, "NO BASELINE — user has never downloaded at this volume",
    "Anomalous volume vs baseline"
)
| project
    UserId,
    DownloadCount,
    UniqueFiles,
    UniqueSites,
    TotalSizeMB,
    Multiplier,
    BaselineDaily = round(BaselineDaily, 1),
    RiskContext,
    SourceIPs,
    SampleFiles,
    SampleSites,
    FirstDownload,
    LastDownload,
    DurationMin = datetime_diff('minute', LastDownload, FirstDownload)
| sort by Multiplier desc
```

## Why This Detection Is Effective

Traditional DLP focuses on what's in the files. This detection focuses on the behavioral anomaly. A user who normally downloads 5 files per day suddenly downloading 500. The content of the files doesn't matter for detection purposes; the volume anomaly is the signal.

The baseline comparison eliminates the most common false positive: power users. A sales director who downloads 100 files daily has a baseline of 100. They won't trigger the detection unless they download 1,000. A standard user with a baseline of 3 triggers at 30 downloads.

The sign-in risk enrichment adds critical context. A volume anomaly from a user with no risky sign-ins might be a legitimate project deadline. The same anomaly from a user flagged for AiTM phishing or impossible travel is almost certainly attacker-driven exfiltration.

## What Triggers This

1. Attacker compromises a user account (AiTM, credential stuffing, token theft)
2. Attacker accesses SharePoint/OneDrive through the web interface, Graph API, or OneDrive sync client
3. Attacker downloads files systematically. Navigating site by site, downloading document libraries
4. The download volume exceeds 10x the user's normal daily baseline
5. The detection flags the anomaly with the user's download count, file list, and risk context

## False Positives

1. **OneDrive sync client initial setup.** When a user sets up OneDrive sync on a new device, the initial sync downloads all files. This produces a one-time volume spike. The `FileSyncDownloadedFull` operation captures this. Consider excluding initial sync events for known device provisioning days.
2. **Project deadlines.** Users downloading large volumes for presentations, audits, or deliverables. These typically access files from 1-2 sites (their project sites), not across multiple sites. The `UniqueSites` field helps distinguish project work (1-2 sites) from systematic exfiltration (5+ sites).
3. **Departing employees.** Users leaving the organization may download personal files or project archives. Correlate with HR offboarding data if available.
4. **Automated tools.** Migration tools, backup scripts, or eDiscovery tools operating under user context. These should use service accounts, not user accounts.

## Tuning Notes

- **Anomaly multiplier.** 10x baseline is conservative. Reduce to 5x for higher sensitivity. Increase to 20x in environments with high legitimate download volume.
- **Minimum file count.** 50 files filters out low-volume anomalies that are likely benign (a user who normally downloads 1 file downloading 10). Reduce for high-security environments where any anomaly matters.
- **Site diversity.** Add a filter for `UniqueSites >= 3` to focus on cross-site downloads (systematic exfiltration pattern) versus single-site downloads (likely legitimate project work).
- **Time compression.** Add a filter for `DurationMin < 60` to focus on rapid bulk downloads (attacker-speed) versus slow accumulation over a full day (more likely legitimate).
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. Entity mapping: `UserId` as Account, `SourceIPs` as IP.

## Response

1. **Check the user's sign-in history.** Is there an AiTM, impossible travel, or anomalous sign-in event preceding the downloads?
2. **Revoke sessions** if the account is suspected compromised: `Revoke-MgUserSignInSession`
3. **Review what was downloaded.** The `SampleFiles` and `SampleSites` fields show which documents and sites were accessed. Prioritize: is this sensitive data, IP, or regulated content?
4. **Check for secondary exfiltration.** After downloading, did the user email files externally, upload to a personal cloud storage service, or print? Check `OfficeActivity` for `MailSend` and `FileUploaded` events.
5. **Preserve evidence.** Export the user's audit log for the incident window before the 90-day retention expires.

## Learn More

- [SOC Operations: Cloud & SaaS Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/). SharePoint/OneDrive monitoring and data exfiltration investigation
- [Threat Hunting in Microsoft 365](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). hunting for anomalous file access patterns
- [Detection Engineering](https://ridgelinecyber.com/training/courses/detection-engineering/). baseline-driven anomaly detection design
