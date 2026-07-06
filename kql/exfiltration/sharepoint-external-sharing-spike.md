# Cloud Exfiltration: SharePoint External Sharing Spike

Detects a sudden increase in external file sharing from SharePoint Online and OneDrive. A compromised account or insider threat shares sensitive files with external email addresses. The cloud equivalent of copying data to a USB drive.

## ATT&CK

- **Technique:** T1567.002. Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **Tactic:** Exfiltration

## Severity

**High.** External sharing of company files is the primary cloud exfiltration vector. If the sharing account is already flagged as compromised, escalate to Critical.

## Data Sources

- Microsoft 365 Unified Audit Log, `OfficeActivity` table
- Requires: SharePoint Online audit logging enabled

## Query

```kql
let TimePeriod = 24h;
let BaselinePeriod = 14d;
let SharingThreshold = 10;
let BaselineMultiplier = 3;
// Current period sharing
let CurrentSharing = OfficeActivity
| where TimeGenerated > ago(TimePeriod)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where Operation in ("SharingSet", "AddedToSecureLink", "AnonymousLinkCreated",
                       "CompanyLinkCreated", "SecureLinkCreated", "SharingInvitationCreated")
| where TargetUserOrGroupType == "Guest" or TargetUserOrGroupName has "@"
| where TargetUserOrGroupName !endswith "@contoso.com"  // adjust to your domain
| summarize
    CurrentShareCount = count(),
    ExternalRecipients = make_set(TargetUserOrGroupName, 20),
    SharedFiles = make_set(SourceFileName, 20),
    SharedSites = dcount(Site_),
    DistinctIPs = make_set(ClientIP, 5)
    by UserId;
// Baseline period sharing
let BaselineSharing = OfficeActivity
| where TimeGenerated between (ago(BaselinePeriod) .. ago(TimePeriod))
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where Operation in ("SharingSet", "AddedToSecureLink", "AnonymousLinkCreated",
                       "CompanyLinkCreated", "SecureLinkCreated", "SharingInvitationCreated")
| where TargetUserOrGroupType == "Guest" or TargetUserOrGroupName has "@"
| where TargetUserOrGroupName !endswith "@contoso.com"
| summarize
    BaselineDailyAvg = round(count() * 1.0 / 14, 1)
    by UserId;
// Compare
CurrentSharing
| join kind=leftouter BaselineSharing on UserId
| extend BaselineDailyAvg = coalesce(BaselineDailyAvg, 0.0)
| where CurrentShareCount >= SharingThreshold
    or CurrentShareCount > BaselineDailyAvg * BaselineMultiplier
| extend AnomalyRatio = iff(BaselineDailyAvg > 0,
    round(CurrentShareCount / BaselineDailyAvg, 1), 999.0)
| project
    UserId,
    CurrentShareCount,
    BaselineDailyAvg,
    AnomalyRatio,
    ExternalRecipients,
    SharedFiles,
    SharedSites,
    DistinctIPs
| sort by AnomalyRatio desc
```

## What Triggers This

A user shares 10+ files externally in 24 hours, or shares at 3x their normal daily rate. The detection catches both absolute volume spikes and relative anomalies against the user's own baseline.

## False Positives

1. **Project handoffs.** Legitimate external collaboration spikes during vendor onboarding or project deliverables. Check if the recipient domain is a known partner.
2. **Marketing and sales.** Teams that regularly share collateral externally. Build per-team baselines and exclude known high-sharing roles.
3. **Automated workflows.** Power Automate or third-party tools that generate sharing events. Exclude by `ClientIP` or `UserAgent` after verification.

## Tuning Notes

- Adjust `@contoso.com` to your organization's domain(s). Include all accepted domains.
- The `BaselineMultiplier` of 3 catches meaningful spikes while tolerating normal variation. Lower to 2 for high-sensitivity environments.
- Anonymous link creation (`AnonymousLinkCreated`) is the highest-risk operation. Consider a separate lower-threshold rule for these.
- Combine with DLP: if the shared files match a DLP sensitive information type, escalate.

## Validation

1. From a test account, create external sharing links for 12 test documents to an external test address
2. Verify the detection fires and captures the user, file list, recipients, and anomaly ratio
3. Remove the test sharing links

## Learn More

- [SOC Operations: Data Protection Alerts](https://ridgelinecyber.com/training/courses/m365-security-operations/). SharePoint and OneDrive exfiltration investigation
- [M365 Security Architecture: Information Protection](https://ridgelinecyber.com/training/courses/m365-security-architecture/). external sharing controls and DLP integration
