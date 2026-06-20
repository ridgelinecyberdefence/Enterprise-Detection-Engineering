# MailItemsAccessed Volume Spike — Bulk Mailbox Exfiltration

Detects anomalous spikes in mailbox item access using the MailItemsAccessed audit event, which logs every individual email read operation. An attacker with a compromised mailbox or OAuth token systematically reads email at a rate that far exceeds the user's normal pattern — hundreds or thousands of items accessed via Graph API or OWA within minutes.

## ATT&CK

- **Technique:** T1114.002 — Email Collection: Remote Email Collection
- **Tactic:** Collection

## Severity

**Critical.** MailItemsAccessed with anomalous volume from a compromised account means the attacker is actively reading email. In BEC scenarios, the attacker reads email to identify payment workflows, vendor relationships, and internal processes before launching the fraud. Every email read is potential intelligence for the attacker.

## Data Sources

- Microsoft 365 Advanced Audit — `OfficeActivity` table (MailItemsAccessed operation)
- Requires: Microsoft 365 E5 or E5 Compliance add-on (MailItemsAccessed requires Advanced Audit)
- Note: MailItemsAccessed is only available with E5 licensing. E3 tenants do not log this event.

## Query — KQL (Sentinel)

```kql
let lookback = 24h;
let baseline_days = 14;
let volume_threshold = 200;
let anomaly_multiplier = 5;
// Stage 1: Current MailItemsAccessed volume per user
let currentAccess = OfficeActivity
| where TimeGenerated > ago(lookback)
| where Operation == "MailItemsAccessed"
| where ResultStatus == "Succeeded"
| extend AccessMethod = case(
    ClientInfoString has "Client=OWA", "Outlook Web",
    ClientInfoString has "Client=Microsoft Outlook", "Outlook Desktop",
    ClientInfoString has "Client=ActiveSync", "ActiveSync",
    ClientInfoString has "Client=Other", "Graph API/Other",
    "Unknown"
)
| summarize
    ItemsAccessed = count(),
    UniqueIPs = dcount(ClientIP),
    AccessMethods = make_set(AccessMethod),
    SourceIPs = make_set(ClientIP, 10),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated),
    // Detect bind vs sync — bind is interactive reading, sync is background
    BindCount = countif(OperationProperties has "Bind"),
    SyncCount = countif(OperationProperties has "Sync")
    by UserId
| where ItemsAccessed >= volume_threshold;
// Stage 2: Baseline comparison
let accessBaseline = OfficeActivity
| where TimeGenerated between(ago(baseline_days + 1d) .. ago(1d))
| where Operation == "MailItemsAccessed"
| where ResultStatus == "Succeeded"
| summarize BaselineDaily = count() / toreal(baseline_days) by UserId;
// Stage 3: Anomaly detection
currentAccess
| join kind=leftouter (accessBaseline) on UserId
| extend BaselineDaily = coalesce(BaselineDaily, 0.0)
| extend Multiplier = iff(BaselineDaily > 0,
    round(toreal(ItemsAccessed) / BaselineDaily, 1), 999.0)
| where Multiplier >= anomaly_multiplier or BaselineDaily == 0
// Stage 4: Risk enrichment
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == 0
    | where RiskLevelDuringSignIn in ("medium", "high")
    | summarize RiskySignins = count() by UserPrincipalName
) on $left.UserId == $right.UserPrincipalName
// Stage 5: Check for OAuth app access (non-user Graph API access)
| join kind=leftouter (
    OfficeActivity
    | where TimeGenerated > ago(lookback)
    | where Operation == "MailItemsAccessed"
    | where ClientInfoString has "Client=Other"
    | summarize GraphAPICalls = count() by UserId
) on UserId
| extend RiskLevel = case(
    coalesce(RiskySignins, 0) > 0 and Multiplier > 20, "Critical — risky sign-in + extreme volume",
    coalesce(GraphAPICalls, 0) > 100, "Critical — bulk Graph API mailbox access",
    Multiplier > 50, "High — extreme volume anomaly",
    Multiplier > 10, "High — significant volume anomaly",
    "Medium — elevated volume"
)
| project
    UserId,
    ItemsAccessed,
    Multiplier,
    BaselineDaily = round(BaselineDaily, 1),
    RiskLevel,
    AccessMethods,
    BindCount,
    SyncCount,
    GraphAPICalls = coalesce(GraphAPICalls, 0),
    UniqueIPs,
    SourceIPs,
    RiskySignins = coalesce(RiskySignins, 0),
    FirstAccess,
    LastAccess,
    DurationMin = datetime_diff('minute', LastAccess, FirstAccess)
| sort by Multiplier desc
```

## Why This Detection Is Effective

MailItemsAccessed is the most granular email monitoring signal available in M365. Unlike `MessageBind` (which only logs Outlook client access), MailItemsAccessed captures every email read event across all access methods — Outlook desktop, OWA, mobile, Graph API, ActiveSync, and third-party IMAP clients.

The critical distinction is **Bind vs Sync**:
- **Bind** = a client opened a specific email and read it (interactive access)
- **Sync** = a client synchronized a folder (background activity)

High Bind counts with low Sync counts indicate systematic reading — the attacker is opening and reading individual emails. High Sync counts are typically legitimate clients doing background folder sync.

The Graph API detection layer (`Client=Other`) catches a pattern that's increasingly common: the attacker uses an OAuth application token to call `GET /users/{id}/messages` and reads the entire mailbox through the API without ever opening Outlook. This produces MailItemsAccessed events with no associated interactive sign-in.

## What Triggers This

1. Attacker compromises a user account or obtains an OAuth token with Mail.Read/Mail.ReadWrite
2. Attacker systematically reads the mailbox — searching for payment information, credentials, sensitive communications
3. Access volume spikes to 5x+ the user's normal daily baseline
4. The detection identifies the anomaly and enriches with sign-in risk and Graph API correlation

## False Positives

1. **Outlook initial folder sync.** Configuring Outlook on a new device triggers a large sync. High SyncCount, low BindCount. The Bind/Sync ratio helps distinguish this from attacker behavior.
2. **Mobile device mailbox sync.** ActiveSync devices downloading email after being offline. Produces periodic spikes from known mobile IPs.
3. **eDiscovery searches.** Compliance officers running content searches read many items. These operate under eDiscovery service accounts, not user accounts.
4. **Email migration.** Migrating mailboxes between tenants or to/from on-premises Exchange produces high-volume access. Coordinate with migration teams and time-bound exclusions.

## Tuning Notes

- **Volume threshold.** 200 items/day catches most exfiltration. Executives who receive 200+ emails daily may need a higher threshold or individual baseline calibration.
- **Graph API focus.** For highest-fidelity alerting, create a separate NRT rule that fires only when `Client=Other` (Graph API) MailItemsAccessed exceeds 100 items. Legitimate users rarely read email through the Graph API.
- **Bind ratio.** Add a filter for `BindCount > SyncCount` to focus on interactive reading patterns. Attacker behavior is bind-heavy (reading specific emails); sync-heavy patterns are typically legitimate client activity.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. Create a separate NRT rule for Graph API access (Client=Other) above 100 items. Entity mapping: `UserId` as Account, `SourceIPs` as IP.

## Response

1. **Determine access method.** Graph API access (`Client=Other`) without a corresponding interactive sign-in indicates an OAuth token or compromised application — revoke OAuth grants, not just user sessions.
2. **Revoke user sessions and OAuth grants:**
   ```powershell
   Revoke-MgUserSignInSession -UserId <UPN>
   Get-MgUserOauth2PermissionGrant -UserId <UPN> | Remove-MgOauth2PermissionGrant
   ```
3. **Identify what was read.** MailItemsAccessed includes folder and item references. Determine whether the attacker accessed specific high-value folders (Inbox, Sent Items) or searched for specific keywords.
4. **Check for downstream BEC.** After reading email, did the attacker send messages? Check for outbound email with payment keywords, forwarding rule creation, or reply-chain hijacking.
5. **Notify affected parties.** If the attacker read email containing sensitive data about third parties (clients, vendors, partners), notification obligations may apply.

## References

- Microsoft: [MailItemsAccessed Mailbox Auditing](https://learn.microsoft.com/en-us/purview/audit-mailitemsaccessed)
- Microsoft Incident Response: MailItemsAccessed analysis in BEC investigations
- MITRE ATT&CK: [T1114.002](https://attack.mitre.org/techniques/T1114/002/)

## Learn More

- [SOC Operations — Investigation Playbooks](https://ridgelinecyber.com/training/courses/m365-security-operations/) — BEC investigation methodology using MailItemsAccessed
- [Detection Engineering — Email Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — building detections for email collection techniques
- [Threat Hunting in Microsoft 365](https://ridgelinecyber.com/training/courses/threat-hunting-m365/) — hunting for mailbox access anomalies
