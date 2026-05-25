# Audit Log Gap Detection — Extended Period Without Events

Detects gaps in Entra ID audit and sign-in logging that may indicate log tampering, data connector failures, or an attacker who has disabled or diverted logging. If your SIEM stops receiving logs for 4+ hours and nobody notices, you have a blind spot the attacker can operate in freely.

## ATT&CK

- **Technique:** T1562.008 — Impair Defenses: Disable or Modify Cloud Logs
- **Tactic:** Defense Evasion

## Severity

**High.** A logging gap means your detection coverage is zero for the duration. Every other detection in your library is useless during a gap. Whether the cause is infrastructure failure or attacker manipulation, the impact is the same — you can't see what happened.

## Data Sources

- Entra ID Audit Logs — `AuditLogs` table
- Entra ID Sign-in Logs — `SigninLogs` table
- Sentinel ingestion health — `SentinelHealth` table (if available)
- Requires: Baseline log volume for comparison

## Query — KQL (Sentinel)

```kql
let lookback = 24h;
let gap_threshold = 4h;
let bin_size = 1h;
// Stage 1: Hourly event volume for audit and sign-in logs
let auditVolume = AuditLogs
| where TimeGenerated > ago(lookback)
| summarize AuditCount = count() by bin(TimeGenerated, bin_size)
| extend LogType = "AuditLogs";
let signinVolume = SigninLogs
| where TimeGenerated > ago(lookback)
| summarize SigninCount = count() by bin(TimeGenerated, bin_size)
| extend LogType = "SigninLogs";
// Stage 2: Generate expected time bins and find gaps
let expectedBins = range TimeGenerated from ago(lookback) to now() step bin_size
| extend Expected = 1;
// Stage 3: Left join to find missing bins
let auditGaps = expectedBins
| join kind=leftouter (auditVolume) on TimeGenerated
| extend AuditCount = coalesce(AuditCount, 0)
| where AuditCount == 0
| project GapStart = TimeGenerated, GapType = "AuditLogs";
let signinGaps = expectedBins
| join kind=leftouter (signinVolume) on TimeGenerated
| extend SigninCount = coalesce(SigninCount, 0)
| where SigninCount == 0
| project GapStart = TimeGenerated, GapType = "SigninLogs";
// Stage 4: Identify consecutive gaps exceeding threshold
let allGaps = union auditGaps, signinGaps
| order by GapType asc, GapStart asc
| serialize
| extend PrevGap = prev(GapStart), PrevType = prev(GapType)
| extend IsConsecutive = iff(GapType == PrevType and (GapStart - PrevGap) == bin_size, 1, 0)
| extend GapGroup = row_cumsum(iff(IsConsecutive == 0, 1, 0))
| summarize
    GapStartTime = min(GapStart),
    GapEndTime = max(GapStart) + bin_size,
    ConsecutiveHours = count()
    by GapType, GapGroup
| where ConsecutiveHours >= toint(gap_threshold / bin_size)
| project
    GapType,
    GapStartTime,
    GapEndTime,
    GapDurationHours = ConsecutiveHours,
    Severity = case(
        ConsecutiveHours >= 12, "Critical",
        ConsecutiveHours >= 8, "High",
        "Medium"
    )
| sort by GapStartTime desc;
// Stage 5: Volume anomaly — current hour vs 7-day baseline
let baseline = AuditLogs
| where TimeGenerated between(ago(7d) .. ago(lookback))
| summarize AvgHourly = count() / (7.0 * 24) ;
let currentHour = AuditLogs
| where TimeGenerated > ago(1h)
| summarize CurrentCount = count();
let volumeAnomaly = baseline
| extend CurrentCount = toscalar(currentHour | project CurrentCount)
| extend DropPercent = round((1.0 - toreal(CurrentCount) / max_of(AvgHourly, 1)) * 100, 1)
| where DropPercent > 80;
union allGaps, (volumeAnomaly | project GapType = "VolumeAnomaly",
    GapStartTime = ago(1h), GapEndTime = now(),
    GapDurationHours = 1, Severity = "High")
```

## Why This Detection Is Effective

Most detection programs focus on what's in the logs. This detection focuses on what's missing. An attacker with Global Admin can modify diagnostic settings to stop sending logs to your SIEM. A data connector failure produces the same symptom — no alerts fire because there's nothing to fire on.

The two-layer approach catches both scenarios:
1. **Gap detection** — consecutive hours with zero events in a table that normally has continuous activity. Entra ID tenants with 100+ users generate sign-in events every minute. Zero events for 4+ hours is abnormal.
2. **Volume anomaly** — current hour event volume compared to 7-day baseline. An 80%+ drop indicates partial log loss even if some events are still flowing.

## What Triggers This

- **Attacker scenario:** Attacker with Global Admin modifies Azure Monitor diagnostic settings to remove the Log Analytics workspace destination, or disables the Entra ID data connector in Sentinel
- **Infrastructure scenario:** Data connector auth token expires, Log Analytics workspace reaches capacity limit, or network path between Entra ID and the workspace is disrupted
- **Configuration scenario:** Someone modifies the diagnostic settings during maintenance and forgets to restore them

## False Positives

1. **Planned maintenance windows.** Sentinel workspace maintenance, data connector updates, or diagnostic setting migrations. Document maintenance windows and suppress alerts during them.
2. **Low-activity tenants.** Small tenants (< 50 users) may have legitimate gaps during overnight hours. Adjust `gap_threshold` upward for small tenants or exclude overnight hours.
3. **New workspace.** A freshly configured workspace or newly enabled data connector will have historical gaps. Suppress for the first 48 hours after connector setup.

## Tuning Notes

- **Gap threshold.** 4 hours is appropriate for tenants with 100+ users. Increase to 8 hours for small tenants. Decrease to 2 hours for high-security tenants where any gap is unacceptable.
- **Add data connector health.** If `SentinelHealth` is available, add a check for data connector status changes alongside the volume analysis.
- **Multi-table coverage.** Extend to `OfficeActivity`, `SecurityEvent`, and other critical tables. A gap in all tables simultaneously is an infrastructure issue. A gap in only `AuditLogs` while other tables flow normally is suspicious.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. This is a meta-detection — it monitors the health of your detection infrastructure.

## Response

1. **Check diagnostic settings immediately.** Azure Portal → Entra ID → Diagnostic settings. Verify the Log Analytics workspace destination is configured and enabled.
2. **Check data connector status.** Sentinel → Data connectors → Microsoft Entra ID. Verify the connector is active and recently synced.
3. **If settings were modified:** Determine who modified them and when. Check `AzureActivity` logs for diagnostic settings changes during the gap window.
4. **If infrastructure failure:** Restore the connector and verify log flow resumes. Audit what happened during the gap by querying Entra ID directly (Graph API audit logs) for events during the missing window.
5. **Backfill if possible.** Some data connectors support historical ingestion. Backfill the gap period to restore detection coverage retroactively.

## Learn More

- [Detection Engineering — Detection Architecture](https://training.ridgelinecyber.com/courses/detection-engineering/) — log pipeline health monitoring and coverage measurement
- [SOC Operations](https://training.ridgelinecyber.com/courses/m365-security-operations/) — SIEM data connector management and log source validation
- [M365 Security Architecture](https://training.ridgelinecyber.com/courses/m365-security-architecture/) — diagnostic settings architecture and log routing design
