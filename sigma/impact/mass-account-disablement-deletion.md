# Mass Account Disablement or Deletion

Detects bulk account disablement or deletion events that indicate destructive action against Active Directory or Entra ID user accounts. An attacker with Domain Admin or Global Admin privileges can disable or delete user accounts to disrupt business operations, a destructive impact technique.

## ATT&CK

- **Technique:** T1531, Account Access Removal
- **Tactic:** Impact

## Severity

**Critical.** Mass account manipulation by a single admin session indicates either a destructive attack or a catastrophic misconfiguration. Either requires immediate investigation and potential rollback.

## Data Sources

- Windows Security Event Log. Event IDs 4725 (account disabled), 4726 (account deleted)
- Entra ID Audit Logs, `AuditLogs`

## Detection

```yaml
title: Mass Account Disablement or Deletion
id: 6f4a2c81-e3b7-42d9-8a15-b7c9d3e84f21
status: experimental
description: >
  Detects multiple account disable or delete operations from a single
  source within a short time window. Indicates destructive impact or
  catastrophic admin error.
references:
  - https://attack.mitre.org/techniques/T1531/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.impact
  - attack.t1531
logsource:
  product: windows
  service: security
detection:
  selection_disable:
    EventID: 4725
  selection_delete:
    EventID: 4726
  condition: selection_disable or selection_delete
  # Aggregate in SIEM: 5+ events from the same SubjectUserName within 10 minutes
  # Sigma doesn't natively support aggregation, implement as correlation rule
falsepositives:
  - Bulk deprovisioning during organizational restructuring
  - Scripted cleanup of stale accounts by IT
  - Automated lifecycle management tools (Okta, SailPoint)
level: critical
```

## KQL Supplement (Entra ID)

```kql
let TimePeriod = 1h;
let Threshold = 5;
AuditLogs
| where TimeGenerated > ago(TimePeriod)
| where OperationName in ("Disable account", "Delete user", "Hard Delete user")
| summarize
    ActionCount = count(),
    AffectedAccounts = make_set(tostring(TargetResources[0].userPrincipalName), 50),
    Operations = make_set(OperationName),
    FirstAction = min(TimeGenerated),
    LastAction = max(TimeGenerated)
    by InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where ActionCount >= Threshold
| extend DurationMin = datetime_diff("minute", LastAction, FirstAction)
| project
    InitiatedBy,
    ActionCount,
    Operations,
    DurationMin,
    AffectedAccounts
| sort by ActionCount desc
```

## What Triggers This

Accounts being disabled or deleted in volume, from Windows security event logs. The rule matches the disablement and deletion events; the impact comes from the count rather than any single event.

This is destruction rather than access. It appears in ransomware operations that remove administrator accounts to slow recovery, and in insider incidents at the point of departure.

## False Positives

1. **Joiner-mover-leaver automation.** HR-driven identity lifecycle tooling disables and deletes accounts in batches on a schedule, and on a large organisation that batch can be substantial. This is the dominant producer and it is entirely legitimate.
2. **Contractor and seasonal offboarding,** which arrives as a single large batch at predictable points in the year.
3. **Directory cleanup projects.** Stale account removal is a normal hygiene exercise and looks identical to destruction.
4. **Test and service account teardown** at the end of a project or environment decommission.

## Tuning Notes

- Threshold of 5 accounts in 1 hour minimizes false positives from individual offboarding while catching destructive attacks
- Exclude known lifecycle automation service accounts by `InitiatedBy` after verifying their expected behavior
- For the Sigma rule, implement the aggregation in your SIEM's correlation engine (5+ events from same `SubjectUserName` in 10 minutes)

## Tuning Notes

- **The threshold is the rule.** A single disablement is routine; the question is how many in what window is abnormal for you, and that depends entirely on your headcount and joiner-leaver rate. Take a month of counts before setting it.
- **Exclude the identity automation account, and alert if it stops.** The lifecycle tool will always be the top producer, so it has to come out. Its silence is also worth knowing about, since an attacker who disables it has removed your baseline.
- **Actor matters more than volume.** The lifecycle service performing bulk disablement is normal; a named administrator account doing it outside a change window is not, at any volume. Splitting the rule by actor type is more effective than tuning the count.
- **Pair it with the recovery view.** Mass disablement alongside backup deletion or shadow copy removal is a ransomware pattern rather than an offboarding batch, and the combination is far more specific than either.
- **Conversion:** `sigma convert -t splunk -p windows sigma/impact/mass-account-disablement-deletion.yml`

## Learn More

- [Incident Response: Destructive Attack Response](https://ridgelinecyber.com/training/courses/practical-ir/). containment and recovery from destructive attacks
- [Entra ID Detection and Operations](https://ridgelinecyber.com/training/courses/entra-id-detection-operations/)
