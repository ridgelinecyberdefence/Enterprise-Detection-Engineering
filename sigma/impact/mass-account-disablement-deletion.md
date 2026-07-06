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
  # Sigma doesn't natively support aggregation — implement as correlation rule
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

## Tuning Notes

- Threshold of 5 accounts in 1 hour minimizes false positives from individual offboarding while catching destructive attacks
- Exclude known lifecycle automation service accounts by `InitiatedBy` after verifying their expected behavior
- For the Sigma rule, implement the aggregation in your SIEM's correlation engine (5+ events from same `SubjectUserName` in 10 minutes)

## Learn More

- [Incident Response: Destructive Attack Response](https://ridgelinecyber.com/training/courses/practical-ir/). containment and recovery from destructive attacks
- [Entra ID Security: Admin Account Protection](https://ridgelinecyber.com/training/courses/entra-id-security/). protecting administrative accounts from compromise
