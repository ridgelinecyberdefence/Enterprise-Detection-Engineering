# Privileged Role Assignment Outside PIM

Detects direct privileged role assignments in Entra ID that bypass Privileged Identity Management governance controls. Direct assignments create persistent standing access that PIM's time-limited, approval-gated model is designed to prevent.

## ATT&CK

- **Technique:** T1078.004. Valid Accounts: Cloud Accounts, T1098, Account Manipulation
- **Tactic:** Privilege Escalation, Persistence

## Severity

**High.** A direct privileged role assignment outside PIM means either governance controls were intentionally bypassed or an attacker is establishing persistent administrative access. Both require immediate investigation.

## Data Sources

- Entra ID Audit Logs, `AuditLogs` table in Sentinel
- Requires: Entra ID P2 license for PIM functionality

## Query: Sigma

```yaml
title: Privileged Role Assignment Outside PIM
id: det-soc-004
status: production
description: |
  Detects direct privileged role assignments that bypass
  PIM governance controls. Covers both explicit "outside
  PIM" operations and direct "Add member to role" where
  the initiator is not the PIM service.
author: Ridgeline Cyber Detection Engineering
date: 2026/05/17
tags:
  - attack.privilege_escalation
  - attack.t1078.004
  - attack.persistence
  - attack.t1098
logsource:
  product: azure
  service: auditlogs
detection:
  selection_direct_assignment:
    properties.message|contains:
      - 'Add member to role'
      - 'Add eligible member to role'
    properties.initiatedBy.app.displayName|contains: ''
  filter_pim_service:
    properties.initiatedBy.app.displayName:
      - 'MS-PIM'
      - 'Privileged Identity Management'
  selection_privileged_roles:
    properties.targetResources[].displayName|contains|any:
      - 'Global Administrator'
      - 'Privileged Role Administrator'
      - 'Privileged Authentication Administrator'
      - 'Security Administrator'
      - 'Exchange Administrator'
      - 'SharePoint Administrator'
      - 'User Administrator'
      - 'Application Administrator'
      - 'Cloud Application Administrator'
  condition: (selection_direct_assignment and not filter_pim_service) and selection_privileged_roles
falsepositives:
  - Break-glass account activation (should be rare and documented)
  - Initial PIM configuration during tenant setup
  - Automated role assignment via approved governance workflows
level: high
```

## KQL Equivalent (Sentinel)

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName in (
    "Add member to role",
    "Add eligible member to role",
    "Add member to role outside of PIM"
)
| where InitiatedBy !has "MS-PIM"
| extend TargetRole = tostring(TargetResources[0].displayName)
| extend TargetUser = tostring(TargetResources[1].userPrincipalName)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| where TargetRole in (
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator"
)
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser,
    TargetUser,
    TargetRole,
    CorrelationId
```

## What Triggers This

Someone assigns a privileged Entra ID role directly. Through the Azure Portal, Graph API, or PowerShell, without going through the PIM activation workflow. PIM requires justification, optional approval, and time-limits every activation. A direct assignment bypasses all of this and creates persistent standing access.

The detection specifically watches for:
- `Add member to role` where the initiating service is not MS-PIM
- `Add member to role outside of PIM` (explicit audit log operation)
- Assignments to the 9 most dangerous roles (those that can modify security controls, access all data, or escalate to Global Admin)

## False Positives

1. **Break-glass account provisioning.** Emergency access accounts are assigned Global Admin permanently by design. These should be pre-documented. Exclude the specific break-glass UPNs after validating.
2. **Tenant initial configuration.** During initial Entra ID setup, roles are assigned directly before PIM is configured. One-time exclusion window.
3. **Automated governance tools.** Some third-party identity governance platforms assign roles through their own service principal. Validate the service principal and exclude by `InitiatedBy.app.appId` if confirmed legitimate.

## Tuning Notes

- **Role scope.** The 9 roles listed are the most dangerous. Expand to include `Intune Administrator`, `Compliance Administrator`, and `Helpdesk Administrator` if your risk model requires it.
- **PIM service name.** The filter uses "MS-PIM" and "Privileged Identity Management" as the service name. Verify these match your tenant's audit log format. Microsoft occasionally changes the display name.
- **Sentinel deployment:** NRT rule recommended. Direct privileged role assignments are extremely low volume (should be near zero in a mature environment) and extremely high impact. Entity mapping: `InitiatedByUser` and `TargetUser` as Account entities.

## Validation

1. In a test tenant, assign the "Security Reader" role (low risk) directly to a test user through the Entra Admin Center (not through PIM)
2. Verify the detection fires and captures the initiator, target user, and assigned role
3. Remove the role assignment after validation

**Do not test with Global Administrator or Privileged Role Administrator in production.**

## Learn More

- [Entra ID Security: PIM and Privileged Access](https://ridgelinecyber.com/training/courses/entra-id-security/). PIM architecture, governance controls, and detection strategies
- [Identity and Access Management: Role Governance](https://ridgelinecyber.com/training/courses/identity-access-management/). role assignment workflows and monitoring
