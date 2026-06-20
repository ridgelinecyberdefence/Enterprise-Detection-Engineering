# Cloud Permission and Role Enumeration

Detects reconnaissance commands used to enumerate Azure AD roles, group memberships, and administrative permissions. After gaining initial access, attackers enumerate permissions to identify escalation paths — which accounts have Global Admin, which groups grant access to sensitive resources, and what roles are available via PIM.

## ATT&CK

- **Technique:** T1087.004 — Account Discovery: Cloud Account
- **Tactic:** Discovery

## Severity

**Medium.** Permission enumeration is a prerequisite for privilege escalation. On its own it's informational. Combined with other indicators (compromised account, unusual source IP), escalate to High.

## Data Sources

- Sysmon Event ID 1 (ProcessCreate) — for PowerShell-based enumeration
- Microsoft Defender for Endpoint — `DeviceProcessEvents`

## Detection

```yaml
title: Azure AD / Entra ID Role and Permission Enumeration via PowerShell
id: 3d8e4f21-a7c9-4b62-9e13-f5d2a8b74c30
status: experimental
description: >
  Detects PowerShell commands used to enumerate Entra ID roles, group
  memberships, directory roles, and administrative unit membership.
  Common post-compromise reconnaissance activity.
references:
  - https://attack.mitre.org/techniques/T1087/004/
author: Ridgeline Cyber
date: 2025/05/25
tags:
  - attack.discovery
  - attack.t1087.004
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_commands:
    CommandLine|contains:
      - 'Get-MgDirectoryRole'
      - 'Get-MgDirectoryRoleMember'
      - 'Get-MgRoleManagementDirectoryRoleAssignment'
      - 'Get-MgRoleManagementDirectoryRoleEligibilitySchedule'
      - 'Get-MgGroupMember'
      - 'Get-MgUserMemberOf'
      - 'Get-MgPrivilegedAccessRoleAssignment'
      - 'Get-AzureADDirectoryRole'
      - 'Get-AzureADDirectoryRoleMember'
      - 'Get-AzureADGroupMember'
      - 'Get-AzureADUserMembership'
      - 'Get-MsolRole'
      - 'Get-MsolRoleMember'
  condition: selection_process and selection_commands
falsepositives:
  - IT administrators auditing role assignments during access reviews
  - Automated governance scripts for compliance reporting
  - Identity team running access certification workflows
level: medium
```

## What Triggers This

PowerShell execution of Microsoft Graph or AzureAD module commands that enumerate directory roles, role assignments, group membership, and PIM eligibility. This is the attacker mapping the permission landscape to find escalation paths.

## False Positives

1. **IT governance.** Identity teams run access reviews using these exact commands. Correlate with known admin accounts and scheduled maintenance windows.
2. **Compliance automation.** Scripts that generate role assignment reports for auditors. Exclude known service accounts running on schedule.
3. **Security tooling.** CSPM and identity governance tools that audit permissions. Exclude by process parent or service account.

## Tuning Notes

- Multiple enumeration commands from the same session in quick succession is higher confidence than a single command
- Combine with sign-in anomalies: if the account running enumeration commands just had an unusual sign-in (new IP, impossible travel), escalate
- The AzureAD module commands (Get-AzureAD*) are legacy but still common. The Graph module commands (Get-Mg*) are the modern equivalents. Cover both.

## Learn More

- [Entra ID Security — Role Governance](https://ridgelinecyber.com/training/courses/entra-id-security/) — directory role enumeration and monitoring
- [Offensive Security for Defenders — Cloud Reconnaissance](https://ridgelinecyber.com/training/courses/offensive-security-for-defenders/) — how attackers enumerate cloud permissions
- [Identity and Access Management](https://ridgelinecyber.com/training/courses/identity-access-management/) — privilege access management and role assignment monitoring
