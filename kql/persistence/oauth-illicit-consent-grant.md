# Illicit OAuth Application Consent — High-Risk Permissions

Detects consent grants to OAuth applications requesting permissions that enable persistent data access. Consent phishing creates API access that survives password resets and MFA re-enrollment.

## ATT&CK

- **Technique:** T1098.003 — Account Manipulation: Additional Cloud Credentials
- **Tactic:** Persistence, Credential Access

## Severity

**High.** An OAuth application with `Mail.ReadWrite` or `Files.ReadWrite.All` has persistent, silent access to user data through the Graph API. The user sees no sign-in prompts. The attacker reads email and exfiltrates files through API calls that bypass Conditional Access entirely.

## Data Sources

- Entra ID Audit Logs — `AuditLogs` table in Sentinel
- Requires: Entra ID P1 or P2 license for complete audit logging
- Alternative: Microsoft 365 Unified Audit Log via `OfficeActivity`

## Query — KQL (Sentinel)

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Consent to application"
| extend ConsentedApp = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any (
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory"
)
| project
    TimeGenerated,
    ConsentedBy,
    ConsentedApp,
    AppId,
    Permissions,
    OperationName,
    CorrelationId
| sort by TimeGenerated desc
```

## What Triggers This

A user grants an OAuth application access to their data (or an admin grants tenant-wide consent). The detection fires when the granted permissions include capabilities commonly abused by attackers:

- **Mail.ReadWrite / Mail.Send** — read, modify, and send email as the user
- **Files.ReadWrite.All** — access all files the user can see in SharePoint and OneDrive
- **Application.ReadWrite.All** — register and modify applications in the tenant (privilege escalation)
- **Directory.ReadWrite.All** — modify directory objects including users and groups
- **RoleManagement.ReadWrite.Directory** — assign directory roles (direct path to Global Admin)

The consent grant is the persistence mechanism. Once granted, the application accesses data through the Graph API using its own tokens. The user's password, MFA, and Conditional Access policies do not apply to application API calls.

## False Positives

1. **Legitimate business applications.** Microsoft Power Platform, third-party SaaS integrations, and internal LOB apps may request broad permissions. Validate the application ID against your tenant's app inventory before excluding.
2. **Admin consent for known applications.** IT teams granting admin consent to approved SaaS tools. These should be pre-approved through a formal consent workflow, not ad-hoc user consent.
3. **Microsoft first-party apps.** Some Microsoft services request broad permissions during setup. Filter by checking whether the AppId is in the Microsoft first-party application list.

## Tuning Notes

- **Permission scope:** The permission list above covers the most dangerous Graph API scopes. Add or remove permissions based on your organization's risk tolerance. `Sites.ReadWrite.All` generates more noise in SharePoint-heavy environments.
- **User vs admin consent:** Consider splitting into two rules — one for user consent (higher urgency, users should rarely grant these permissions) and one for admin consent (lower urgency but still requires validation).
- **Application allowlist:** Maintain a watchlist of approved application IDs. Add a `| where AppId !in (allowlist)` filter after validating each application.
- **Sentinel deployment:** NRT (Near Real-Time) rule recommended. Consent grants are low-volume, high-impact events. Entity mapping: `ConsentedBy` as Account, `AppId` as custom entity.

## Validation

1. Register a test application in Entra ID (App registrations)
2. Add `Mail.ReadWrite` as a delegated permission
3. Sign in as a test user and consent to the application
4. Verify the detection fires and captures the application name, permissions, and consenting user
5. Remove the test application after validation

## Learn More

- [SOC Operations — Cloud & SaaS Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/) — consent phishing investigation playbook
- [Entra ID Security — Application Governance](https://ridgelinecyber.com/training/courses/entra-id-security/) — consent framework architecture and controls
