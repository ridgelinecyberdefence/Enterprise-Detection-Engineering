# Cross-Tenant Guest Account — Elevated Activity

Detects external guest accounts (B2B collaboration users) performing privileged operations or accessing sensitive resources beyond their expected scope. Guest accounts are a common blind spot — they bypass your hiring, onboarding, and identity vetting processes, yet can be granted the same permissions as internal users.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts
- **Tactic:** Lateral Movement, Privilege Escalation

## Severity

**High.** A guest account performing admin operations, accessing SharePoint sites outside their designated collaboration scope, or being assigned privileged roles indicates either a misconfiguration (guest has too much access) or a compromised guest account being used for lateral movement from a partner tenant into yours.

## Data Sources

- Entra ID Sign-in Logs — `SigninLogs` table
- Entra ID Audit Logs — `AuditLogs` table
- Microsoft 365 Unified Audit Log — `OfficeActivity` table
- Requires: Entra ID P1 or P2, guest user sign-in logging enabled

## Query — KQL (Sentinel)

```kql
let lookback = 24h;
// Stage 1: Guest sign-ins with elevated activity indicators
let guestSignins = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| where UserType == "Guest"
| extend GuestUPN = UserPrincipalName
| extend HomeTenant = HomeTenantId
| extend GuestIP = IPAddress
| extend GuestLocation = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion);
// Stage 2: Guest accounts performing admin/privileged operations
let guestAdminOps = AuditLogs
| where TimeGenerated > ago(lookback)
| where InitiatedBy has "#EXT#"
    or InitiatedBy has "guest"
| where OperationName has_any (
    "Add member to role",
    "Add owner to application",
    "Add owner to service principal",
    "Update application",
    "Add service principal credentials",
    "Consent to application",
    "Update conditional access policy",
    "Add user",
    "Invite external user",
    "Update user"
)
| extend GuestUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetResource = tostring(TargetResources[0].displayName)
| project
    TimeGenerated,
    GuestUPN,
    OperationName,
    TargetResource,
    Category = "Admin Operation";
// Stage 3: Guest accounts accessing high-value SharePoint sites
let guestFileAccess = OfficeActivity
| where TimeGenerated > ago(lookback)
| where UserId has "#EXT#" or UserId has "guest"
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where Operation in ("FileDownloaded", "FileAccessed", "FileModified",
    "FolderAccessed", "ListViewed")
| summarize
    FileOps = count(),
    UniqueSites = dcount(Site_Url),
    SiteList = make_set(Site_Url, 10),
    SampleFiles = make_set(SourceFileName, 10)
    by UserId
| where FileOps > 50 or UniqueSites > 3
| extend Category = "High Volume File Access"
| project
    TimeGenerated = now(),
    GuestUPN = UserId,
    OperationName = strcat("SharePoint: ", FileOps, " operations across ", UniqueSites, " sites"),
    TargetResource = strcat(SiteList),
    Category;
// Combine all guest elevated activity
union guestAdminOps, guestFileAccess
| join kind=leftouter (
    guestSignins
    | summarize
        SigninCount = count(),
        GuestIPs = make_set(GuestIP, 5),
        GuestLocations = make_set(GuestLocation, 5),
        HomeTenant = take_any(HomeTenant)
        by GuestUPN
) on GuestUPN
| project
    TimeGenerated,
    GuestUPN,
    HomeTenant,
    Category,
    OperationName,
    TargetResource,
    GuestIPs,
    GuestLocations,
    SigninCount
| sort by Category asc, TimeGenerated desc
```

## Why This Detection Is Effective

Guest accounts are the weakest link in most tenants' identity perimeter. They are:
- **Not subject to your password policies** — the guest's password is managed by their home tenant
- **Not covered by your MFA enrollment** — MFA is enforced by Conditional Access, but many tenants don't apply CA policies to guests
- **Not monitored by your SOC** — guest sign-ins often aren't included in standard detection rules that filter for `UserType == "Member"`
- **Not vetted by your HR process** — anyone with an email address can be invited as a guest

When a partner organization is compromised, the attacker inherits access to every tenant where that organization's users are guests. This is cross-tenant lateral movement — the attacker pivots from a compromised partner into your tenant using a legitimate guest identity.

## What Triggers This

1. An attacker compromises a user account in a partner organization
2. That user is a guest in your tenant with access to shared resources
3. The attacker signs in using the compromised guest account
4. The attacker performs operations beyond the guest's expected scope — accessing admin portals, modifying applications, downloading files across multiple sites
5. The detection identifies the guest account performing privileged operations or accessing resources at anomalous volume

## False Positives

1. **External consultants with admin roles.** Some organizations grant admin roles to external consultants (security assessors, M365 migration partners). These should be time-bounded, documented, and using dedicated accounts — not personal guest accounts.
2. **Cross-tenant application management.** Multi-tenant ISV partners managing their application registrations in your tenant. Validate the ISV relationship and the specific operations.
3. **Collaborative project work.** External team members accessing shared SharePoint sites at high volume during project deadlines. The `UniqueSites > 3` threshold helps distinguish project work (1-2 sites) from broad exploration.

## Tuning Notes

- **Guest role audit.** Before tuning this detection, audit which guest accounts have privileged roles: `Get-MgDirectoryRoleMember -DirectoryRoleId <role-id> | Where-Object { $_.UserType -eq "Guest" }`. Any guest with admin roles should be investigated regardless of whether this detection fires.
- **SharePoint site sensitivity.** Consider enriching with site sensitivity labels. Guest access to a "Confidential" or "Highly Confidential" labeled site is higher risk than access to a "General" collaboration site.
- **Conditional Access for guests.** If your CA policies don't apply to guest users, fix that first. Require MFA and compliant devices for guest access. This reduces the risk and makes detection more effective.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. Entity mapping: `GuestUPN` as Account, `GuestIPs` as IP.

## Response

1. **Block the guest account.** Set the guest user's account status to blocked in Entra ID → Users → Guest user → Block sign-in.
2. **Contact the home tenant.** Notify the partner organization that their user's account may be compromised. They need to investigate on their side.
3. **Audit the guest's access.** Review everything the guest account accessed during the current sign-in window — files, emails, admin operations, and OAuth consents.
4. **Review guest access policies.** If a guest account had admin roles or broad SharePoint access, review whether that access was appropriate and revoke excessive permissions.
5. **Audit all guests from the same tenant.** If one guest from a partner is compromised, other guests from the same organization may also be affected. Check all guest accounts with the same `HomeTenantId`.

## Learn More

- [Entra ID Security — External Identities](https://ridgelinecyber.com/training/courses/entra-id-security/) — B2B collaboration security, guest access governance, and cross-tenant access settings
- [Identity and Access Management](https://ridgelinecyber.com/training/courses/identity-access-management/) — guest lifecycle management and access reviews
- [SOC Operations](https://ridgelinecyber.com/training/courses/m365-security-operations/) — cross-tenant investigation methodology
