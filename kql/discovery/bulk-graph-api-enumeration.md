# Bulk Graph API Enumeration: User, Group, and Role Discovery

Detects applications or service principals performing high-volume Microsoft Graph API calls to enumerate users, groups, roles, and directory objects. Attackers use Graph API enumeration to map the tenant's organizational structure, identify high-value targets, and plan privilege escalation paths. The cloud equivalent of running BloodHound against Active Directory.

## ATT&CK

- **Technique:** T1087.004. Account Discovery: Cloud Account, T1069.003, Permission Groups Discovery: Cloud Groups
- **Tactic:** Discovery

## Severity

**Medium.** Some applications legitimately call Graph API at high volume (HR sync, identity governance, monitoring tools). The detection flags anomalous volume from applications that don't normally enumerate the directory. Escalates to High when the calling application was recently granted permissions or uses newly added credentials.

## Data Sources

- Microsoft Graph Activity Logs. `MicrosoftGraphActivityLogs` table (requires Entra ID P1/P2 + diagnostic settings configured for Graph activity)
- Entra ID Sign-in Logs. `AADServicePrincipalSignInLogs` for application authentication context
- Alternative: Microsoft Cloud App Security. `CloudAppEvents` for Graph API activity if Graph Activity Logs aren't configured

## Query: KQL (Sentinel)

```kql
let lookback = 24h;
let call_threshold = 500;
let enum_paths = dynamic([
    "/users", "/groups", "/directoryRoles",
    "/roleManagement", "/servicePrincipals",
    "/applications", "/administrativeUnits",
    "/groupMembers", "/appRoleAssignments",
    "/oauth2PermissionGrants", "/domains"
]);
// Stage 1: High-volume Graph API calls to enumeration endpoints
let enumActivity = MicrosoftGraphActivityLogs
| where TimeGenerated > ago(lookback)
| where RequestMethod == "GET"
| extend NormalizedPath = tolower(replace_regex(RequestUri, @'/[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}', '/{id}'))
| extend NormalizedPath = replace_regex(NormalizedPath, @'\?.*$', '')
| where NormalizedPath has_any (enum_paths)
| summarize
    TotalCalls = count(),
    UniqueEndpoints = dcount(NormalizedPath),
    EndpointList = make_set(NormalizedPath, 15),
    ResponseCodes = make_set(ResponseStatusCode, 10),
    FirstCall = min(TimeGenerated),
    LastCall = max(TimeGenerated),
    CallerIPs = make_set(IPAddress, 5)
    by AppId, ServicePrincipalId
| where TotalCalls >= call_threshold;
// Stage 2: Baseline — is this normal for this application?
let appBaseline = MicrosoftGraphActivityLogs
| where TimeGenerated between(ago(30d) .. ago(lookback))
| where RequestMethod == "GET"
| extend NormalizedPath = tolower(replace_regex(RequestUri, @'/[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}', '/{id}'))
| where NormalizedPath has_any (enum_paths)
| summarize BaselineDailyAvg = count() / 30.0 by AppId;
// Stage 3: Identify anomalous apps — current volume >> baseline
enumActivity
| join kind=leftouter (appBaseline) on AppId
| extend BaselineDailyAvg = coalesce(BaselineDailyAvg, 0.0)
| extend VolumeMultiplier = iff(BaselineDailyAvg > 0,
    round(toreal(TotalCalls) / BaselineDailyAvg, 1), 999.0)
| where VolumeMultiplier > 5.0 or BaselineDailyAvg == 0
// Stage 4: Enrich with application identity
| join kind=leftouter (
    AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(lookback)
    | summarize
        AppName = take_any(ServicePrincipalName),
        AuthIPs = make_set(IPAddress, 5)
        by ServicePrincipalId
) on ServicePrincipalId
| project
    AppName = coalesce(AppName, AppId),
    AppId,
    TotalCalls,
    UniqueEndpoints,
    EndpointList,
    VolumeMultiplier,
    BaselineDailyAvg,
    CallerIPs,
    FirstCall,
    LastCall,
    EnumDurationMin = datetime_diff('minute', LastCall, FirstCall)
| sort by VolumeMultiplier desc
```

## Why This Detection Is Effective

Standard identity detections focus on authentication anomalies. This detection targets what the attacker does after authentication. The reconnaissance phase that precedes privilege escalation and data access.

Graph API enumeration is the cloud equivalent of LDAP reconnaissance in on-prem AD. The attacker maps:
- **Users**. Who exists, what attributes they have, who is privileged
- **Groups**. Organizational structure, security group membership, dynamic groups
- **Roles**. Who has Global Admin, who has Application Admin, what custom roles exist
- **Applications**. What apps are registered, what permissions they have, which ones have secrets
- **Administrative Units**. Scoped admin boundaries that reveal organizational segmentation

The 30-day baseline comparison is critical. An HR sync application that calls `/users` 10,000 times daily is normal. The same volume from an application that previously made 0 calls is a compromised application or a newly weaponized credential.

## What Triggers This

1. Attacker compromises an application credential or OAuth token
2. Attacker uses the token to call Graph API endpoints to enumerate the directory
3. The enumeration produces hundreds or thousands of GET requests to user/group/role endpoints within hours
4. The detection identifies the volume spike against the application's baseline

Alternatively: attacker creates a new application, grants it Directory.Read.All, and immediately begins enumeration. The application has zero baseline, any volume is anomalous.

## False Positives

1. **Identity governance platforms.** SailPoint, Saviynt, and similar tools enumerate the directory continuously. These have consistent baselines and won't trigger the multiplier threshold.
2. **New application onboarding.** A newly deployed application making its first directory sync. The zero-baseline check flags this. Validate the application and add to baseline after confirmation.
3. **Audit and compliance tools.** Tools that periodically audit directory configuration (weekly or monthly) produce volume spikes on schedule. Identify the schedule and exclude or create a separate lower-severity rule.
4. **Migration tools.** Tenant-to-tenant migration tools enumerate the source directory. Time-bounded and documented.

## Tuning Notes

- **Call threshold.** 500 calls/day catches aggressive enumeration. Reduce to 100 for higher sensitivity (in small tenants) or increase to 2000 for large enterprise tenants with many legitimate high-volume apps.
- **Volume multiplier.** 5x baseline catches significant anomalies. Reduce to 3x for higher sensitivity. The `999.0` value for zero-baseline apps ensures new apps always trigger the detection.
- **Endpoint weighting.** Not all enumeration is equal. Calls to `/directoryRoles` and `/roleManagement` are higher risk than calls to `/users`. Consider a weighted scoring system in v2.
- **Sentinel deployment:** Scheduled rule, 4-hour frequency. Entity mapping: `AppName` as custom entity, `CallerIPs` as IP entities.

## Response

1. **Identify the application.** What is it, who owns it, and what permissions does it have?
2. **Check for recent credential additions.** Was a new secret or federated credential added to this application in the last 7 days? If so, the credential is likely compromised.
3. **Review the enumeration scope.** The `EndpointList` shows what the application queried. Roles and applications indicate privilege escalation reconnaissance. Users and groups indicate target identification.
4. **Revoke the application's credentials** if unauthorized. Remove secrets, certificates, and federated identity credentials.
5. **Audit subsequent activity.** After enumeration, did the application make write calls (POST/PATCH/DELETE)? Check for role assignments, permission grants, or user modifications.

## Learn More

- [Entra ID Security: Application Governance](https://ridgelinecyber.com/training/courses/entra-id-security/). Graph API permissions, application monitoring, and consent governance
- [Threat Hunting in Microsoft 365](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). hunting for anomalous application behavior and API abuse
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). building detections for Graph API-based attack techniques
