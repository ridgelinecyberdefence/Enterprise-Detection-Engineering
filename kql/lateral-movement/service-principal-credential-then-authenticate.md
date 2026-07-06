# Service Principal Credential Addition with Immediate API Activity

Detects when a new credential (secret or certificate) is added to a service principal or application, followed by Graph API or Azure Resource Manager activity from that application within 60 minutes. This two-stage pattern. Add credential, then authenticate as the application, is the primary persistence and lateral movement technique for cloud-native attacks in Entra ID.

## ATT&CK

- **Technique:** T1098.001. Account Manipulation: Additional Cloud Credentials, T1550.001, Use Alternate Authentication Material: Application Access Token
- **Tactic:** Persistence, Lateral Movement

## Severity

**Critical.** The two-stage pattern (credential addition followed by application authentication) has almost zero legitimate occurrences outside of planned CI/CD deployments. In the context of a compromised admin account, this is the attacker establishing application-level persistence that survives user password resets, MFA re-enrollment, and session revocation.

## Data Sources

- Entra ID Audit Logs. `AuditLogs` table (credential addition events)
- Entra ID Service Principal Sign-in Logs, `AADServicePrincipalSignInLogs` table (application authentication)
- Optional: Microsoft Graph Activity Logs for detailed API call analysis
- Requires: Entra ID P1 or P2, Service Principal sign-in logging enabled

## Query: KQL (Sentinel)

```kql
let lookback = 24h;
let correlation_window = 60m;
// Stage 1: Credential additions to applications or service principals
let credentialAdditions = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in (
    "Add service principal credentials",
    "Update application – Certificates and secrets management"
)
| extend AppObjectId = tostring(TargetResources[0].id)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AddedBy = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName)
)
| extend AddedByIP = tostring(InitiatedBy.user.ipAddress)
| extend CredentialType = case(
    AdditionalDetails has "Certificate", "Certificate",
    AdditionalDetails has "Password", "ClientSecret",
    "Unknown"
)
| project
    CredentialAddedTime = TimeGenerated,
    AppObjectId,
    AppName,
    AddedBy,
    AddedByIP,
    CredentialType,
    CorrelationId;
// Stage 2: Service principal sign-ins within the correlation window
let appAuthentications = AADServicePrincipalSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| extend AppId = tostring(ServicePrincipalId)
| project
    AuthTime = TimeGenerated,
    AppId,
    AppName = ServicePrincipalName,
    AuthIPAddress = IPAddress,
    ResourceDisplayName,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion);
// Correlate: credential added, then app authenticates within 60 minutes
credentialAdditions
| join kind=inner (appAuthentications) on $left.AppName == $right.AppName
| where AuthTime between (CredentialAddedTime .. (CredentialAddedTime + correlation_window))
| project
    CredentialAddedTime,
    AppName,
    AddedBy,
    AddedByIP,
    CredentialType,
    AuthTime,
    TimeDelta = datetime_diff('minute', AuthTime, CredentialAddedTime),
    AuthIPAddress,
    ResourceDisplayName,
    Location
| sort by CredentialAddedTime desc
```

## Why This Detection Is Effective

Application credentials in Entra ID are the cloud equivalent of service account passwords. But worse. An application with `Mail.ReadWrite.All` and a client secret can read every mailbox in the tenant through the Graph API. The authentication uses client_credentials flow, which:

- Does not trigger MFA
- Is not evaluated by most Conditional Access policies (Conditional Access for workload identities requires P2 + Workload Identities Premium)
- Does not appear in user sign-in logs (only service principal sign-in logs)
- Persists until the credential is explicitly deleted (default secret lifetime: 2 years)

The credential-then-authenticate pattern is the strongest signal because legitimate application credential rotations are planned operations that typically happen during deployment windows, not followed by immediate API activity from unfamiliar IPs. The 60-minute correlation window catches the attacker's immediate use of the new credential while excluding scheduled credential rotations that happen days before the next deployment.

## What Triggers This

1. Attacker compromises an account with Application Administrator, Cloud Application Administrator, or application owner permissions
2. Attacker adds a new client secret or certificate to an existing high-privilege application (e.g., one with `Mail.ReadWrite.All`, `Directory.ReadWrite.All`)
3. Within 60 minutes, the attacker authenticates as the application using the new credential from attacker-controlled infrastructure
4. The attacker calls Graph API endpoints to read email, enumerate users, or modify directory objects

The detection correlates the AuditLog credential addition event with the ServicePrincipalSignInLog authentication event, proving the new credential was used immediately. Not stored for future legitimate use.

## False Positives

1. **CI/CD pipeline deployments.** Automated pipelines may add credentials and immediately authenticate for deployment. These run from known IP ranges with known service principal names. Exclude by `AddedBy` (the CI/CD service principal) and `AuthIPAddress` (your CI/CD runner IP range).
2. **Application secret rotation scripts.** Automated rotation adds a new secret, tests authentication, then removes the old secret. The test authentication triggers the correlation. Exclude by the rotation service principal identity.
3. **Developer testing.** Developers adding credentials to test apps and immediately testing authentication. Correlate with development team accounts and non-production application names.

## Tuning Notes

- **Correlation window.** 60 minutes is the default. Reduce to 15 minutes for higher fidelity (attackers typically use the credential within minutes). Increase to 4 hours if your deployment pipelines have longer gaps between credential provisioning and first use.
- **IP comparison.** Add a filter for `AddedByIP != AuthIPAddress` to focus on cases where the credential was added from one location and used from another, the strongest signal.
- **Application permission baseline.** Cross-reference the application's permissions. A credential addition to an app with `User.Read` is low risk. The same operation on an app with `Mail.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` is critical.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. NRT is not possible due to the correlation window requirement. Entity mapping: `AddedBy` as Account, `AppName` as custom entity, `AuthIPAddress` as IP.

## Validation

1. Register a test application in a test tenant with `User.Read` permissions only
2. Add a client secret through the Azure Portal
3. Within 10 minutes, authenticate using the secret:
   ```bash
   curl -X POST "https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token" \
     -d "client_id={appId}&scope=https://graph.microsoft.com/.default&client_secret={secret}&grant_type=client_credentials"
   ```
4. Verify the detection fires and captures both the credential addition and the authentication
5. Delete the test application and secret

## Response

1. **Revoke the credential immediately.** Remove the added secret or certificate from the application in Entra ID → App registrations → Certificates & secrets.
2. **Review application permissions.** Check what the application has access to. If it has mail, file, or directory write permissions, assume the attacker used them.
3. **Check application activity.** Query `AADServicePrincipalSignInLogs` and Microsoft Graph Activity Logs for all activity from this application in the last 7 days.
4. **Investigate the adding account.** The `AddedBy` field shows which account added the credential. This account is compromised or the credential addition was authorized. Determine which.
5. **Audit all application credentials.** The attacker may have added credentials to multiple applications. Run an audit across all applications for recently added secrets and certificates.

## References

- Microsoft Incident Response: Application identity compromise patterns in M365 tenant attacks
- Thomas Naunheim: [Token Hunting for Workload Identities](https://www.cloud-architekt.net/token-hunting-workload-identity-activity/) (January 2026)
- MITRE ATT&CK: [T1098.001](https://attack.mitre.org/techniques/T1098/001/). Additional Cloud Credentials

## Learn More

- [Entra ID Security: Application Governance](https://ridgelinecyber.com/training/courses/entra-id-security/). application identity architecture, consent framework, and credential lifecycle management
- [Identity and Access Management: Non-Human Identity Governance](https://ridgelinecyber.com/training/courses/identity-access-management/). service principal security, workload identity protection, and monitoring
- [Detection Engineering: Cloud Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). building detections for application-level attack techniques
