# Workload Identity Federation — External Identity Provider Linked

Detects when a federated identity credential is added to an application or service principal, allowing an external identity provider (GitHub Actions, AWS, GCP, or attacker-controlled infrastructure) to authenticate as the application without a stored secret. Workload identity federation is the modern equivalent of adding a client secret — but harder to detect and harder to revoke because no credential is stored in Entra ID.

## ATT&CK

- **Technique:** T1098.001 — Account Manipulation: Additional Cloud Credentials, T1199 — Trusted Relationship
- **Tactic:** Persistence, Privilege Escalation

## Severity

**Critical.** A federated identity credential allows an external system to obtain tokens as the application by presenting a token from the trusted external IdP. If the application has Mail.ReadWrite.All or Directory.ReadWrite.All, the attacker's external infrastructure gains those permissions without any credential stored in Entra ID — nothing to find in a credential audit, nothing to rotate.

## Data Sources

- Entra ID Audit Logs — `AuditLogs` table in Sentinel
- Requires: Entra ID P1 or P2

## Query — KQL (Sentinel)

```kql
let lookback = 7d;
AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in (
    "Update application",
    "Add service principal",
    "Update service principal"
)
| extend ModifiedProps = tostring(TargetResources[0].modifiedProperties)
| where ModifiedProps has_any (
    "FederatedIdentityCredentials",
    "federatedIdentityCredential",
    "SubjectIdentifier",
    "Issuer"
)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
// Extract federation details from modified properties
| extend FedIssuer = extract(@'"Issuer":"([^"]+)"', 1, ModifiedProps)
| extend FedSubject = extract(@'"Subject":"([^"]+)"', 1, ModifiedProps)
| extend FedAudience = extract(@'"Audience":"([^"]+)"', 1, ModifiedProps)
| extend TrustType = case(
    FedIssuer has "token.actions.githubusercontent.com", "GitHub Actions",
    FedIssuer has "accounts.google.com", "GCP",
    FedIssuer has "sts.amazonaws.com", "AWS",
    FedIssuer has "login.microsoftonline.com", "Entra ID (cross-tenant)",
    isnotempty(FedIssuer), strcat("Custom: ", FedIssuer),
    "Unknown"
)
| project
    TimeGenerated,
    OperationName,
    AppName,
    AppId,
    TrustType,
    FedIssuer,
    FedSubject,
    FedAudience,
    InitiatedByUser,
    InitiatedByApp,
    InitiatedByIP,
    ModifiedProps
| sort by TimeGenerated desc
```

## Why This Detection Is Effective

Workload identity federation is a legitimate feature for CI/CD pipelines (GitHub Actions authenticating to Azure without stored secrets). But it's also the most sophisticated persistence mechanism available to an attacker in Entra ID because:

1. **No stored credential.** Standard credential audits (`Get-MgApplication -Property PasswordCredentials`) return nothing. The federation trust is the credential.
2. **External control.** The attacker's infrastructure (a GitHub repo, an AWS account, a custom OIDC provider) issues the tokens. Revoking Entra ID sessions doesn't help — the attacker gets new tokens from their own IdP.
3. **Subject specificity bypass.** If the federation is configured with a broad subject filter (e.g., `repo:org/*` instead of `repo:org/specific-repo:ref:refs/heads/main`), any workflow in any repo in the org can authenticate.
4. **Audit log opacity.** The federation configuration is buried in the `modifiedProperties` field of an `Update application` event. Most SOC teams don't parse this field.

## What Triggers This

1. Attacker gains Application Administrator or application owner permissions
2. Attacker adds a federated identity credential pointing to infrastructure they control:
   ```powershell
   New-MgApplicationFederatedIdentityCredential -ApplicationId <id> -Body @{
       name = "attacker-trust"
       issuer = "https://attacker-oidc.example.com"
       subject = "attacker-subject"
       audiences = @("api://AzureADTokenExchange")
   }
   ```
3. The attacker's OIDC provider issues a token with the matching issuer and subject
4. The attacker exchanges this token for an Entra ID access token via the client_credentials + federated credential flow
5. The detection captures the federation credential addition in the audit log

## False Positives

1. **CI/CD pipeline setup.** DevOps teams configuring GitHub Actions, Azure DevOps, or Terraform Cloud to authenticate to Azure. These are legitimate and should reference known org-owned issuers (your GitHub org URL, your AWS account).
2. **Cross-tenant application access.** Multi-tenant applications using federation for cross-tenant authentication. The issuer will be `login.microsoftonline.com` with a specific tenant ID.
3. **Application migration.** Moving applications between identity providers during infrastructure changes. Temporary and should be coordinated with change management.

## Tuning Notes

- **Issuer allowlist.** Maintain a list of approved federation issuers (your GitHub org, your AWS accounts, your GCP projects). Any issuer not in the list is high priority.
- **Subject specificity.** Flag federation credentials with broad subjects. `repo:myorg/*` is overly permissive. `repo:myorg/deploy-pipeline:ref:refs/heads/main` is appropriately scoped.
- **Application permission correlation.** Cross-reference the target application's permissions. A federation credential added to an app with `User.Read` is low risk. The same on an app with `RoleManagement.ReadWrite.Directory` is a critical alert.
- **Sentinel deployment:** NRT rule. Federation credential changes should be extremely rare. Entity mapping: `InitiatedByUser` as Account, `AppName` as custom entity.

## Response

1. **Verify the federation trust.** Contact the application owner. Is this a planned CI/CD integration?
2. **If unauthorized: remove the federated identity credential immediately.**
   ```powershell
   Remove-MgApplicationFederatedIdentityCredential -ApplicationId <id> -FederatedIdentityCredentialId <credId>
   ```
3. **Audit the application's recent activity.** Check `AADServicePrincipalSignInLogs` for authentications using the federated credential.
4. **Review the application's permissions.** What could the attacker access through this application?
5. **Investigate the initiating account.** The account that added the federation is compromised or the addition was unauthorized.

## References

- Microsoft: [Workload Identity Federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation)
- Microsoft Incident Response: Federation-based persistence in tenant compromise scenarios
- MITRE ATT&CK: [T1098.001](https://attack.mitre.org/techniques/T1098/001/)

## Learn More

- [Entra ID Security — Application Identity](https://ridgelinecyber.com/training/courses/entra-id-security/) — workload identity architecture, federation, and credential lifecycle
- [Identity and Access Management — Non-Human Identity](https://ridgelinecyber.com/training/courses/identity-access-management/) — service principal security and federation governance
