# New Federation Trust or Domain Added to Tenant

Detects when a new federated domain or federation trust is configured in an Entra ID tenant. Adding a federation trust allows the attacker to authenticate as any user in the tenant without knowing their password. The attacker's identity provider issues tokens that Entra ID accepts as legitimate. This is the most powerful persistence mechanism available in Entra ID.

## ATT&CK

- **Technique:** T1484.002. Domain or Tenant Policy Modification: Trust Modification, T1199, Trusted Relationship
- **Tactic:** Persistence, Privilege Escalation

## Severity

**Critical.** A malicious federation trust gives the attacker the equivalent of a skeleton key for the entire tenant. They forge SAML tokens for any user. Including Global Administrators, without triggering password-based or MFA-based detection. The trust persists until explicitly removed. This technique was used in the SolarWinds attack (SUNBURST) for persistent tenant access.

## Data Sources

- Entra ID Audit Logs, `AuditLogs` table in Sentinel
- Requires: Entra ID P1 or P2 for audit logging
- Enhanced: Microsoft Defender for Cloud Apps for additional cloud activity context

## Query: KQL (Sentinel)

```kql
let lookback = 7d;
// Stage 1: Federation trust and domain events
let federationEvents = AuditLogs
| where TimeGenerated > ago(lookback)
| where OperationName in (
    "Set federation settings on domain",
    "Set domain authentication",
    "Add unverified domain",
    "Add verified domain",
    "Set company information",
    "Set DirSyncEnabled flag",
    "Add application",
    "Update application"
)
| extend ModifiedProperty = tostring(TargetResources[0].modifiedProperties)
| where ModifiedProperty has_any (
    "FederationBrandName",
    "IssuerUri",
    "MetadataExchangeUri",
    "PassiveSignInUri",
    "FederatedIdpMfaBehavior",
    "SigningCertificate",
    "TrustType",
    "DomainAuthentication"
)
    OR OperationName in (
    "Add unverified domain",
    "Add verified domain",
    "Set federation settings on domain"
)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetDomain = tostring(TargetResources[0].displayName);
// Stage 2: Check if the initiator account shows other compromise indicators
let initiatorRisk = SigninLogs
| where TimeGenerated > ago(lookback)
| where UserPrincipalName in (
    federationEvents | project InitiatedByUser | where isnotempty(InitiatedByUser)
)
| where RiskLevelDuringSignIn in ("medium", "high")
| summarize RiskSignins = count() by UserPrincipalName;
// Final output
federationEvents
| join kind=leftouter (initiatorRisk) on $left.InitiatedByUser == $right.UserPrincipalName
| project
    TimeGenerated,
    OperationName,
    InitiatedByUser,
    InitiatedByApp,
    InitiatedByIP,
    TargetDomain,
    ModifiedProperty,
    RiskSignins = coalesce(RiskSignins, 0),
    CorrelationId
| sort by TimeGenerated desc
```

## Why This Detection Is Effective

Federation trust modification is one of the rarest operations in Entra ID. Most tenants configure federation once (during initial ADFS setup) and never touch it again. Any federation change outside a planned migration is either a misconfiguration or an attack.

The SolarWinds attack demonstrated why this matters: the attackers used `Set-MsolDomainAuthentication` to add a rogue federation trust, then forged SAML tokens to access the tenant as any user. The forged tokens were indistinguishable from legitimate ADFS-issued tokens. MFA, Conditional Access, and Entra ID Protection did not flag the authentication because the token was technically valid.

This detection catches:
- **New domain addition**. The first step in establishing a federation trust (attacker adds a domain they control)
- **Federation configuration changes**. Setting IssuerUri, signing certificates, or passive sign-in URLs for a domain
- **Authentication method changes**. Switching a domain from managed to federated
- **Signing certificate rotation**. Replacing the federation trust's signing certificate (allows the attacker to issue tokens with the new certificate)

The enrichment with the initiator's sign-in risk signals identifies cases where the admin account that made the change was itself compromised.

## What Triggers This

1. Attacker gains Global Administrator or Privileged Role Administrator access (typically through AiTM phishing, token theft, or credential stuffing)
2. Attacker runs: `New-MgDomainFederationConfiguration` or `Set-MsolDomainAuthentication` to configure federation for a domain they control
3. The federation trust points to attacker-controlled infrastructure that issues signed SAML tokens
4. Attacker forges tokens for any user in the tenant, authenticating without passwords or MFA
5. The detection captures the federation configuration change in the audit log

## False Positives

1. **Initial ADFS/PingFederate setup.** First-time federation configuration during identity infrastructure deployment. One-time event, should be coordinated with change management.
2. **Federation certificate rotation.** Annual or biennial rotation of the ADFS token signing certificate. Planned, documented, and typically performed by a known identity admin.
3. **Azure AD Connect configuration.** Changes to directory synchronization settings during hybrid identity setup or troubleshooting. The `Set DirSyncEnabled flag` operation is part of this workflow.
4. **Domain verification for email routing.** Adding and verifying domains for Exchange Online mail flow. These are `Add verified domain` events without federation configuration changes.

## Tuning Notes

- **Alert on every instance.** Federation changes are rare enough that every alert warrants investigation. Do not suppress or auto-close these alerts.
- **Separate new domains from config changes.** A new unverified domain followed by federation configuration is the attack chain. A signing certificate update on an existing federated domain is a rotation. Both warrant review, but the first is higher urgency.
- **Monitor the initiator.** The admin who made the change is either the attacker or was compromised. Cross-reference with sign-in risk, impossible travel, and recent MFA changes for that admin account.
- **Sentinel deployment:** NRT rule. These events should be near-zero in steady state. Any occurrence is worth waking someone up for. Entity mapping: `InitiatedByUser` as Account, `InitiatedByIP` as IP, `TargetDomain` as DNS custom entity.

## Response

1. **Verify the change immediately.** Contact the initiating admin through an out-of-band channel (phone call, not email. The attacker may control their email). Confirm whether they made the change.
2. **If unauthorized: remove the federation trust immediately.** `Remove-MgDomainFederationConfiguration -DomainId <domain>`. Switch the domain back to managed authentication.
3. **Revoke all sessions tenant-wide** for the affected domain's users. Forged tokens from the malicious federation may still be active.
4. **Audit all authentication from the federated domain** during the window the trust was active. Any sign-in through the malicious federation should be treated as attacker access.
5. **Rotate the compromised admin's credentials** and audit all admin actions during the compromise window.
6. **Check for additional persistence**. The attacker likely planted OAuth apps, service principal credentials, or inbox rules alongside the federation trust.

## References

- Microsoft: [SolarWinds: Understanding the Federation Trust Attack](https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#new-federated-identity-provider-added-to-the-directory)
- Mandiant: Golden SAML attack technique analysis
- MITRE ATT&CK: [T1484.002](https://attack.mitre.org/techniques/T1484/002/)
- CISA: Emergency Directive 21-01 (SolarWinds response, federation trust remediation)

## Learn More

- [Entra ID Security: Federation and Trust Architecture](https://ridgelinecyber.com/training/courses/entra-id-security/). SAML federation, token forgery attacks, and trust monitoring
- [M365 Security Architecture](https://ridgelinecyber.com/training/courses/m365-security-architecture/). tenant architecture decisions including federation trust design
- [Identity and Access Management](https://ridgelinecyber.com/training/courses/identity-access-management/). hybrid identity security and federation governance
