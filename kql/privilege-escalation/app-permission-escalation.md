# Application Permission Escalation — Credential and Grant Addition

Detects when new credentials (secrets or certificates) are added to an existing application or service principal, or when new high-risk API permissions are granted. These are the two primary methods for escalating application privileges in Entra ID.

## ATT&CK

- **Technique:** T1098.001 — Account Manipulation: Additional Cloud Credentials, T1550.001 — Use Alternate Authentication Material: Application Access Token
- **Tactic:** Privilege Escalation, Persistence

## Severity

**High.** Adding credentials to an application gives the attacker a persistent, non-interactive authentication method that bypasses Conditional Access and MFA. The credentials work until explicitly revoked — password resets have no effect.

## Data Sources

- Entra ID Audit Logs — `AuditLogs` table in Sentinel
- Requires: Entra ID P1 or P2 for complete audit logging

## Query — Sigma

```yaml
title: Application Permission Escalation - Credential and Grant
id: det-soc-027
status: production
description: |
  Detects credential addition to service principal combined
  with permission grant on the same application. Application
  hijacking for persistence via T1098.001. Three-table
  correlation: AuditLogs (cred + grant) + MicrosoftGraphActivityLogs
  (new endpoint access).
author: Ridgeline Cyber Detection Engineering
date: 2026/05/17
tags:
  - attack.persistence
  - attack.t1098.001
  - attack.privilege_escalation
  - attack.t1078.004
logsource:
  product: azure
  service: auditlogs
detection:
  selection_creds:
    OperationName:
      - 'Add service principal credentials'
      - 'Update application – Certificates and secrets management'
  selection_perms:
    OperationName:
      - 'Add app role assignment to service principal'
      - 'Add delegated permission grant'
  condition: selection_creds or selection_perms
falsepositives:
  - Application registration updates during deployment cycles
  - Service principal credential rotation (automated)
level: high
```

## What Triggers This

An attacker with Application Administrator, Cloud Application Administrator, or application owner permissions:

1. **Adds a client secret** to an existing application — creates a password credential the attacker uses to authenticate as the application via client_credentials flow
2. **Adds a certificate** to an existing application — same as above but using certificate-based authentication (harder to detect in token logs)
3. **Grants new API permissions** — adds Mail.ReadWrite, Files.ReadWrite.All, or other high-risk permissions to an application that previously had limited scope

The attacker then authenticates as the application using the new credential, inheriting all the application's permissions without triggering user-based Conditional Access policies.

## False Positives

1. **Application development.** Developers add credentials during app registration and secret rotation. Correlate with development team accounts and approved CI/CD service principals.
2. **Secret rotation.** Automated secret rotation adds new credentials before removing old ones. This produces paired add/remove events within a short window.
3. **Managed identity configuration.** Azure managed identities may trigger credential-related audit events during resource provisioning.

## Tuning Notes

- **Application inventory.** Maintain a list of sanctioned applications with their expected permission sets. Credential additions to applications not in the inventory are high priority.
- **Permission delta.** Alert specifically when the newly granted permissions are more privileged than the application's existing permissions — that's escalation, not maintenance.
- **Sentinel deployment:** NRT rule. Application credential operations are low volume and high impact.

## Validation

1. Register a test application in Entra ID
2. Add a client secret through the Azure Portal
3. Verify the detection fires and captures the application name, credential type, and admin who added it
4. Delete the test application and secret

## Learn More

- [Entra ID Security — Application Governance](https://ridgelinecyber.com/training/courses/entra-id-security/) — application identity architecture, consent framework, and credential monitoring
- [SOC Operations — Cloud & SaaS Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/) — cloud application investigation playbook
