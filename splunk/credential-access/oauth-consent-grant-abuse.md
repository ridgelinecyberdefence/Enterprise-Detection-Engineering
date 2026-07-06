# OAuth Consent Grant Abuse: Illicit Application Authorization

Detects users granting OAuth consent to applications, surfacing the high-risk and admin-consent cases that consent-phishing relies on. An attacker who tricks a user (or admin) into consenting to a malicious app gets a standing, MFA-free token to mailbox, files, or directory data that survives a password reset.

## ATT&CK

- **Technique:** T1528, Steal Application Access Token
- **Tactic:** Credential Access

## Severity

**High.** A consented app holds durable delegated or application permissions that no password change revokes. Admin consent or mail and directory scopes make it Critical.

## Data Sources

- Entra ID audit logs via the Splunk Add-on for Microsoft Azure, `sourcetype="azure:monitor:aad"`, `category="AuditLogs"`
- Requires: directory audit logging; an `identity` lookup for grantor context

## Query

```spl
sourcetype="azure:monitor:aad" category="AuditLogs"
    (operationName="Consent to application" OR operationName="Add OAuth2PermissionGrant"
     OR operationName="Add delegated permission grant" OR operationName="Add app role assignment to service principal")
| stats count AS grants, values(operationName) AS operations, values(targetResource) AS app,
        values(result) AS result, min(_time) AS first_seen, max(_time) AS last_seen by initiatedBy
| lookup identity user AS initiatedBy OUTPUT department, privileged
| sort - grants
```

## What Triggers This

A consent grant that opens standing access:

- A user consenting to an application, especially one not seen before in the tenant
- An admin-consent operation, which grants tenant-wide permissions in one step
- Mail, files, or directory scopes in the grant, the permissions consent-phishing targets

## False Positives

1. **Sanctioned app rollouts.** IT consenting to approved applications. Allowlist known app IDs and the admin-consent workflow.
2. **Routine user consent.** Users consenting to vetted productivity apps. Baseline the normal app set and surface the unseen ones.
3. **Marketplace and SSO apps.** Onboarding of approved SaaS. Confirm against the app catalogue.

## Tuning Notes

- **Weight the scopes.** Enrich with the requested permissions and escalate mail, files, and directory scopes; low-risk profile scopes are usually benign.
- **Surface unseen apps.** Compare the app ID against the tenant's historical consent set so new applications stand out.
- **Escalate admin consent.** Treat tenant-wide admin consent as the highest-severity case regardless of app.

## Validation

1. In a test tenant, consent to a low-risk test application as a standard user.
2. Confirm the grant surfaces with the operation and app captured.

## Learn More

- [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). OAuth consent abuse and application-permission risk
- [Entra ID Security](https://ridgelinecyber.com/training/courses/entra-id-security/). consent governance and application risk
