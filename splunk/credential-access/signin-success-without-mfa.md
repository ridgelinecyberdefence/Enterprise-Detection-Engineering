# Sign-In Success Without MFA — Single-Factor Cloud Access

Detects successful Entra ID sign-ins where multi-factor was not satisfied. Single-factor success on an account that should require MFA points to a Conditional Access gap, a legacy-auth path, or an attacker reaching a resource that escapes the MFA policy.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts, T1556.006 — Modify Authentication Process: Multi-Factor Authentication
- **Tactic:** Credential Access, Defense Evasion

## Severity

**High.** A password alone reaching a sensitive resource is the exposure MFA is meant to close. It is Critical for a privileged account or a high-value application.

## Data Sources

- Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure — `sourcetype="azure:monitor:aad"`, `category="SignInLogs"`
- Requires: `mfa` and `app` fields populated; an `identity` lookup for privilege context

## Query

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" action="success" mfa="false"
| stats count AS signins, values(app) AS apps, values(src_country) AS country, dc(src_ip) AS distinct_ips by user
| lookup identity user AS user OUTPUT department, privileged
| where privileged="true" OR signins >= 5
| sort - signins
```

## What Triggers This

A success that skipped the second factor:

- `mfa=false` on a successful sign-in to a protected application
- A privileged account authenticating single-factor
- An application that should be MFA-gated appearing in `apps`

## False Positives

1. **Legitimate MFA exemptions.** Trusted-location or compliant-device policies can satisfy access without an interactive MFA prompt. Confirm the policy intent.
2. **Service and automation accounts.** Some non-interactive flows record no MFA. Allowlist known service principals.
3. **Legacy clients in transition.** Apps mid-migration to modern auth. Track and remediate rather than alert long-term.

## Tuning Notes

- **Scope to what must be protected.** Focus on privileged users and high-value apps; raw single-factor volume is high in many tenants.
- **Pair with Conditional Access state.** Combine with `conditional_access_status` to separate a deliberate exemption from a genuine gap.
- **Surface legacy auth.** Filter on legacy client apps to drive an MFA-enforcement remediation backlog.

## Validation

1. In a test tenant, sign in to an app with a user excluded from MFA, or use a legacy-auth client.
2. Confirm the user surfaces with `mfa=false` and the app listed.

## Learn More

- [Splunk Detection and Incident Response — Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — MFA-gap detection and Conditional Access correlation
- [Detection Engineering — Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — authentication-strength detections
