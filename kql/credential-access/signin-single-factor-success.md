# Single-Factor Sign-In Success — MFA Not Satisfied

Detects successful sign-ins that completed with single-factor authentication. A password alone reaching a protected resource points to a Conditional Access gap, a legacy-auth path, or an attacker reaching an application that escapes the MFA policy.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts, T1556.006 — Modify Authentication Process: Multi-Factor Authentication
- **Tactic:** Credential Access, Defense Evasion

## Severity

**High.** A password alone reaching a sensitive resource is the exposure MFA exists to close. It is Critical for a privileged account or a high-value application.

## Data Sources

- Entra ID Sign-in Logs — `SigninLogs` and `AADNonInteractiveUserSignInLogs` in Sentinel
- Requires: Entra ID P1; `AuthenticationRequirement` populated

## Query — KQL (Sentinel)

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| where AuthenticationRequirement == "singleFactorAuthentication"
| summarize
    Signins = count(),
    Apps = make_set(AppDisplayName, 10),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5),
    DistinctIPs = dcount(IPAddress)
    by UserPrincipalName
| sort by Signins desc
```

## What Triggers This

A success that skipped the second factor:

- `AuthenticationRequirement == "singleFactorAuthentication"` on a successful sign-in
- A privileged account authenticating single-factor
- An application that should be MFA-gated appearing in `Apps`

## False Positives

1. **Trusted-location or compliant-device policies.** These can satisfy access without an interactive MFA prompt. Confirm the policy intent before treating as a gap.
2. **Service and automation accounts.** Some non-interactive flows record single-factor. Allowlist known service principals.
3. **Legacy clients in transition.** Apps mid-migration to modern auth. Track and remediate rather than alert indefinitely.

## Tuning Notes

- **Scope to what must be protected.** Focus on privileged users and high-value apps; raw single-factor volume is high in many tenants.
- **Pair with Conditional Access state.** Combine with `ConditionalAccessStatus` to separate a deliberate exemption from a genuine gap.
- **Surface legacy auth.** Filter on legacy client apps to drive an MFA-enforcement remediation backlog.

## Validation

1. In a test tenant, sign in to an app with a user excluded from MFA, or via a legacy-auth client.
2. Confirm the user surfaces with single-factor success and the app listed.

## Learn More

- [Entra ID Security — Conditional Access](https://ridgelinecyber.com/training/courses/entra-id-security/) — MFA enforcement and policy-gap analysis
- [Detection Engineering — Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — authentication-strength detections
