# Conditional Access Not Applied: Policy Coverage Gap

Detects sign-ins where Conditional Access evaluated to `notApplied`, meaning no policy governed the authentication. Attackers seek the paths CA does not cover, and a cluster of `notApplied` sign-ins on a sensitive application is a coverage gap worth closing before it is abused.

## ATT&CK

- **Technique:** T1556, Modify Authentication Process
- **Tactic:** Defense Evasion

## Severity

**Medium.** A gap is an exposure rather than an active compromise, so it sits at Medium as a hardening signal. It rises when the gap is on a privileged user or a high-value application.

## Data Sources

- Entra ID Sign-in Logs, `SigninLogs` in Sentinel
- Requires: `ConditionalAccessStatus` populated

## Query: KQL (Sentinel)

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| where ConditionalAccessStatus == "notApplied"
| summarize
    Signins = count(),
    DistinctUsers = dcount(UserPrincipalName),
    UserSet = make_set(UserPrincipalName, 15),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5)
    by AppDisplayName
| where Signins >= 10
| sort by Signins desc
```

## What Triggers This

Authentication that no policy governed:

- `ConditionalAccessStatus == "notApplied"` clustering on one application
- A path consistently escaping policy (a specific app, client, or account type)
- The same gap appearing for privileged users

## False Positives

1. **Intentionally excluded apps.** Some apps are deliberately outside CA scope. Maintain an allowlist of accepted exclusions.
2. **Emergency-access accounts.** Break-glass accounts are excluded by design. Exclude and monitor them separately.
3. **Coverage by other controls.** An app protected by a different mechanism. Confirm before flagging.

## Tuning Notes

- **Treat this as hardening.** Route to a coverage-gap backlog rather than the incident queue unless paired with a risk signal.
- **Allowlist accepted exclusions.** Exclude apps and accounts deliberately out of CA scope so only unexpected gaps surface.
- **Escalate privileged gaps.** Weight `notApplied` on privileged users and high-value apps upward.

## Validation

1. In a test tenant, sign in to an app that no CA policy targets.
2. Confirm the app surfaces with `ConditionalAccessStatus == "notApplied"`.

## Learn More

- [Entra ID Security: Conditional Access](https://ridgelinecyber.com/training/courses/entra-id-security/). Conditional Access design and closing policy gaps
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). coverage-gap detection
