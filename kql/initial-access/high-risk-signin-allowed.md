# High-Risk Sign-In Allowed: Risk Verdict Not Enforced

Detects sign-ins that Identity Protection scored as high risk but that succeeded with Conditional Access reporting success, meaning the risk verdict was not enforced. A high-risk sign-in that gets in anyway is either a missing risk-based policy or one left in report-only mode.

## ATT&CK

- **Technique:** T1078.004, Valid Accounts: Cloud Accounts
- **Tactic:** Initial Access, Defense Evasion

## Severity

**High.** The platform already flagged the sign-in as risky and it succeeded regardless. That is both a likely compromise and a control failure.

## Data Sources

- Entra ID Sign-in Logs, `SigninLogs` in Sentinel
- Requires: Entra ID P2 for risk scoring (`RiskLevelDuringSignIn`)

## Query: KQL (Sentinel)

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| where RiskLevelDuringSignIn == "high"
| where ConditionalAccessStatus == "success"
| summarize
    AllowedSignins = count(),
    Countries = make_set(tostring(LocationDetails.countryOrRegion), 5),
    IPs = make_set(IPAddress, 5),
    Apps = make_set(AppDisplayName, 5)
    by UserPrincipalName
| sort by AllowedSignins desc
```

## What Triggers This

A risky sign-in the controls let through:

- A `RiskLevelDuringSignIn == "high"` verdict on a successful sign-in
- Conditional Access reporting `success` rather than a block or step-up
- A privileged account among the allowed high-risk sign-ins

## False Positives

1. **Report-only policies.** A risk-based policy in report-only mode logs success while not enforcing. Confirm policy state, then move it to enforce.
2. **Risk false positives.** Identity Protection occasionally over-scores a legitimate sign-in. Confirm against the user's pattern.
3. **Remediated risk.** A user who completed risk remediation. Correlate with the risk-state timeline.

## Tuning Notes

- **Drive policy enforcement.** Persistent hits usually mean a report-only policy that should be enforcing; that is the fix, not a tuning exclusion.
- **Weight privileged users.** Enrich with directory role membership and surface privileged accounts first.
- **Add medium risk.** A separate, higher-threshold variant on repeat `medium` offenders extends coverage.

## Validation

1. In a test tenant with a report-only risk policy, generate a high-risk sign-in (for example from an anonymised source) that succeeds.
2. Confirm the user surfaces with `AllowedSignins >= 1`.

## Learn More

- [Entra ID Security: Identity Protection](https://ridgelinecyber.com/training/courses/entra-id-security/). risk-based Conditional Access and enforcement gaps
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). risk-signal detection design
