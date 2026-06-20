# High-Risk Sign-In Allowed — Risk Verdict Not Enforced

Detects sign-ins that Entra ID Identity Protection scored as high risk but that succeeded with Conditional Access reporting success, meaning the risk verdict was not enforced. A high-risk sign-in that gets in anyway is either a missing risk-based policy or a policy in report-only mode.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts
- **Tactic:** Initial Access, Defense Evasion

## Severity

**High.** The platform already flagged the sign-in as risky and it succeeded regardless. That combination is both a likely compromise and a control failure.

## Data Sources

- Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure — `sourcetype="azure:monitor:aad"`, `category="SignInLogs"`
- Requires: Entra ID P2 for risk scoring; `risk` and `conditional_access_status` fields

## Query

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" risk="high" action="success"
    conditional_access_status="success"
| stats count AS allowed_signins, values(src_country) AS countries, values(src_ip) AS ips by user
| lookup identity user AS user OUTPUT department, job_title, privileged
| sort - allowed_signins
```

## What Triggers This

A risky sign-in the controls let through:

- A `risk=high` verdict on a successful sign-in
- Conditional Access reporting `success` rather than a block or step-up
- A privileged account among the allowed high-risk sign-ins

## False Positives

1. **Report-only policies.** A risk-based policy deployed in report-only mode logs success while not enforcing. Confirm policy state, then move it to enforce.
2. **Risk false positives.** Identity Protection occasionally over-scores a legitimate sign-in. Confirm against the user's pattern.
3. **Remediated risk.** A user who completed risk remediation. Correlate with the risk-state timeline.

## Tuning Notes

- **Drive policy enforcement.** Persistent hits usually mean a report-only policy that should be enforcing; that is the fix.
- **Weight privileged users.** Surface privileged accounts first.
- **Add medium risk.** A separate, higher-threshold variant on `risk=medium` repeat offenders extends coverage.

## Validation

1. In a test tenant with a report-only risk policy, generate a high-risk sign-in (for example via an anonymised source) that succeeds.
2. Confirm the user surfaces with `allowed_signins >= 1`.

## Learn More

- [Splunk Detection and Incident Response — Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — risk-verdict enforcement gaps
- [Entra ID Security](https://ridgelinecyber.com/training/courses/entra-id-security/) — Identity Protection and risk-based Conditional Access
