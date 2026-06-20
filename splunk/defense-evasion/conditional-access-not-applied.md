# Conditional Access Not Applied: Policy Coverage Gap

Detects sign-ins where Conditional Access evaluated to `notApplied`, meaning no policy governed the authentication. Attackers seek the paths CA does not cover (specific apps, legacy clients, service accounts), and a cluster of `notApplied` sign-ins on a sensitive app is a coverage gap worth closing before it is abused.

## ATT&CK

- **Technique:** T1556, Modify Authentication Process
- **Tactic:** Defense Evasion

## Severity

**Medium.** A gap is an exposure rather than an active compromise, so it sits at Medium as a hardening signal. It rises when the gap is on a privileged user or a high-value application.

## Data Sources

- Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure, `sourcetype="azure:monitor:aad"`, `category="SignInLogs"`
- Requires: `conditional_access_status` field populated

## Query

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" conditional_access_status="notApplied"
| stats count AS signins, values(user) AS users, dc(user) AS distinct_users, values(src_country) AS country by app
| where signins >= 10
| sort - signins
```

## What Triggers This

Authentication that no policy governed:

- `conditional_access_status=notApplied` clustering on one application
- A path consistently escaping policy (a specific app, client, or account type)
- The same gap appearing for privileged users

## False Positives

1. **Intentionally excluded apps.** Some apps are deliberately outside CA scope. Maintain an allowlist of accepted exclusions.
2. **Emergency-access accounts.** Break-glass accounts are excluded by design. Exclude and monitor them separately.
3. **Coverage by other controls.** An app protected by a different mechanism. Confirm before flagging.

## Tuning Notes

- **Treat this as hardening.** Route to a coverage-gap backlog rather than the incident queue unless paired with risk.
- **Allowlist accepted exclusions.** Exclude apps and accounts deliberately out of CA scope so only unexpected gaps surface.
- **Escalate privileged gaps.** Weight `notApplied` on privileged users and high-value apps upward.

## Validation

1. In a test tenant, sign in to an app that no CA policy targets.
2. Confirm the app surfaces with `conditional_access_status=notApplied`.

## Learn More

- [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). Conditional Access coverage analysis
- [Entra ID Security](https://ridgelinecyber.com/training/courses/entra-id-security/). Conditional Access design and closing policy gaps
