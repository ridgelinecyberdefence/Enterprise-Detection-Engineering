# MFA Fatigue: Push Bombing Detection

Detects MFA push bombing attacks where an attacker with valid credentials repeatedly triggers MFA push notifications hoping the victim approves one out of fatigue or confusion. Identifies accounts receiving an abnormal volume of MFA challenges in a short window, especially when followed by a successful authentication.

## ATT&CK

- **Technique:** T1621, Multi-Factor Authentication Request Generation
- **Tactic:** Initial Access, Credential Access

## Severity

**High.** MFA push bombing is an active attack requiring the adversary to already possess valid credentials. If the victim approves a push, the attacker has full account access. Escalate to Critical if followed by a successful sign-in.

## Data Sources

- Entra ID Sign-in Logs, `SigninLogs` and `AADNonInteractiveUserSignInLogs`
- Requires: Entra ID P1 or P2

## Query

```kql
let TimePeriod = 1h;
let PushThreshold = 5;
SigninLogs
| where TimeGenerated > ago(TimePeriod)
| where ResultType == "500121"  // MFA challenge failed / denied / timed out
    or ResultType == "50074"    // Strong auth required
    or ResultType == "50076"    // MFA required but not completed
| summarize
    FailedMFACount = count(),
    DistinctIPs = dcount(IPAddress),
    IPAddresses = make_set(IPAddress, 10),
    AppNames = make_set(AppDisplayName, 5),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName, UserDisplayName
| where FailedMFACount >= PushThreshold
| extend AttackDurationMin = datetime_diff("minute", LastAttempt, FirstAttempt)
// Check if a success followed the push bombing
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(TimePeriod)
    | where ResultType == 0
    | where AuthenticationRequirement == "multiFactorAuthentication"
    | project
        UserPrincipalName,
        SuccessTime = TimeGenerated,
        SuccessIP = IPAddress,
        SuccessApp = AppDisplayName,
        SuccessLocation = LocationDetails
) on UserPrincipalName
| where isempty(SuccessTime) or SuccessTime > FirstAttempt
| extend
    VictimApproved = isnotempty(SuccessTime),
    ApprovedFromAttackerIP = iff(
        isnotempty(SuccessTime) and SuccessIP in (IPAddresses),
        true, false)
| project
    UserPrincipalName,
    UserDisplayName,
    FailedMFACount,
    AttackDurationMin,
    DistinctIPs,
    IPAddresses,
    AppNames,
    VictimApproved,
    SuccessTime,
    SuccessIP,
    ApprovedFromAttackerIP
| sort by VictimApproved desc, FailedMFACount desc
```

## What Triggers This

An account accumulates 5+ failed MFA challenges within 1 hour. The attacker has the password and repeatedly initiates sign-in attempts, each triggering a push notification to the victim's phone. The query also checks whether a successful MFA sign-in followed the bombardment. Indicating the victim approved a push.

## False Positives

1. **MFA registration issues.** Users with misconfigured authenticator apps may generate repeated failures. Check if the failures are all from the user's known IP.
2. **Token refresh storms.** Some applications aggressively retry authentication. Check `AppDisplayName`. If all failures come from one app, it may be an app issue.
3. **Shared accounts.** Service or shared accounts with MFA sometimes generate bursts. These shouldn't exist with MFA enabled.

## Tuning Notes

- Default threshold of 5 pushes in 1 hour catches most attacks while avoiding noise. Lower to 3 for high-security accounts (admins, executives).
- The `VictimApproved` field is the critical escalation signal. Any row where this is `true` is an active compromise.
- `ApprovedFromAttackerIP` = true means the successful sign-in came from one of the IPs that was bombing, near-certain compromise confirmation.
- Deploy as NRT rule in Sentinel for real-time alerting.

## Validation

1. From a test account, trigger 6 failed MFA attempts within 30 minutes (use a wrong authenticator code)
2. Verify the detection fires and captures the attempt count, duration, and IPs
3. Then successfully authenticate and verify `VictimApproved` flips to true

## Learn More

- [Entra ID Security: MFA Attack Patterns](https://ridgelinecyber.com/training/courses/entra-id-security/). MFA fatigue, SIM swap, and authenticator compromise
- [SOC Operations: Identity Alert Triage](https://ridgelinecyber.com/training/courses/m365-security-operations/). triaging MFA-related alerts
- [Detection Engineering: Identity Detections](https://ridgelinecyber.com/training/courses/detection-engineering/). building identity-layer detection rules
