# Impossible Travel: One User, Distant Countries in a Short Window

Detects a single user authenticating successfully from countries too far apart to be physically possible in the elapsed time. Two successful sign-ins from distant geographies within hours mean a credential is shared across locations or a session is being driven from attacker infrastructure.

## ATT&CK

- **Technique:** T1078.004, Valid Accounts: Cloud Accounts
- **Tactic:** Initial Access, Defense Evasion

## Severity

**High.** Geographically impossible concurrent sign-ins are a strong account-takeover signal that does not rely on a static blocklist. It is Critical for a privileged account.

## Data Sources

- Entra ID Sign-in Logs. `SigninLogs` and `AADNonInteractiveUserSignInLogs` in Sentinel
- Requires: Entra ID P1 for full sign-in telemetry

## Query: KQL (Sentinel)

```kql
let lookback = 6h;
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| where isnotempty(Country)
| summarize
    Countries = dcount(Country),
    CountrySet = make_set(Country, 10),
    IPs = make_set(IPAddress, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName
| where Countries > 1
| extend WindowMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| sort by Countries desc
```

## What Triggers This

One identity present in two places at once:

- Successful sign-ins from more than one country within the window
- A short elapsed time between distant geographies
- A privileged user exhibiting the pattern, the highest-priority case

## False Positives

1. **VPN and proxy.** A user toggling a VPN exit can appear in two countries. Maintain a Named Location allowlist and account for known VPN exits.
2. **Mobile roaming.** Carrier routing can misattribute geography. Confirm against the user's device and pattern.
3. **Shared service accounts.** An account used from multiple sites. Remediate rather than alert long-term.

## Tuning Notes

- **Add a velocity gate.** Where a geo-coordinate enrichment is available, compute required travel speed and alert only when it is implausible.
- **Allowlist egress and VPN.** Exclude known exits via Named Locations to cut the dominant false positive.
- **Tighten the window.** Shorten the 6-hour lookback to raise confidence; lengthen it to catch slow session reuse.

## Validation

1. From a test account, sign in successfully through VPN exits in two distant countries within the window.
2. Confirm the user surfaces with `Countries > 1` and both geographies listed.

## Learn More

- [Entra ID Security: Authentication Threats](https://ridgelinecyber.com/training/courses/entra-id-security/). impossible travel and sign-in anomaly detection
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). geo-velocity detection design
