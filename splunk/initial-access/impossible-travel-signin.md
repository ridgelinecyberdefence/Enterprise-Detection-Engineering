# Impossible Travel: One User, Distant Countries in a Short Window

Detects a single user authenticating successfully from countries too far apart to be physically possible in the elapsed time. Two sign-ins from distant geographies within hours mean either a credential is shared across locations or a session is being used from attacker infrastructure.

## ATT&CK

- **Technique:** T1078.004, Valid Accounts: Cloud Accounts
- **Tactic:** Initial Access, Defense Evasion

## Severity

**High.** Concurrent geographically impossible sign-ins are a strong account-takeover signal that does not depend on a static blocklist. Escalate when one of the locations is on the egress allowlist and the other is not.

## Data Sources

- Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure, `sourcetype="azure:monitor:aad"`, `category="SignInLogs"`
- Requires: `src_country` populated; an `identity` lookup for privilege context

## Query

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" action="success" earliest=-6h
| stats dc(src_country) AS countries, values(src_country) AS seen_in,
        values(src_ip) AS ips, min(_time) AS first_seen, max(_time) AS last_seen by user
| where countries > 1
| eval window_min = round((last_seen - first_seen)/60, 1)
| lookup identity user AS user OUTPUT department, privileged
| sort - countries
```

## What Triggers This

One identity in two places at once:

- Successful sign-ins from more than one country in a short window
- A short elapsed time between distant geographies
- A privileged user exhibiting the pattern, the highest-priority case

## False Positives

1. **VPN and proxy.** A user toggling a VPN exit can appear in two countries. Maintain an egress allowlist and account for known VPN exits.
2. **Mobile roaming.** Carrier routing can misattribute geography. Confirm against the user's device and pattern.
3. **Shared service accounts.** An account used from multiple sites. These should be remediated rather than alerted long-term.

## Tuning Notes

- **Add a distance or velocity gate.** Where a geo-distance lookup exists, compute required travel speed and alert only when it is implausible.
- **Allowlist egress and VPN.** Exclude known exits to cut the dominant false positive.
- **Tighten the window.** A 6-hour window is a starting point; shorten it to raise confidence.

## Validation

1. From a test account, sign in successfully through VPN exits in two distant countries within the window.
2. Confirm the user surfaces with `countries > 1` and both geographies listed.

## Learn More

- [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). impossible travel and velocity analysis
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). geo-velocity detection design
