# Sign-In from a Rare Source Country: Tenant-Relative Geo Anomaly

Detects a successful sign-in from a country that almost no one in the tenant uses, computed against the tenant's own population rather than a static blocklist. Attacker infrastructure clusters in geographies the legitimate workforce never touches.

## ATT&CK

- **Technique:** T1078.004, Valid Accounts: Cloud Accounts
- **Tactic:** Initial Access, Defense Evasion

## Severity

**High.** A successful authentication from a country used by only a handful of accounts is a strong account-takeover signal, particularly for a privileged user. Rarity is measured against your own tenant, so it adapts to where your workforce actually is.

## Data Sources

- Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure, `sourcetype="azure:monitor:aad"`, `category="SignInLogs"`
- Requires: an `allowlist` lookup of sanctioned egress and an `identity` lookup for user context

## Query

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" action="success" earliest=-24h
| eventstats dc(user) AS users_from_country by src_country
| where users_from_country <= 3
| lookup allowlist value AS src_ip OUTPUT reason
| where isnull(reason)
| stats count AS signins, values(src_ip) AS source_ips, values(src_country) AS country by user
| lookup identity user AS user OUTPUT department, job_title, privileged
| sort - signins
```

## What Triggers This

A success from a geography the tenant barely uses:

- A country three or fewer distinct users have ever signed in from
- A source not on the egress allowlist
- A privileged account surfacing first when present

## False Positives

1. **Genuine travel.** An employee abroad or recently relocated produces a rare-country sign-in. Confirm against the user's role and travel pattern.
2. **VPN and egress.** A VPN or corporate egress can present an unexpected country. Maintain the allowlist.
3. **New region.** A newly opened office shifts the baseline. Re-baseline after expansion.

## Tuning Notes

- **Rarity floor.** Tune `users_from_country <= 3` to tenant size.
- **Keep the lookups current.** The `allowlist` and `identity` lookups carry most of the precision; privileged users should surface first.
- **Pair with impossible travel.** Combine with a same-user two-country check within a short window for higher confidence.

## Validation

1. From a test account, sign in successfully through a VPN exit in a country no test user normally uses.
2. Confirm the account surfaces with the rare country listed.

## Learn More

- [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). tenant-relative geo-rarity and allowlist-filtered sign-in detection
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). population-relative anomaly design
