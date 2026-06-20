# Sign-In Success from a Rare Source Country

**ATT&CK:** T1078.004 Valid Accounts: Cloud Accounts. Tactics: Initial Access, Defense Evasion.

**Severity:** High. A successful sign-in from a country that almost no one in the tenant uses is a strong account-takeover signal, because attacker infrastructure clusters in geographies the legitimate workforce never touches.

**Data Sources:** Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure (`sourcetype="azure:monitor:aad"`, `category="SignInLogs"`). Maps to the CIM Authentication data model.

**Query:**

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

**What Triggers This:** A successful authentication from a country that three or fewer distinct users in the tenant have ever signed in from, excluding any source on the egress allowlist. The rarity is computed against the tenant's own population, so it adapts to where your workforce actually is rather than a static geo-blocklist.

**False Positives:** Genuine travel, a relocated employee, and a new regional office all produce rare-country sign-ins. VPN and corporate egress can present an unexpected country. Distinguish by the user's role and travel pattern, and by whether MFA was satisfied interactively.

**Tuning Notes:** Tune the `users_from_country <= 3` rarity floor to tenant size. Maintain the egress `allowlist` and the `identity` lookup so privileged users surface first. Pair with an impossible-travel check (same user, two distant countries within a short window) for higher confidence, and weight privileged accounts upward.

**Validation:** From a test account, sign in successfully through a VPN exit in a country no test user normally uses; confirm the account surfaces with the rare country listed.

**Learn More:** [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers tenant-relative geo-rarity and allowlist-filtered sign-in detection.
