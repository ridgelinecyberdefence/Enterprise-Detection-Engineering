# Distributed Password Spray by Source IP

**ATT&CK:** T1110.003 Brute Force: Password Spraying. Tactic: Credential Access.

**Severity:** High. A spray that stays under per-account lockout thresholds is the standard opener for account takeover and frequently precedes a successful sign-in. Raise to Critical when the same source also produces a success against one of the targeted accounts (see Tuning).

**Data Sources:** Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure (`sourcetype="azure:monitor:aad"`, `category="SignInLogs"`). The fields map to the CIM Authentication data model, so the same logic runs as a `tstats` query over an accelerated `Authentication` model where that is in place.

**Query:**

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" action="failure" earliest=-1h
| where NOT cidrmatch("10.0.0.0/8", src_ip)
| stats dc(user) AS accounts_targeted, count AS failed_attempts,
        values(user) AS targeted_accounts, earliest(_time) AS first_seen, latest(_time) AS last_seen
        by src_ip
| where accounts_targeted >= 10 AND failed_attempts <= accounts_targeted * 4
| sort - accounts_targeted
```

**What Triggers This:** One source IP failing authentication against many distinct accounts with only a few attempts per account in a short window. The signature is breadth with shallow depth: many accounts touched, few tries each, which is how a spray deliberately stays beneath per-account lockout. A real user fat-fingering a password produces the opposite shape, many attempts against one account.

**False Positives:** Shared NAT or VPN egress puts many legitimate users behind one IP, so a brief outage or an expired password during a sync storm can produce correlated failures across accounts. A misconfigured service account or mail client retrying stale credentials against several mailboxes will match. Vulnerability scanners and authenticated monitoring also generate broad failure patterns. Distinguish by user-agent uniformity, whether any success followed from the same IP, and whether the IP is known corporate egress.

**Tuning Notes:** Set `accounts_targeted` to your tenant size; 10 is a starting point, and large NAT egress estates may need 25 or more, or an egress allowlist applied with a `lookup`. Keep `failed_attempts <= accounts_targeted * 4` to hold the low-and-slow shape and avoid catching single-account brute force, which is a separate detection. To prioritise sprays that landed, append a success correlation:

```spl
| join src_ip [ search sourcetype="azure:monitor:aad" category="SignInLogs" action="success" earliest=-1h
                | stats values(user) AS compromised_accounts by src_ip ]
```

Tighten `earliest` for noisier tenants and exclude known scanner sources.

**Validation:** In a test tenant, attempt one failed sign-in each against ten or more test accounts from a single host inside the window and confirm the IP surfaces with `accounts_targeted >= 10`. Then authenticate one of those accounts successfully from the same host and confirm the success-correlation variant attaches it under `compromised_accounts`.

**Learn More:** [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) covers spray detection, the breadth-versus-depth signature, and success correlation in depth.
