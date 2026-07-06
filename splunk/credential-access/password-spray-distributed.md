# Distributed Password Spray: Low-and-Slow by Source IP

Detects password spray by identifying a single source IP failing authentication against many distinct accounts with only a few attempts per account in a short window. Brute force counts failures per account; spray spreads one or two attempts across hundreds of accounts, so each account stays under lockout while the pattern across accounts is unmistakable.

## ATT&CK

- **Technique:** T1110.003, Brute Force: Password Spraying
- **Tactic:** Credential Access

## Severity

**High.** A successful spray hands the attacker a valid credential, and spray is the most common initial access route against Entra ID tenants. Auto-elevate to Critical when the same source then succeeds against a sprayed account (stage 2).

## Data Sources

- Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure, `sourcetype="azure:monitor:aad"`, `category="SignInLogs"`
- Requires: both interactive and non-interactive sign-ins, since legacy auth carries sprays that raise no MFA prompt; maps to the CIM Authentication data model

## Query

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" action="failure" earliest=-1h
| where NOT cidrmatch("10.0.0.0/8", src_ip)
| stats dc(user) AS accounts_targeted, count AS failed_attempts,
        values(user) AS targeted_accounts, earliest(_time) AS first_seen, latest(_time) AS last_seen
        by src_ip
| where accounts_targeted >= 10 AND failed_attempts <= accounts_targeted * 4
| sort - accounts_targeted
```

Stage 2, promote sprays that landed by joining any subsequent success from the same source:

```spl
| join src_ip
    [ search sourcetype="azure:monitor:aad" category="SignInLogs" action="success" earliest=-1h
    | stats values(user) AS compromised_accounts, dc(user) AS breach_count by src_ip ]
| eval severity = if(breach_count > 0, "Critical", "High")
```

## What Triggers This

A single source IP exhibiting the spray shape:

- Many distinct accounts targeted, only a few attempts each, staying beneath Smart Lockout
- Failures accumulating on one source while spreading thin across accounts
- A subsequent success from the same source, which separates a blocked spray from a breach

## False Positives

1. **Shared NAT or VPN egress.** Many users behind one IP can produce correlated failures during an outage or password-expiry sync. Exclude known corporate egress with a lookup.
2. **Misconfigured app or mail client.** A service retrying stale credentials against several mailboxes mimics breadth. Check `targeted_accounts` and user-agent uniformity; a single app across all failures is a misconfiguration.
3. **Scanners and monitoring.** Authorized tools generate broad failure patterns. Coordinate and exclude their source IPs.

## Tuning Notes

- **Thresholds.** `accounts_targeted >= 10` suits a 500-user tenant; raise to 25+ for large tenants or apply an egress allowlist. The `failed_attempts <= accounts_targeted * 4` guard holds the low-and-slow shape and keeps single-account brute force out.
- **CIM acceleration.** Where the Authentication model is accelerated, convert the base search to `| tstats ... from datamodel=Authentication` for scale.
- **Deployment.** Scheduled search, 15-minute cadence with a 1-hour overlapping lookback. If `breach_count > 0`, route straight to the incident queue.

## Validation

1. In a test tenant, attempt one failed sign-in each against 10 or more test accounts from a single host within the window.
2. Confirm the IP surfaces with `accounts_targeted >= 10`.
3. Authenticate one account successfully from the same host and confirm stage 2 attaches it under `compromised_accounts` with `severity = "Critical"`.

## Learn More

- [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). spray detection, the breadth-versus-depth signature, and success correlation
- [Detection Engineering: Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/). statistical detection design for distributed attacks
