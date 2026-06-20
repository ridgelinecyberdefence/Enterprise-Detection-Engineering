# AiTM Token Replay: Claim-Backed Sign-In from a Foreign Source

Detects sign-ins authenticated by `SatisfiedByClaimInToken` from an unexpected country, the fingerprint of an adversary-in-the-middle attack replaying a stolen session token. The token already carries a satisfied MFA claim, so the attacker authenticates without ever facing a prompt.

## ATT&CK

- **Technique:** T1550.001. Use Alternate Authentication Material: Application Access Token
- **Tactic:** Defense Evasion, Lateral Movement

## Severity

**Critical.** Token replay bypasses MFA entirely and is the payoff of an AiTM phishing kit. A claim-backed sign-in from a foreign source on a privileged account is an active session hijack.

## Data Sources

- Entra ID sign-in logs via the Splunk Add-on for Microsoft Azure, `sourcetype="azure:monitor:aad"`
- Requires: `authentication_method`, `risk`, and `src_country` populated; a `threatintel` lookup and an `identity` lookup for context

## Query

```spl
sourcetype="azure:monitor:aad" category="SignInLogs" action="success"
    authentication_method="SatisfiedByClaimInToken"
| where src_country != "GB"
| stats count AS signins, values(src_country) AS country, values(src_ip) AS ip, values(risk) AS risk by user
| lookup identity user AS user OUTPUT department, job_title, privileged
| sort - signins
```

A second query stacks the AiTM signals across interactive and non-interactive logs, weighting threat-intel hits and high risk:

```spl
sourcetype="azure:monitor:aad" action="success" (category="SignInLogs" OR category="NonInteractiveUserSignInLogs")
| lookup threatintel indicator AS src_ip OUTPUT associated_incident
| eval foreign=if(src_country="GB",0,1), token_claim=if(authentication_method="SatisfiedByClaimInToken",1,0),
       high=if(risk="high",1,0), ti=if(isnotnull(associated_incident),1,0)
| stats sum(foreign) AS foreign_signins, sum(token_claim) AS token_replays, sum(high) AS high_risk,
        sum(ti) AS ti_hits, values(src_country) AS countries, values(associated_incident) AS incident by user
| where token_replays > 0 AND (ti_hits > 0 OR high_risk > 0)
| lookup identity user AS user OUTPUT privileged
| sort - token_replays, - ti_hits
```

## What Triggers This

A session authenticated by a replayed token from the wrong place:

- `SatisfiedByClaimInToken` as the authentication method, meaning the MFA claim rode in on the token
- A source country outside the expected footprint
- A threat-intel hit or high-risk verdict on the same source, which promotes it to high confidence

## False Positives

1. **Legitimate token use abroad.** A genuine traveller's existing session presenting a claim. Confirm against travel and the source reputation.
2. **Conditional Access token lifetimes.** Long-lived sessions can show claim satisfaction. Weight on the foreign source and risk, not the method alone.
3. **Federated edge cases.** Some federation flows record claim satisfaction. Confirm the user is not expected to authenticate this way from abroad.

## Tuning Notes

- **Set your home country.** Replace `GB` with the tenant's expected country or a small set.
- **Stack signals.** The single-method query is the tripwire; the correlation query is the high-confidence alert. Run both, route the correlated one straight to incident.
- **Weight privileged users.** Surface privileged accounts first via the `identity` lookup.

## Validation

1. In a lab, replay a captured session token (or simulate by injecting a `SatisfiedByClaimInToken` success from a foreign source IP into test data).
2. Confirm the user surfaces in both queries with the foreign country and any threat-intel context.

## Learn More

- [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). AiTM token replay and multi-signal session-hijack correlation
- [Threat Hunting in Microsoft 365](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). hunting for stolen-token reuse
