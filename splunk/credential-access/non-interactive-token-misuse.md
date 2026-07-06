# Non-Interactive Token Misuse: Refresh-Token Use from External

Detects non-interactive sign-ins (refresh-token use) from an external source, reaching resources without any fresh interactive authentication. After an AiTM or token theft, the attacker rides the stolen refresh token through the non-interactive log, which never raises an MFA prompt and is easy to overlook.

## ATT&CK

- **Technique:** T1550.001. Use Alternate Authentication Material: Application Access Token
- **Tactic:** Defense Evasion, Lateral Movement

## Severity

**High.** Non-interactive token use from outside the footprint is how a hijacked session persists and moves. It is Critical for a privileged account.

## Data Sources

- Entra ID non-interactive sign-in logs via the Splunk Add-on for Microsoft Azure, `sourcetype="azure:monitor:aad"`, `category="NonInteractiveUserSignInLogs"`
- Requires: non-interactive sign-in logging; an `identity` lookup for privilege context

## Query

```spl
sourcetype="azure:monitor:aad" category="NonInteractiveUserSignInLogs" action="success"
| where NOT cidrmatch("10.0.0.0/8", src_ip) AND src_country != "GB"
| stats count AS token_uses, values(src_ip) AS ips, values(resource) AS reached,
        min(_time) AS first_seen, max(_time) AS last_seen by user, src_country
| lookup identity user AS user OUTPUT privileged
| sort - token_uses
```

## What Triggers This

A refresh token used from the wrong place:

- Non-interactive success from an external source and unexpected country
- Several resources reached on one token without re-authentication
- A privileged account riding a non-interactive session externally

## False Positives

1. **Mobile and roaming clients.** Legitimate background token refresh from a travelling user. Confirm against travel and device.
2. **Distributed services.** A service whose token is used from multiple regions. Allowlist known service principals and regions.
3. **CDN and proxy egress.** Token use appearing from an edge location. Account for known egress.

## Tuning Notes

- **Set home country and ranges.** Replace `GB` and the internal CIDR with your footprint.
- **Correlate with the interactive log.** Pair with a preceding AiTM or token-replay interactive sign-in for the full hijack chain.
- **Weight resources reached.** Many distinct resources on one token is stronger than a single refresh.

## Validation

1. In a lab, use a refresh token from an external host (or inject a non-interactive success from a foreign source into test data).
2. Confirm the user surfaces with `token_uses >= 1` and the external country listed.

## Learn More

- [Splunk Detection and Incident Response: Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/). non-interactive token misuse and session-hijack chains
- [Threat Hunting in Microsoft 365](https://ridgelinecyber.com/training/courses/threat-hunting-m365/). hunting refresh-token reuse
