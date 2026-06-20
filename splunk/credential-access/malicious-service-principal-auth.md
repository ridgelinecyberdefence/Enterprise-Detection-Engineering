# Malicious Service Principal Authentication — App Identity from a Bad Source

Detects a service principal (application identity) authenticating from a source that matches threat intelligence. Compromised app credentials and consented OAuth apps are an attacker's route to durable, MFA-free access, and a service principal signing in from known-bad infrastructure is a strong compromise signal.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts, T1550.001 — Use Alternate Authentication Material: Application Access Token
- **Tactic:** Credential Access, Defense Evasion

## Severity

**High.** Service principals often hold broad, standing API permissions and never face MFA, so a compromised app identity is high-impact and quiet. A threat-intel match on the source makes it high-confidence.

## Data Sources

- Entra ID service-principal sign-in logs via the Splunk Add-on for Microsoft Azure — `sourcetype="azure:monitor:aad"`, `category="ServicePrincipalSignInLogs"`
- Requires: service-principal sign-in logging; a `threatintel` lookup

## Query

```spl
sourcetype="azure:monitor:aad" category="ServicePrincipalSignInLogs"
| lookup threatintel indicator AS src_ip OUTPUT threat_category, associated_incident
| where isnotnull(associated_incident)
| stats count AS auths, values(src_ip) AS ips, values(resource) AS reached,
        values(threat_category) AS threat by app, associated_incident
| sort - auths
```

## What Triggers This

An application identity authenticating from bad infrastructure:

- A `ServicePrincipalSignInLogs` event whose source matches a threat-intel indicator
- The resources the app token reached, for blast-radius assessment
- The associated incident context attached from intelligence

## False Positives

1. **Stale intelligence.** A recycled IP flagged in an aged feed. Filter on confidence and expiry in the `threatintel` lookup.
2. **Shared infrastructure.** A CDN or hosting range carrying both the app and a flagged neighbour. Prefer higher-confidence indicators.
3. **Vendor-hosted apps.** A SaaS app whose egress overlaps a flagged range. Confirm the recipient and app.

## Tuning Notes

- **Curate the lookup.** Precision here depends entirely on intelligence quality; maintain confidence and expiry.
- **Baseline app sources.** For higher coverage, add a variant that flags any service principal signing in from a source outside its historical set, independent of intel.
- **Assess permissions.** Enrich with the app's granted scopes so high-privilege apps surface first.

## Validation

1. Add a benign test IP to the `threatintel` lookup and authenticate a test service principal from it.
2. Confirm the app surfaces with the threat category and incident attached, then remove the test indicator.

## Learn More

- [Splunk Detection and Incident Response — Identity Attack Detection](https://ridgelinecyber.com/training/courses/splunk-detection-and-response/) — service-principal abuse and OAuth app compromise
- [Entra ID Security](https://ridgelinecyber.com/training/courses/entra-id-security/) — application identity governance and consent risk
