# AiTM Phishing — Token Replay Detection via User-Agent Similarity Analysis

Detects Adversary-in-the-Middle phishing attacks by identifying authentication sessions where multiple distinct but suspiciously similar user-agent strings appear within a single sign-in correlation — a behavioral fingerprint of AiTM proxy frameworks like Evilginx, Modlishka, and Sneaky2FA. Standard AiTM detections rely on Entra ID risk signals. This catches the cases those miss.

## ATT&CK

- **Technique:** T1557 — Adversary-in-the-Middle, T1539 — Steal Web Session Cookie, T1550.001 — Use Alternate Authentication Material: Application Access Token
- **Tactic:** Credential Access, Initial Access

## Severity

**Critical.** A true positive means the attacker has a valid session token that bypasses MFA. They are already authenticated. The token works until revoked or it expires (typically 1 hour for access tokens, 90 days for refresh tokens with default Entra ID settings).

## Data Sources

- Entra ID Sign-in Logs — `SigninLogs` table in Sentinel
- Requires: Entra ID P1 or P2 for complete sign-in telemetry
- Enhanced: `AADNonInteractiveUserSignInLogs` for token refresh detection

## Query — KQL (Sentinel)

```kql
let lookback = 24h;
let jaccard_threshold = 0.8;
// Step 1: Find sign-in sessions with no registered device and multiple user-agents
let suspiciousSessions = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| where tostring(DeviceDetail.deviceId) == ""
| summarize
    UserAgents = make_set(UserAgent),
    IPs = make_set(IPAddress),
    AppList = make_set(AppDisplayName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by CorrelationId, UserPrincipalName
| where array_length(UserAgents) > 1;
// Step 2: Compare user-agent pairs using Jaccard similarity on byte arrays
// AiTM proxies modify user-agents slightly (version strings, encoding) but
// the overall structure is nearly identical — Jaccard catches this
let sessionWithSimilarity = suspiciousSessions
| mv-expand i = range(0, array_length(UserAgents) - 2)
| mv-expand j = range(toint(i) + 1, array_length(UserAgents) - 1)
| extend UA1 = tostring(UserAgents[toint(i)])
| extend UA2 = tostring(UserAgents[toint(j)])
| extend ByteSet1 = to_utf8(UA1)
| extend ByteSet2 = to_utf8(UA2)
| extend JaccardIndex = jaccard_index(ByteSet1, ByteSet2)
| where JaccardIndex < jaccard_threshold and JaccardIndex > 0.3;
// Step 3: Enrich with sign-in context
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| where CorrelationId in (sessionWithSimilarity | project CorrelationId)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AppDisplayName,
    UserAgent,
    DeviceDetail,
    RiskLevelDuringSignIn,
    ConditionalAccessStatus,
    CorrelationId
| sort by UserPrincipalName asc, TimeGenerated asc
```

## Why This Detection Is Effective

Standard AiTM detections check whether Entra ID Identity Protection flagged the sign-in as risky. The problem: AiTM frameworks increasingly evade these signals. Sneaky2FA (active since late 2024) uses legitimate cloud infrastructure, rotates IPs through residential proxies, and modifies its proxy behavior to avoid triggering anomalous token or unfamiliar features risk detections.

This query targets a behavioral invariant that AiTM proxies cannot easily eliminate: the proxy sits between the user's browser and Microsoft's authentication endpoint. During the authentication flow, both the real user's browser and the proxy's relay generate HTTP requests. These requests carry slightly different user-agent strings because the proxy modifies or injects headers. The user-agent strings are similar (same browser family, similar version) but not identical — producing a Jaccard similarity between 0.3 and 0.8.

A legitimate user produces either one user-agent per session (single device) or completely different user-agents (phone + laptop). The "almost identical but not quite" pattern is the AiTM fingerprint.

## What Triggers This

1. User clicks a phishing link that routes through an AiTM proxy
2. The proxy relays the authentication challenge to Microsoft's real login page
3. User completes MFA on the real page (they see Microsoft's actual MFA prompt)
4. The proxy captures the session token from the response
5. During this flow, the CorrelationId groups multiple requests with slightly different user-agent strings — the real browser's and the proxy's modified versions
6. The detection identifies sessions where user-agent pairs have Jaccard similarity in the 0.3-0.8 range (similar but not identical)

## False Positives

1. **Browser extensions.** Some extensions modify user-agent strings mid-session. These typically produce Jaccard > 0.9 (very similar) or < 0.2 (completely different), outside the detection window.
2. **Corporate proxy chains.** Multi-hop corporate proxies may inject or modify headers. Baseline your corporate proxy user-agent behavior and exclude known patterns.
3. **SSO redirect chains.** Complex SSO flows through ADFS or third-party identity providers may produce multiple user-agents within a correlation. These typically have registered devices — the `DeviceDetail.deviceId == ""` filter excludes them.

## Tuning Notes

- **Jaccard thresholds.** The 0.3-0.8 range targets AiTM-modified user-agents. Below 0.3 catches completely different browsers (legitimate multi-device use). Above 0.8 catches minor encoding differences (usually benign). Adjust based on your false positive rate after a 7-day hunt.
- **Device filter.** `DeviceDetail.deviceId == ""` filters to unregistered devices. AiTM proxies cannot present Entra-registered device claims. This dramatically reduces false positives in environments with hybrid-joined or compliant devices.
- **Combine with post-authentication signals.** After identifying a suspicious session, check for inbox rule creation (`OfficeActivity`), OAuth consent grants (`AuditLogs`), or anomalous file access (`OfficeActivity`) within the next 30 minutes using the same `CorrelationId` or `UserPrincipalName`.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency with 24-hour lookback. Entity mapping: `UserPrincipalName` as Account, `IPAddress` as IP.

## Validation

1. This detection is difficult to validate without an actual AiTM framework (do not deploy Evilginx in production)
2. In a test environment, use curl with two slightly different user-agent strings against the Azure AD token endpoint with the same correlation context
3. Alternatively, run the query in hunt mode over 30 days of historical data — if you find hits with confirmed compromised accounts, the detection is validated
4. Cross-reference results with Entra ID Identity Protection risk events to measure detection overlap

## References

- Eye Security: [Sneaky2FA KQL Detection](https://www.eye.security/blog/sneaky2fa-use-this-kql-query-to-stay-ahead-of-the-emerging-threat) — original Jaccard similarity research (February 2025)
- Microsoft Incident Response: AiTM phishing campaign analysis — token replay behavioral patterns
- M-Trends 2025: AiTM as the dominant initial access vector for M365 compromises

## Learn More

- [SOC Operations — Investigation Playbook Framework](https://ridgelinecyber.com/training/courses/m365-security-operations/) — complete AiTM investigation and response playbook
- [Entra ID Security — Token Architecture and Protection](https://ridgelinecyber.com/training/courses/entra-id-security/) — PRT, access token, and refresh token lifecycle with detection strategies
- [Detection Engineering — Identity Detection](https://ridgelinecyber.com/training/courses/detection-engineering/) — building behavioral detection for authentication anomalies
