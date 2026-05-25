# Token Replay — Session Used from Different IP than Authentication

Detects stolen session tokens being replayed from attacker infrastructure by identifying sessions where the authentication IP and subsequent resource access IP are different and geographically inconsistent. The user authenticates from London, but the token is used from a VPS in Eastern Europe 30 seconds later. Legitimate users don't teleport.

## ATT&CK

- **Technique:** T1550.001 — Use Alternate Authentication Material: Application Access Token, T1539 — Steal Web Session Cookie
- **Tactic:** Credential Access, Lateral Movement

## Severity

**Critical.** A confirmed token replay means the attacker has a valid session that bypasses MFA. The stolen token grants the same access as the legitimate user's session. Every minute the token remains active, the attacker can read email, access files, and establish persistence.

## Data Sources

- Entra ID Sign-in Logs — `SigninLogs` table
- Entra ID Non-Interactive Sign-in Logs — `AADNonInteractiveUserSignInLogs` (token refresh events)
- Optional: `OfficeActivity` for resource access IP correlation
- Requires: Entra ID P1 or P2

## Query — KQL (Sentinel)

```kql
let lookback = 24h;
let max_travel_km = 500;
let max_travel_minutes = 30;
// Stage 1: Get the authentication IP for each user's sessions
let authSessions = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| extend AuthLat = toreal(LocationDetails.geoCoordinates.latitude)
| extend AuthLon = toreal(LocationDetails.geoCoordinates.longitude)
| extend AuthCity = tostring(LocationDetails.city)
| extend AuthCountry = tostring(LocationDetails.countryOrRegion)
| where isnotempty(AuthLat) and isnotempty(AuthLon)
| project
    AuthTime = TimeGenerated,
    UserPrincipalName,
    AuthIP = IPAddress,
    AuthLat, AuthLon,
    AuthLocation = strcat(AuthCity, ", ", AuthCountry),
    AuthUserAgent = UserAgent,
    SessionId = CorrelationId;
// Stage 2: Get non-interactive token usage (resource access)
let tokenUsage = AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| extend UseLat = toreal(LocationDetails.geoCoordinates.latitude)
| extend UseLon = toreal(LocationDetails.geoCoordinates.longitude)
| extend UseCity = tostring(LocationDetails.city)
| extend UseCountry = tostring(LocationDetails.countryOrRegion)
| where isnotempty(UseLat) and isnotempty(UseLon)
| project
    UseTime = TimeGenerated,
    UserPrincipalName,
    UseIP = IPAddress,
    UseLat, UseLon,
    UseLocation = strcat(UseCity, ", ", UseCountry),
    ResourceDisplayName,
    UseUserAgent = UserAgent;
// Stage 3: Correlate — find sessions where auth IP != usage IP
authSessions
| join kind=inner (tokenUsage) on UserPrincipalName
| where UseTime between (AuthTime .. (AuthTime + 4h))
| where AuthIP != UseIP
// Calculate distance using Haversine approximation
| extend LatDiff = radians(UseLat - AuthLat)
| extend LonDiff = radians(UseLon - AuthLon)
| extend A = sin(LatDiff/2) * sin(LatDiff/2) +
    cos(radians(AuthLat)) * cos(radians(UseLat)) *
    sin(LonDiff/2) * sin(LonDiff/2)
| extend DistanceKm = round(2 * 6371 * asin(sqrt(A)), 0)
| extend TimeDeltaMin = datetime_diff('minute', UseTime, AuthTime)
// Flag impossible travel: too far in too little time
| where DistanceKm > max_travel_km and TimeDeltaMin < max_travel_minutes
| extend TravelSpeedKmh = round(DistanceKm / (max_of(TimeDeltaMin, 1) / 60.0), 0)
| project
    AuthTime,
    UseTime,
    UserPrincipalName,
    AuthIP,
    AuthLocation,
    UseIP,
    UseLocation,
    DistanceKm,
    TimeDeltaMin,
    TravelSpeedKmh,
    ResourceDisplayName,
    AuthUserAgent,
    UseUserAgent
| where TravelSpeedKmh > 800
| sort by TravelSpeedKmh desc
```

## Why This Detection Is Effective

Standard impossible travel detection compares consecutive sign-ins. Token replay is harder — the attacker doesn't sign in again. They use the stolen token to access resources directly, which appears in `AADNonInteractiveUserSignInLogs` (token refresh events) rather than `SigninLogs` (interactive authentication).

This detection correlates the interactive authentication (where the user actually signed in) with the non-interactive token usage (where the token was used to access resources). If the user authenticated from London and the token is accessing SharePoint from a VPS in Romania 5 minutes later, the token was stolen and replayed.

The Haversine distance calculation is more accurate than simple IP geolocation comparison because it handles edge cases (two cities in the same country that are 1000km apart) and provides an actual speed metric. Anything over 800 km/h (faster than commercial aviation) is physically impossible.

Key advantage over Entra ID's built-in impossible travel: Microsoft's detection has a learning period and baseline tolerance that sophisticated attackers exploit by replaying tokens from geographically nearby infrastructure. This detection has no learning period and catches same-country replays that are still physically impossible within the time delta.

## What Triggers This

1. Attacker steals a session token (AiTM phishing, browser malware, LSASS dump, token extraction from a compromised endpoint)
2. User continues working normally from their legitimate IP
3. Attacker replays the token from different infrastructure to access the same resources
4. The non-interactive sign-in log records the token refresh from the attacker's IP
5. The detection identifies that the same user's token is being used from two geographically distant locations within a timeframe that makes physical travel impossible

## False Positives

1. **VPN connect/disconnect.** A user signs in from their office IP, then their traffic shifts to the corporate VPN (different IP, different geolocation). The VPN exit point may be in a different city or country. Exclude your corporate VPN egress ASNs.
2. **Mobile roaming.** Users on mobile devices may change cell towers or WiFi networks, causing IP and geolocation changes. Mobile transitions typically show small distances (< 50km) and are filtered by the 500km threshold.
3. **Proxy chains.** Corporate proxy infrastructure may route authentication through one location and resource access through another. Baseline your proxy architecture.
4. **GeoIP inaccuracy.** IP geolocation databases have accuracy limits, especially for mobile carriers and satellite ISPs. The 500km minimum threshold accounts for reasonable GeoIP error.

## Tuning Notes

- **Distance threshold.** 500km with 30-minute window catches intercontinental replays reliably. Reduce to 200km for higher sensitivity (more false positives from VPN transitions). Increase to 1000km for lower noise.
- **Speed threshold.** 800 km/h filters out all commercial travel. Reduce to 500 km/h to catch more replays from nearby countries (e.g., UK → Netherlands in 10 minutes).
- **Correlation window.** 4 hours covers the typical access token lifetime. Extend to 24 hours to catch refresh token replays that happen hours after the initial authentication.
- **Combine with risk signals.** Join results with `IdentityRiskEvents` to check whether Entra ID also flagged the session. Detections that fire when Entra missed the risk are the highest-value alerts.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. Entity mapping: `UserPrincipalName` as Account, both `AuthIP` and `UseIP` as IP entities.

## Response

1. **Revoke all user sessions immediately:** `Revoke-MgUserSignInSession -UserId <UPN>`
2. **Enable Continuous Access Evaluation (CAE)** if not already enabled — CAE allows near-instant token revocation
3. **Check the UseIP** — what infrastructure is the attacker using? Block it in Conditional Access Named Locations
4. **Audit resource access** from the UseIP — what did the attacker access? Check `OfficeActivity` for email reads, file downloads, and SharePoint access
5. **Check for persistence** — inbox rules, OAuth consent grants, service principal credential additions within 4 hours of the initial authentication

## References

- Microsoft: [Token Protection in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)
- Microsoft: [Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
- M-Trends 2025: Token theft as the dominant post-MFA attack technique

## Learn More

- [Entra ID Security — Token Architecture](https://training.ridgelinecyber.com/courses/entra-id-security/) — PRT, access tokens, refresh tokens, and token protection strategies
- [SOC Operations — Investigation Playbooks](https://training.ridgelinecyber.com/courses/m365-security-operations/) — token theft investigation and containment
- [Threat Hunting in Microsoft 365](https://training.ridgelinecyber.com/courses/threat-hunting-m365/) — proactive hunting for session anomalies
