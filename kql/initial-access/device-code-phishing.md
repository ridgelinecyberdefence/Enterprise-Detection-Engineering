# OAuth Device Code Phishing

Detects OAuth device code flow abuse where an attacker initiates a device code authorization request and tricks the victim into entering the code at microsoft.com/devicelogin. This grants the attacker a refresh token for the victim's account, bypassing MFA entirely because the victim authenticates on their own trusted device.

## ATT&CK

- **Technique:** T1528 — Steal Application Access Token
- **Tactic:** Initial Access, Credential Access

## Severity

**Critical.** Device code phishing bypasses MFA and Conditional Access device compliance checks. The attacker receives a long-lived refresh token. This technique was used in the Midnight Blizzard (Nobelium) campaign against Microsoft in 2024.

## Data Sources

- Entra ID Sign-in Logs — `SigninLogs`
- Requires: Entra ID P1 or P2

## Query

```kql
let TimePeriod = 24h;
SigninLogs
| where TimeGenerated > ago(TimePeriod)
| where AuthenticationProtocol == "deviceCode"
| where ResultType == 0  // successful
| extend
    DeviceCodeApp = AppDisplayName,
    SignInIP = IPAddress,
    SignInCity = tostring(LocationDetails.city),
    SignInCountry = tostring(LocationDetails.countryOrRegion),
    CAStatus = ConditionalAccessStatus,
    RiskLevel = RiskLevelDuringSignIn,
    MFASatisfied = tostring(AuthenticationDetails)
| summarize
    DeviceCodeSignIns = count(),
    DistinctApps = make_set(DeviceCodeApp, 10),
    DistinctIPs = make_set(SignInIP, 10),
    DistinctCountries = make_set(SignInCountry, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by UserPrincipalName, UserDisplayName
| where DeviceCodeSignIns >= 1
// Enrich: check if the user has EVER used device code flow before
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(90d)
    | where AuthenticationProtocol == "deviceCode"
    | where ResultType == 0
    | summarize HistoricalDeviceCodeCount = count() by UserPrincipalName
) on UserPrincipalName
| extend
    FirstTimeDeviceCode = iff(
        isempty(HistoricalDeviceCodeCount) or HistoricalDeviceCodeCount <= DeviceCodeSignIns,
        true, false)
| project
    UserPrincipalName,
    UserDisplayName,
    DeviceCodeSignIns,
    DistinctApps,
    DistinctIPs,
    DistinctCountries,
    FirstTimeDeviceCode,
    FirstSeen,
    LastSeen
| sort by FirstTimeDeviceCode desc, DeviceCodeSignIns desc
```

## What Triggers This

A successful sign-in using the OAuth device code flow. The device code flow is legitimate for devices without browsers (smart TVs, IoT), but when a regular user account authenticates via device code for the first time, it's a strong phishing indicator.

The attack works by:
1. Attacker generates a device code via the OAuth endpoint
2. Attacker sends the code to the victim (email, Teams, phone) claiming they need to "verify their account"
3. Victim enters the code at microsoft.com/devicelogin and authenticates with MFA on their own device
4. Attacker receives the resulting refresh token on their machine

## False Positives

1. **Legitimate device code usage.** Conference room displays, smart TVs, and devices without browsers use device code flow legitimately. These should be service accounts, not user accounts.
2. **Azure CLI and PowerShell.** Developers using `az login` with device code. Common in development teams. Build a baseline of users who regularly use device code.
3. **IT provisioning.** Device enrollment workflows sometimes use device code. Exclude known provisioning accounts.

## Tuning Notes

- `FirstTimeDeviceCode = true` is the highest-confidence signal. A user who has never used device code flow before suddenly using it is suspicious.
- Consider blocking device code flow entirely via Conditional Access for most users. Only allow it for service accounts and specific device-provisioning scenarios.
- Deploy as NRT rule — device code phishing grants immediate access.

## Validation

1. From a test machine, initiate a device code flow using Azure CLI: `az login --use-device-code`
2. Authenticate with a test account at microsoft.com/devicelogin
3. Verify the detection fires and captures the account, app, and IP

## Learn More

- [Entra ID Security — OAuth Attack Patterns](https://ridgelinecyber.com/training/courses/entra-id-security/) — device code flow abuse, consent phishing, token theft
- [M365 Security Architecture — Authentication Security](https://ridgelinecyber.com/training/courses/m365-security-architecture/) — Conditional Access policies to block device code flow
