# Sign-In from Anonymizer Infrastructure

Detects successful Entra ID sign-ins originating from known anonymizer services — commercial VPNs, TOR exit nodes, residential proxy networks, and cloud hosting providers commonly used as attacker infrastructure. The sign-in succeeds, which means Conditional Access and MFA were satisfied. The risk is what the attacker does next with a valid session from untraceable infrastructure.

## ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts
- **Tactic:** Initial Access

## Severity

**Medium.** Many organizations have legitimate VPN users. The detection fires on infrastructure category, not on confirmed malice. Severity escalates to High when combined with other indicators (new device, inbox rule creation, OAuth consent within the same session).

## Data Sources

- Entra ID Sign-in Logs — `SigninLogs` table in Sentinel
- Entra ID Identity Protection risk events — `AADRiskyUsers`, `IdentityRiskEvents`
- Requires: Entra ID P1 or P2 for IP categorization in sign-in logs

## Query — KQL (Sentinel)

```kql
let lookback = 24h;
// Known anonymizer ASNs — TOR, major commercial VPNs, residential proxies
let anonymizerASNs = dynamic([
    "AS9009",    // M247 (NordVPN, Surfshark infrastructure)
    "AS20473",   // Choopa/Vultr (attacker hosting)
    "AS14061",   // DigitalOcean
    "AS16276",   // OVHcloud
    "AS24940",   // Hetzner
    "AS396982",  // Google Cloud (GCP)
    "AS8075",    // Microsoft Azure
    "AS16509",   // AWS
    "AS13335",   // Cloudflare
    "AS174",     // Cogent (TOR exit concentration)
    "AS60068",   // CDN77 (residential proxy infrastructure)
    "AS62904",   // Eonix/PacketHub (proxy pools)
    "AS212238",  // Datacamp (residential proxies)
    "AS209588"   // Flyservers (bulletproof hosting)
]);
// Stage 1: Successful sign-ins from anonymizer infrastructure
let suspiciousSignins = SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == 0
| where NetworkLocationDetails has_any ("vpn", "proxy", "tor", "anonymizer", "hosting")
   OR AutonomousSystemNumber in (anonymizerASNs)
| extend ASN = tostring(AutonomousSystemNumber)
| extend InfraType = case(
    NetworkLocationDetails has "tor", "TOR",
    NetworkLocationDetails has "vpn", "VPN",
    NetworkLocationDetails has "proxy", "Proxy",
    ASN in ("AS14061", "AS20473", "AS16276", "AS24940"), "VPS/Hosting",
    ASN in ("AS396982", "AS8075", "AS16509"), "Cloud Provider",
    "Other Anonymizer"
)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ASN,
    InfraType,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AppDisplayName,
    DeviceDetail,
    ConditionalAccessStatus,
    RiskLevelDuringSignIn,
    UserAgent,
    CorrelationId;
// Stage 2: Exclude users who regularly sign in from these ASNs (baseline)
let regularVPNUsers = SigninLogs
| where TimeGenerated between(ago(30d) .. ago(lookback))
| where ResultType == 0
| where AutonomousSystemNumber in (anonymizerASNs)
| summarize VPNSigninDays = dcount(bin(TimeGenerated, 1d)) by UserPrincipalName
| where VPNSigninDays > 5;
// Final: suspicious sign-ins from non-baseline users
suspiciousSignins
| where UserPrincipalName !in (regularVPNUsers | project UserPrincipalName)
| sort by TimeGenerated desc
```

## Why This Detection Is Effective

Entra ID categorizes some IPs as anonymizer infrastructure in `NetworkLocationDetails`, but the coverage is incomplete — residential proxy networks and newer VPS providers often aren't categorized. This detection supplements Entra's built-in categorization with an ASN-based approach that catches infrastructure Entra ID misses.

The 30-day baseline exclusion is critical. Without it, every remote worker using a corporate VPN generates alerts. By excluding users who have signed in from anonymizer ASNs on 5+ days in the past month, the detection focuses on accounts that have never or rarely used anonymizer infrastructure — the accounts where such a sign-in is genuinely anomalous.

## What Triggers This

An attacker authenticates to Entra ID from infrastructure designed to hide their origin:
- TOR exit nodes — the attacker routes through the TOR network
- Commercial VPNs — NordVPN, Surfshark, ExpressVPN infrastructure (M247, Datacamp ASNs)
- Residential proxies — the attacker routes through compromised residential IP pools to appear as a normal ISP user
- Cloud VPS — DigitalOcean, Vultr, Hetzner droplets used as attack staging servers

The sign-in succeeds (ResultType == 0), meaning MFA was satisfied. In AiTM attacks, the attacker satisfies MFA through the proxy and then replays the session token from anonymizer infrastructure.

## False Positives

1. **Corporate VPN users.** Employees using the company's VPN gateway. The 30-day baseline handles this if VPN use is consistent. For intermittent VPN users, add the corporate VPN's ASN to a separate exclusion list.
2. **Traveling employees.** Hotel, airport, and coffee shop WiFi sometimes routes through hosting providers. Cross-reference with the user's travel schedule or expense reports.
3. **Developer testing.** Developers testing from cloud VMs (AWS, Azure, GCP). These are legitimate but should use dedicated test accounts, not production identities.
4. **Mobile carrier CGN.** Some mobile carriers use IP ranges that overlap with hosting ASNs. Validate by checking the UserAgent for mobile device strings.

## Tuning Notes

- **ASN list maintenance.** The anonymizer ASN list needs quarterly review. Attackers shift infrastructure. Add ASNs you see in confirmed incidents. Remove ASNs that generate only false positives.
- **Cloud provider scoping.** The major cloud ASNs (AWS, Azure, GCP) generate significant volume. Consider moving them to a separate, lower-severity rule or requiring additional conditions (new device + cloud ASN = alert).
- **Combine with post-auth signals.** The highest-fidelity version of this detection joins with `AuditLogs` and `OfficeActivity` within 60 minutes of the sign-in — an anonymizer sign-in followed by inbox rule creation, OAuth consent, or bulk file access is a strong BEC indicator.
- **Sentinel deployment:** Scheduled rule, 1-hour frequency. Entity mapping: `UserPrincipalName` as Account, `IPAddress` as IP.

## Validation

1. Sign in to Entra ID from a cloud VM (e.g., a DigitalOcean droplet) using a test account
2. Verify the detection fires with the correct ASN classification and infrastructure type
3. Verify the 30-day baseline correctly excludes test accounts that regularly use the same ASN

## Learn More

- [Entra ID Security — Sign-In Log Analysis](https://ridgelinecyber.com/training/courses/entra-id-security/) — sign-in log schema, risk signal interpretation, and anomaly detection
- [SOC Operations — Identity Detection](https://ridgelinecyber.com/training/courses/m365-security-operations/) — identity-based alert triage and investigation
- [Detection Engineering — Identity Threat Modeling](https://ridgelinecyber.com/training/courses/detection-engineering/) — building identity detection coverage
